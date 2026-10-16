use std::fmt;
use std::mem::MaybeUninit;
use std::sync::Arc;

use bitflags::bitflags;
use bitflags::parser::to_writer;
use color_eyre::eyre;
use ipnet::IpNet;
use libc::{
    AF_INET, AF_INET6, AF_UNSPEC, IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_HOMEADDRESS,
    IFA_F_TENTATIVE, NETLINK_ROUTE, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, RTEXT_FILTER_SKIP_STATS,
    RTM_GETADDR, RTM_GETLINK, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK,
};
use shared::netlink::{LinkRequest, NetlinkRequest, ifaddrmsg, ifinfomsg, nlmsghdr, rtattr};
use socket2::SockAddrStorage;
use tokio::sync::mpsc::Sender;
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use wsdd_rs::define_typed_size;
use zerocopy::IntoBytes as _;
use zerocopy::byteorder::native_endian::{I32, U16, U32};

use crate::config::{BindTo, Config};
use crate::network_handler::Command;
use crate::rtnetlink::{
    AddressValue, Attribute, Attributes, Message, Messages, ReceiveBuffer, RecvBuf,
};
use crate::utils::{i32_to_u8, i32_to_u16, usize_to_u16};

define_typed_size!(SIZE_OF_SOCKADDR_NL, u32, libc::sockaddr_nl);
define_typed_size!(SIZE_OF_LINK_REQUEST, u32, LinkRequest);
define_typed_size!(SIZE_OF_NETLINK_REQUEST, u32, NetlinkRequest);

const DUMP_REQUEST_FLAGS: u16 = i32_to_u16(NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP);

const IFLA_EXT_MASK: u16 = 29;

pub struct NetlinkAddressMonitor {
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
    config: Arc<Config>,
    socket: tokio::net::UdpSocket,
    start_rx: watch::Receiver<()>,
}

impl NetlinkAddressMonitor {
    /// Implementation for Netlink sockets, i.e. Linux.
    pub fn new(
        cancellation_token: CancellationToken,
        command_tx: Sender<Command>,
        start_rx: watch::Receiver<()>,
        config: Arc<Config>,
    ) -> Result<Self, std::io::Error> {
        let mut rtm_groups = RTMGRP_LINK;

        if !config.bind_to.ipv4_only() {
            rtm_groups |= RTMGRP_IPV6_IFADDR;
        }

        if !config.bind_to.ipv6_only() {
            rtm_groups |= RTMGRP_IPV4_IFADDR;
        }

        let socket = netlink_socket(rtm_groups.cast_unsigned())?;

        Ok(Self {
            cancellation_token,
            command_tx,
            config,
            socket,
            start_rx,
        })
    }

    pub fn teardown(self) {
        self.cancellation_token.cancel();
    }

    pub async fn process_changes(&mut self) -> Result<(), eyre::Report> {
        // we originally had this on the stack (array), but that pushed the spawned task's future past tokio's `BOX_FUTURE_THRESHOLD` in debug builds, so `spawn` boxed it
        let mut buffer = ReceiveBuffer::new();

        let mut start_open = true;

        loop {
            match process_changes::<&tokio::net::UdpSocket>(
                &self.cancellation_token,
                &self.socket,
                &self.command_tx,
                &mut self.start_rx,
                &mut start_open,
                &mut buffer,
            )
            .await?
            {
                Exit::Cancelled => {
                    return Ok(());
                },
                Exit::Resync => {
                    if let Err(error) =
                        resync(&self.config, &self.cancellation_token, &self.command_tx).await
                    {
                        event!(
                            Level::ERROR,
                            ?error,
                            "Failed to read the current network state"
                        );
                    }
                },
            }
        }
    }
}

enum Exit {
    Cancelled,
    Resync,
}

async fn process_changes<R>(
    cancellation_token: &CancellationToken,
    recv_buf: R,
    command_tx: &Sender<Command>,
    start_rx: &mut watch::Receiver<()>,
    start_open: &mut bool,
    buffer: &mut ReceiveBuffer,
) -> Result<Exit, eyre::Report>
where
    R: for<'a> RecvBuf<&'a mut [MaybeUninit<u8>]>,
{
    loop {
        let messages = tokio::select! {
            () = cancellation_token.cancelled() => {
                return Ok(Exit::Cancelled);
            },
            changed = start_rx.changed(), if *start_open => {
                if changed.is_ok() {
                    event!(Level::INFO, "Requesting current network state");

                    return Ok(Exit::Resync);
                }

                *start_open = false;

                continue;
            },
            result = buffer.receive(&recv_buf) => {
                match result {
                    Ok(messages) => messages,
                    Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                        // the kernel dropped notifications because our receive queue overflowed
                        event!(
                            Level::WARN,
                            "netlink receive queue overflowed, notifications were lost"
                        );

                        // the queued notifications predate the lost ones and would overwrite the dump
                        buffer.discard_queued(&recv_buf)?;

                        return Ok(Exit::Resync);
                    },
                    Err(error) => {
                        return Err(error.into());
                    },
                }
            },
        };

        if let Err(error) = parse_netlink_response(messages, cancellation_token, command_tx).await {
            event!(
                Level::ERROR,
                ?error,
                "Error parsing response as a netlink response"
            );
        }
    }
}

async fn resync(
    config: &Config,
    cancellation_token: &CancellationToken,
    command_tx: &Sender<Command>,
) -> Result<(), eyre::Report> {
    let socket = netlink_socket(0)?;

    let mut buffer = ReceiveBuffer::new();

    loop {
        request_links(&socket)?;

        let links = forward_dump(&socket, &mut buffer, cancellation_token, command_tx).await?;

        request_addresses(config, &socket)?;

        let addresses = forward_dump(&socket, &mut buffer, cancellation_token, command_tx).await?;

        if let (Dump::Complete, Dump::Complete) = (links, addresses) {
            return announce(Command::ResyncComplete, cancellation_token, command_tx).await;
        }
    }
}

enum Dump {
    Complete,
    Interrupted,
}

async fn forward_dump<R>(
    recv_buf: R,
    buffer: &mut ReceiveBuffer,
    cancellation_token: &CancellationToken,
    command_tx: &Sender<Command>,
) -> Result<Dump, eyre::Report>
where
    R: for<'a> RecvBuf<&'a mut [MaybeUninit<u8>]>,
{
    let mut dump = Dump::Complete;

    loop {
        let messages = buffer.receive(&recv_buf).await?;

        let received = parse_netlink_response(messages, cancellation_token, command_tx).await?;

        if received.dump_interrupted {
            dump = Dump::Interrupted;
        }

        if received.done {
            return Ok(dump);
        }
    }
}

fn netlink_socket(groups: u32) -> Result<tokio::net::UdpSocket, std::io::Error> {
    let socket = socket2::Socket::new(
        libc::AF_NETLINK.into(),
        libc::SOCK_RAW.into(),
        Some(NETLINK_ROUTE.into()),
    )?;

    socket.set_nonblocking(true)?;

    socket.bind(&netlink_address(groups)?)?;

    tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(socket))
}

fn request_links(socket: &tokio::net::UdpSocket) -> Result<(), std::io::Error> {
    let request = LinkRequest {
        nh: nlmsghdr {
            nlmsg_len: U32::new(SIZE_OF_LINK_REQUEST),
            nlmsg_type: U16::new(RTM_GETLINK),
            nlmsg_flags: U16::new(DUMP_REQUEST_FLAGS),
            nlmsg_seq: U32::ZERO,
            nlmsg_pid: U32::ZERO,
        },
        ifi: ifinfomsg {
            ifi_family: const { i32_to_u8(AF_UNSPEC) },
            ifi_pad: 0,
            ifi_type: U16::ZERO,
            ifi_index: I32::ZERO,
            ifi_flags: U32::ZERO,
            ifi_change: U32::ZERO,
        },
        ext_mask_header: rtattr {
            rta_len: U16::new(const { usize_to_u16(size_of::<rtattr>() + size_of::<U32>()) }),
            rta_type: U16::new(IFLA_EXT_MASK),
        },
        // without a filter mask, the kernel ends the dump early at a link message larger than our receive buffer
        ext_mask: U32::new(RTEXT_FILTER_SKIP_STATS.cast_unsigned()),
    };

    send_to_kernel(socket, request.as_bytes())
}

fn request_addresses(
    config: &Config,
    socket: &tokio::net::UdpSocket,
) -> Result<(), std::io::Error> {
    let family = match config.bind_to {
        BindTo::IPv4 => const { i32_to_u8(AF_INET) },
        BindTo::IPv6 => const { i32_to_u8(AF_INET6) },
        BindTo::DualStack => const { i32_to_u8(AF_UNSPEC) },
    };

    let request = NetlinkRequest {
        nh: nlmsghdr {
            nlmsg_len: U32::new(SIZE_OF_NETLINK_REQUEST),
            nlmsg_type: U16::new(RTM_GETADDR),
            nlmsg_flags: U16::new(DUMP_REQUEST_FLAGS),
            nlmsg_seq: U32::ZERO,
            nlmsg_pid: U32::ZERO,
        },
        ifa: ifaddrmsg {
            ifa_family: family,
            ifa_prefixlen: 0,
            ifa_flags: 0,
            ifa_scope: 0,
            ifa_index: U32::ZERO,
        },
    };

    send_to_kernel(socket, request.as_bytes())
}

fn send_to_kernel(socket: &tokio::net::UdpSocket, request: &[u8]) -> Result<(), std::io::Error> {
    socket2::SockRef::from(&socket).send_to(request, &netlink_address(0)?)?;

    Ok(())
}

/// The kernel's address, or ours with the multicast `groups` to join.
fn netlink_address(groups: u32) -> Result<socket2::SockAddr, std::io::Error> {
    #[expect(
        clippy::multiple_unsafe_ops_per_block,
        reason = "Lint limitations on nested `unsafe`"
    )]
    // SAFETY: this is how to do it as per the API docs
    let ((), socket_addr) = unsafe {
        socket2::SockAddr::try_init(|addr_storage, len| {
            const {
                assert!(
                    size_of::<libc::sockaddr_nl>() <= size_of::<SockAddrStorage>(),
                    "`SockAddrStorage`'s size should be larger `libc::sockaddr_nl`'s size"
                );
            }

            // SAFETY: see `SockAddr::try_init` for guarantees that `addr_storage` is zeroed
            let sockaddr_nl = &mut *addr_storage.cast::<libc::sockaddr_nl>();

            sockaddr_nl.nl_family = const { i32_to_u16(libc::AF_NETLINK) };
            sockaddr_nl.nl_pid = 0;
            sockaddr_nl.nl_groups = groups;

            // SAFETY: `len` is initialized and `non-null`
            *len = SIZE_OF_SOCKADDR_NL;

            Ok(())
        })
    }?;

    Ok(socket_addr)
}

bitflags! {
    struct SkippedStates: u32 {
        const IFA_F_DADFAILED = IFA_F_DADFAILED;
        const IFA_F_HOMEADDRESS = IFA_F_HOMEADDRESS;
        const IFA_F_DEPRECATED = IFA_F_DEPRECATED;
        const IFA_F_TENTATIVE = IFA_F_TENTATIVE;
    }
}

impl fmt::Display for SkippedStates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        to_writer(self, f)
    }
}

#[derive(Default)]
struct Received {
    done: bool,
    dump_interrupted: bool,
}

async fn parse_netlink_response(
    messages: Messages<'_>,
    cancellation_token: &CancellationToken,
    command_tx: &Sender<Command>,
) -> Result<Received, eyre::Report> {
    let mut received = Received::default();

    for (header, message) in messages {
        received.dump_interrupted |= header.dump_interrupted;

        let command = match message {
            Message::Done => {
                received.done = true;

                break;
            },
            Message::Ack => {
                event!(Level::DEBUG, "ACK");

                break;
            },
            Message::Error(error) => {
                return Err(eyre::Report::new(error).wrap_err("NLMSG_ERROR"));
            },
            Message::Noop => {
                event!(Level::DEBUG, "NLMSG_NOOP");

                None
            },
            Message::NewAddress(ifa, attributes) => {
                let skipped_states = SkippedStates::from_bits_truncate(u32::from(ifa.ifa_flags));

                if skipped_states.is_empty() {
                    parse_address_message(ifa, attributes).map(|address| Command::NewAddress {
                        address,
                        scope: ifa.ifa_scope,
                        index: ifa.ifa_index.get(),
                    })
                } else {
                    event!(Level::DEBUG, "skipping address, state: {}", skipped_states);

                    None
                }
            },
            Message::DeleteAddress(ifa, attributes) => {
                // a deleted address is gone, whatever its state
                parse_address_message(ifa, attributes).map(|address| Command::DeleteAddress {
                    address,
                    scope: ifa.ifa_scope,
                    index: ifa.ifa_index.get(),
                })
            },
            Message::NonIpAddress(family) => {
                event!(Level::DEBUG, "skipping address, family: {}", family);

                None
            },
            Message::NewLink(ifi) => Some(Command::NewLink {
                index: ifi.ifi_index.get().cast_unsigned(),
                flags: ifi.ifi_flags.get(),
            }),
            Message::DeleteLink(ifi) => Some(Command::DeleteLink {
                index: ifi.ifi_index.get().cast_unsigned(),
            }),
            Message::ProtocolLink(family) => {
                event!(Level::DEBUG, "skipping link, family: {}", family);

                None
            },
            Message::Other(message_type) => {
                event!(Level::DEBUG, "unhandled rtm_message type {}", message_type);

                None
            },
        };

        if let Some(command) = command {
            announce(command, cancellation_token, command_tx).await?;
        }
    }

    Ok(received)
}

async fn announce(
    command: Command,
    cancellation_token: &CancellationToken,
    command_tx: &Sender<Command>,
) -> Result<(), eyre::Report> {
    let Err(error) = command_tx.send(command).await else {
        return Ok(());
    };

    if cancellation_token.is_cancelled() {
        event!(Level::INFO, command = ?error.0, "Could not announce command due to shutting down");
    } else {
        event!(Level::ERROR, command = ?error.0, "Failed to announce command");
    }

    Err(eyre::Report::msg(
        "Command receiver gone, nothing left to do but abandon buffer",
    ))
}

fn parse_address_message(ifa: &ifaddrmsg, attributes: Attributes<'_>) -> Option<IpNet> {
    event!(
        Level::TRACE,
        ifa_family = ifa.ifa_family,
        ifa_flags = ifa.ifa_flags,
        ifa_scope = ifa.ifa_scope,
        ifa_index = ifa.ifa_index.get(),
        "address message"
    );

    let mut ifa_address = None;
    let mut ifa_local = None;

    for attribute in attributes {
        match attribute {
            Attribute::Address(value) => {
                ifa_address = Some(value);
            },
            Attribute::Local(value) => {
                ifa_local = Some(value);
            },
            Attribute::Other => {
                // `IFA_LABEL` might be an alias label, e.g. `eth0:0`, so it does not identify the interface
            },
        }
    }

    // `libc::IFA_ADDRESS` is prefix address, rather than local interface address.
    // It makes no difference for normally configured broadcast interfaces,
    // but for point-to-point `libc::IFA_ADDRESS` is DESTINATION address,
    // local address is supplied in `libc::IFA_LOCAL` attribute.
    // https://github.com/torvalds/linux/blob/e9a6fb0bcdd7609be6969112f3fbfcce3b1d4a7c/include/uapi/linux/if_addr.h#L16-L25
    let Some(addr) = ifa_local.or(ifa_address).map(AddressValue::decode) else {
        event!(Level::DEBUG, "no address in RTM message");

        return None;
    };

    let address = IpNet::new(addr, ifa.ifa_prefixlen)
        .expect("`prefix_len` must be valid for this address, as this is kernel data");

    Some(address)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::mem::MaybeUninit;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::atomic::{AtomicBool, Ordering};

    use bytes::BufMut as _;
    use ipnet::IpNet;
    use libc::{
        AF_INET, AF_INET6, AF_PHONET, AF_UNSPEC, EINVAL, IFA_ADDRESS, IFA_F_DADFAILED,
        IFA_F_DEPRECATED, IFA_F_PERMANENT, IFA_F_TENTATIVE, IFA_LOCAL, IFF_MULTICAST, IFF_RUNNING,
        IFF_UP, NLMSG_DONE, RTM_DELADDR, RTM_NEWADDR, RTM_NEWLINK,
    };
    use pretty_assertions::{assert_eq, assert_matches};
    use shared::netlink::{ifaddrmsg, ifinfomsg, rtattr};
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;
    use zerocopy::IntoBytes as _;
    use zerocopy::byteorder::native_endian::{I32, U16, U32};

    use crate::address_monitor::netlink_address_monitor::{
        Dump, Exit, SIZE_OF_SOCKADDR_NL, SkippedStates, forward_dump, process_changes, resync,
    };
    use crate::network_handler::Command;
    use crate::rtnetlink::{RTA_ALIGNTO, ReceiveBuffer, RecvBuf};
    use crate::test_utils::build_config;
    use crate::test_utils::netlink::{
        done_message, error_message, interrupted_message, link_message, netlink_message,
    };
    use crate::utils::u32_to_usize;

    #[test]
    fn size_of_sockaddr_nl() {
        assert_eq!(
            u32_to_usize(SIZE_OF_SOCKADDR_NL),
            size_of::<libc::sockaddr_nl>()
        );
    }

    #[tokio::test]
    async fn parse_response() {
        let expected: [(&'static str, u8, u32); 47] = [
            ("127.0.0.1/8", 254, 1),
            ("192.168.1.5/24", 0, 2),
            ("192.168.40.5/24", 0, 4),
            ("192.168.20.5/24", 0, 5),
            ("100.111.79.121/32", 0, 6),
            ("172.19.0.1/23", 0, 7),
            ("172.17.0.1/16", 0, 8),
            ("::1/128", 254, 1),
            ("2600:1900:52cc:4c00:1312:a3ff:fe24:8c4/64", 0, 2),
            ("fe80::1312:a3ff:fe24:8c4/64", 253, 2),
            ("fe80::1312:a3ff:fe24:8c4/64", 253, 4),
            ("fe80::1312:a3ff:fe24:8c4/64", 253, 5),
            ("fd75:115e:9e18::6b01:4f79/128", 0, 6),
            ("fe80::c8e2:fe16:117d:3254/64", 253, 6),
            ("fe80::e05b:9cff:fe5d:8a1a/64", 253, 7),
            ("fda8:4ae1:7755::1/48", 0, 8),
            ("2600:1900:52cc:4c10::1/64", 0, 9),
            ("fe80::c85c:89ff:fedc:89f5/64", 253, 9),
            ("fe80::909e:93ff:fee6:c7b7/64", 253, 10),
            ("fe80::10b2:8ff:fe56:7a18/64", 253, 11),
            ("fe80::d02b:7cff:fe99:6e41/64", 253, 13),
            ("fe80::1c17:faff:feb8:725c/64", 253, 15),
            ("fe80::a81f:d9ff:fef0:de6f/64", 253, 16),
            ("fe80::8433:3bff:fe70:b44b/64", 253, 17),
            ("fe80::f4d6:c8ff:fe2d:a45a/64", 253, 20),
            ("fe80::e469:1eff:fe81:4350/64", 253, 21),
            ("fe80::7409:51ff:fe18:6b04/64", 253, 22),
            ("fe80::2c24:b5ff:fed5:6f2d/64", 253, 23),
            ("fe80::d4db:e2ff:fe16:8531/64", 253, 24),
            ("fe80::9825:71ff:fea2:8898/64", 253, 25),
            ("fe80::1411:f6ff:fe4e:8fa8/64", 253, 26),
            ("fe80::703e:1aff:fe27:cabf/64", 253, 27),
            ("fe80::403a:68ff:fe48:c630/64", 253, 30),
            ("fe80::c41e:b7ff:fed3:6090/64", 253, 31),
            ("fe80::7850:8aff:fec5:fccd/64", 253, 32),
            ("fe80::9cb6:35ff:feb8:22fc/64", 253, 33),
            ("fe80::783a:16ff:fe04:9bca/64", 253, 34),
            ("fe80::d8dd:39ff:fefd:7fe5/64", 253, 35),
            ("fe80::b4ed:4cff:fe10:a2d1/64", 253, 37),
            ("fe80::e85d:cbff:fe97:f2c0/64", 253, 39),
            ("fe80::ec5e:acff:fe37:acc3/64", 253, 41),
            ("fe80::b893:edff:fe7b:57c5/64", 253, 42),
            ("fe80::3480:bff:fece:6773/64", 253, 43),
            ("fe80::9c92:34ff:fe1b:1cca/64", 253, 45),
            ("fe80::58bc:7dff:fe21:e5da/64", 253, 46),
            ("fe80::40df:abff:fe84:47bf/64", 253, 47),
            ("fe80::b475:97ff:fe15:fc6c/64", 253, 48),
        ];

        let commands = commands(include_bytes!("fixtures/commands.bin")).await;

        assert_eq!(commands.len(), expected.len());

        for (command, (expected_address, expected_scope, expected_index)) in
            commands.into_iter().zip(expected)
        {
            let Command::NewAddress {
                address,
                scope,
                index,
            } = command
            else {
                panic!("Invalid command type");
            };

            assert_eq!(address, expected_address.parse().unwrap());
            assert_eq!(scope, expected_scope);
            assert_eq!(index, expected_index);
        }
    }

    #[tokio::test]
    async fn notifications_queued_before_an_overflow_are_discarded() {
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<Command>(10);

        let (_start_tx, mut start_rx) = watch::channel(());

        let socket = DatagramSocket {
            datagrams: RefCell::new(VecDeque::from([
                Err(std::io::Error::from_raw_os_error(libc::ENOBUFS)),
                Ok(link_message(
                    RTM_NEWLINK,
                    AF_UNSPEC,
                    7,
                    IFF_UP.cast_unsigned(),
                )),
            ])),
        };

        let mut buffer = ReceiveBuffer::new();

        let result = process_changes(
            &CancellationToken::new(),
            &socket,
            &command_tx,
            &mut start_rx,
            &mut true,
            &mut buffer,
        )
        .await;

        assert!(matches!(result, Ok(Exit::Resync)));
        assert_matches!(socket.datagrams.borrow().front(), None);
        assert_matches!(command_rx.try_recv(), Err(TryRecvError::Empty));
    }

    /// Delivers `bytes` once, then cancels.
    struct DrainingNetlinkSocket<'b> {
        bytes: &'b [u8],
        cancellation_token: CancellationToken,
        done: AtomicBool,
    }

    impl RecvBuf<&mut [MaybeUninit<u8>]> for DrainingNetlinkSocket<'_> {
        async fn peek_len(&self) -> std::io::Result<usize> {
            if self.done.load(Ordering::Relaxed) {
                self.cancellation_token.cancel();

                return std::future::pending().await;
            }

            Ok(self.bytes.len())
        }

        #[expect(clippy::mut_mut, reason = "Mandated by the trait")]
        fn recv_buf(
            &self,
            buf: &mut &mut [MaybeUninit<u8>],
        ) -> impl Future<Output = std::io::Result<usize>> {
            self.done.store(true, Ordering::Relaxed);

            buf.put_slice(self.bytes);

            std::future::ready(Ok(self.bytes.len()))
        }

        #[expect(clippy::mut_mut, reason = "Mandated by the trait")]
        fn try_recv_buf(&self, _buf: &mut &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
            Err(std::io::ErrorKind::WouldBlock.into())
        }
    }

    fn ipv6_address_message(nlmsg_type: u16, ifa_flags: u32, address: Ipv6Addr) -> Vec<u8> {
        let octets = address.octets();

        let ifa = ifaddrmsg {
            ifa_family: u8::try_from(AF_INET6).unwrap(),
            ifa_prefixlen: 64,
            ifa_flags: u8::try_from(ifa_flags).unwrap(),
            ifa_scope: 0,
            ifa_index: U32::new(2),
        };

        let rta = rtattr {
            rta_len: U16::new(u16::try_from(size_of::<rtattr>() + octets.len()).unwrap()),
            rta_type: U16::new(IFA_ADDRESS),
        };

        netlink_message(
            nlmsg_type,
            &[ifa.as_bytes(), rta.as_bytes(), octets.as_slice()].concat(),
        )
    }

    fn attribute(rta_type: u16, value: &[u8]) -> Vec<u8> {
        let rta = rtattr {
            rta_len: U16::new(u16::try_from(size_of::<rtattr>() + value.len()).unwrap()),
            rta_type: U16::new(rta_type),
        };

        let mut bytes = [rta.as_bytes(), value].concat();

        bytes.resize(bytes.len().next_multiple_of(RTA_ALIGNTO), 0);

        bytes
    }

    fn new_address_message(family: i32, prefix_len: u8, attributes: &[Vec<u8>]) -> Vec<u8> {
        let ifa = ifaddrmsg {
            ifa_family: u8::try_from(family).unwrap(),
            ifa_prefixlen: prefix_len,
            ifa_flags: 0,
            ifa_scope: 0,
            ifa_index: U32::new(2),
        };

        netlink_message(
            RTM_NEWADDR,
            &[ifa.as_bytes(), attributes.concat().as_slice()].concat(),
        )
    }

    /// Every command `process_changes` sends for `bytes`.
    async fn commands(bytes: &[u8]) -> Vec<Command> {
        let cancellation_token = CancellationToken::new();

        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<Command>(100);

        let socket = DrainingNetlinkSocket {
            bytes,
            cancellation_token: cancellation_token.clone(),
            done: AtomicBool::new(false),
        };

        let (_start_tx, mut start_rx) = watch::channel(());

        let mut buffer = ReceiveBuffer::new();

        let result = process_changes(
            &cancellation_token,
            socket,
            &command_tx,
            &mut start_rx,
            &mut true,
            &mut buffer,
        )
        .await;

        assert!(matches!(result, Ok(Exit::Cancelled)));

        let mut commands = Vec::new();

        while let Ok(command) = command_rx.try_recv() {
            commands.push(command);
        }

        commands
    }

    #[tokio::test]
    async fn new_address_in_deprecated_state_is_skipped() {
        let mut bytes = ipv6_address_message(
            RTM_NEWADDR,
            IFA_F_DEPRECATED,
            "2001:db8::1".parse().unwrap(),
        );

        bytes.extend(ipv6_address_message(
            RTM_NEWADDR,
            0,
            "2001:db8::2".parse().unwrap(),
        ));

        assert_matches!(
            &*commands(&bytes).await,
            [Command::NewAddress { address, .. }] if *address == "2001:db8::2/64".parse::<IpNet>().unwrap()
        );
    }

    #[tokio::test]
    async fn deleted_address_in_deprecated_state_is_reported() {
        let bytes = ipv6_address_message(
            RTM_DELADDR,
            IFA_F_DEPRECATED,
            "2001:db8::1".parse().unwrap(),
        );

        assert_matches!(
            &*commands(&bytes).await,
            [Command::DeleteAddress { address, .. }] if *address == "2001:db8::1/64".parse::<IpNet>().unwrap()
        );
    }

    #[tokio::test]
    async fn point_to_point_ipv4_address_is_the_local_address() {
        let bytes = new_address_message(
            AF_INET,
            32,
            &[
                attribute(
                    IFA_ADDRESS,
                    &"192.0.2.2".parse::<Ipv4Addr>().unwrap().octets(),
                ),
                attribute(
                    IFA_LOCAL,
                    &"192.0.2.1".parse::<Ipv4Addr>().unwrap().octets(),
                ),
            ],
        );

        assert_matches!(
            &*commands(&bytes).await,
            [Command::NewAddress { address, .. }] if *address == "192.0.2.1/32".parse::<IpNet>().unwrap()
        );
    }

    #[tokio::test]
    async fn point_to_point_ipv6_address_is_the_local_address() {
        let bytes = new_address_message(
            AF_INET6,
            128,
            &[
                attribute(IFA_LOCAL, &"fe80::1".parse::<Ipv6Addr>().unwrap().octets()),
                attribute(
                    IFA_ADDRESS,
                    &"fe80::2".parse::<Ipv6Addr>().unwrap().octets(),
                ),
            ],
        );

        assert_matches!(
            &*commands(&bytes).await,
            [Command::NewAddress { address, .. }] if *address == "fe80::1/128".parse::<IpNet>().unwrap()
        );
    }

    #[tokio::test]
    async fn address_of_another_family_is_ignored() {
        let bytes = new_address_message(AF_PHONET, 0, &[attribute(IFA_LOCAL, &[0x40])]);

        assert_matches!(&*commands(&bytes).await, []);
    }

    #[test]
    fn skipped_states_leave_out_other_flags() {
        let states = SkippedStates::from_bits_truncate(IFA_F_DEPRECATED | IFA_F_PERMANENT);

        assert_eq!(states.to_string(), "IFA_F_DEPRECATED");
    }

    #[test]
    fn skipped_states_list_every_match() {
        let states = SkippedStates::from_bits_truncate(IFA_F_DADFAILED | IFA_F_TENTATIVE);

        assert_eq!(states.to_string(), "IFA_F_DADFAILED | IFA_F_TENTATIVE");
    }

    #[tokio::test]
    async fn addresses_before_done_are_reported() {
        let mut bytes = ipv6_address_message(RTM_NEWADDR, 0, "2001:db8::1".parse().unwrap());

        bytes.extend(netlink_message(
            u16::try_from(NLMSG_DONE).unwrap(),
            0_i32.as_bytes(),
        ));

        assert_matches!(
            &*commands(&bytes).await,
            [Command::NewAddress { address, .. }] if *address == "2001:db8::1/64".parse::<IpNet>().unwrap()
        );
    }

    #[tokio::test]
    async fn link_message_larger_than_a_page_is_reported() {
        let flags = (IFF_UP | IFF_RUNNING | IFF_MULTICAST).cast_unsigned();

        let ifi = ifinfomsg {
            ifi_family: u8::try_from(AF_UNSPEC).unwrap(),
            ifi_pad: 0,
            ifi_type: U16::ZERO,
            ifi_index: I32::new(3),
            ifi_flags: U32::new(flags),
            ifi_change: U32::ZERO,
        };

        // larger than the receive buffer's starting size on every page size
        let bytes = netlink_message(
            RTM_NEWLINK,
            &[ifi.as_bytes(), &attribute(0, &[0; 8192])].concat(),
        );

        assert_matches!(
            &*commands(&bytes).await,
            [Command::NewLink { index: 3, flags: reported }] if *reported == flags
        );
    }

    #[tokio::test]
    async fn device_link_is_reported_with_its_flags() {
        let flags = (IFF_UP | IFF_RUNNING | IFF_MULTICAST).cast_unsigned();

        let bytes = link_message(RTM_NEWLINK, AF_UNSPEC, 3, flags);

        assert_matches!(
            &*commands(&bytes).await,
            [Command::NewLink { index: 3, flags: reported }] if *reported == flags
        );
    }

    #[tokio::test]
    async fn start_asks_for_a_resync() {
        let (command_tx, _command_rx) = tokio::sync::mpsc::channel::<Command>(10);

        let (start_tx, mut start_rx) = watch::channel(());

        start_tx.send_replace(());

        let socket = DatagramSocket {
            datagrams: RefCell::new(VecDeque::new()),
        };

        let mut buffer = ReceiveBuffer::new();

        let result = process_changes(
            &CancellationToken::new(),
            &socket,
            &command_tx,
            &mut start_rx,
            &mut true,
            &mut buffer,
        )
        .await;

        assert!(matches!(result, Ok(Exit::Resync)));
    }

    struct DatagramSocket {
        datagrams: RefCell<VecDeque<std::io::Result<Vec<u8>>>>,
    }

    impl RecvBuf<&mut [MaybeUninit<u8>]> for &DatagramSocket {
        async fn peek_len(&self) -> std::io::Result<usize> {
            let next = self.datagrams.borrow_mut().pop_front();

            match next {
                Some(Ok(datagram)) => {
                    let length = datagram.len();

                    self.datagrams.borrow_mut().push_front(Ok(datagram));

                    Ok(length)
                },
                // the kernel reports a pending error to whichever read comes first
                Some(Err(error)) => Err(error),
                None => std::future::pending().await,
            }
        }

        #[expect(clippy::mut_mut, reason = "Mandated by the trait")]
        async fn recv_buf(&self, buf: &mut &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
            match self.try_recv_buf(buf) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::future::pending().await
                },
                result => result,
            }
        }

        #[expect(clippy::mut_mut, reason = "Mandated by the trait")]
        fn try_recv_buf(&self, buf: &mut &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
            let datagram = self
                .datagrams
                .borrow_mut()
                .pop_front()
                .ok_or(std::io::ErrorKind::WouldBlock)??;

            buf.put_slice(&datagram);

            Ok(datagram.len())
        }
    }

    async fn dump(
        datagrams: Vec<Vec<u8>>,
    ) -> (Result<Dump, color_eyre::eyre::Report>, Vec<Command>) {
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<Command>(10);

        let socket = DatagramSocket {
            datagrams: RefCell::new(datagrams.into_iter().map(Ok).collect()),
        };

        let mut buffer = ReceiveBuffer::new();

        let result =
            forward_dump(&socket, &mut buffer, &CancellationToken::new(), &command_tx).await;

        let mut commands = Vec::new();

        while let Ok(command) = command_rx.try_recv() {
            commands.push(command);
        }

        (result, commands)
    }

    #[tokio::test]
    async fn dump_is_announced_until_done() {
        let flags = (IFF_UP | IFF_RUNNING | IFF_MULTICAST).cast_unsigned();

        let (result, commands) = dump(vec![
            link_message(RTM_NEWLINK, AF_UNSPEC, 3, flags),
            done_message(),
        ])
        .await;

        assert!(matches!(result, Ok(Dump::Complete)));
        assert_matches!(&*commands, [Command::NewLink { index: 3, .. }]);
    }

    #[tokio::test]
    async fn interrupted_dump_is_reported() {
        let flags = (IFF_UP | IFF_RUNNING | IFF_MULTICAST).cast_unsigned();

        let (result, _) = dump(vec![
            interrupted_message(&link_message(RTM_NEWLINK, AF_UNSPEC, 3, flags)),
            done_message(),
        ])
        .await;

        assert!(matches!(result, Ok(Dump::Interrupted)));
    }

    #[tokio::test]
    async fn failed_dump_returns_its_error() {
        let (result, _) = dump(vec![error_message(-EINVAL)]).await;

        assert!(result.is_err());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn resync_ends_with_resync_complete() {
        let config = build_config(Uuid::now_v7(), 1);
        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<Command>(10);

        let sent = async move { resync(&config, &CancellationToken::new(), &command_tx).await };

        let received = async {
            let mut commands = Vec::new();

            while let Some(command) = command_rx.recv().await {
                commands.push(command);
            }

            commands
        };

        let (result, commands) = tokio::join!(sent, received);

        result.unwrap();
        assert_matches!(commands.last(), Some(Command::ResyncComplete));
    }
}
