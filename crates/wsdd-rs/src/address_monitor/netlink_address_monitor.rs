use std::fmt;
use std::mem::{self, MaybeUninit};
use std::sync::Arc;

use bitflags::bitflags;
use bitflags::parser::to_writer;
use color_eyre::eyre;
use ipnet::IpNet;
use libc::{
    AF_INET, AF_INET6, AF_UNSPEC, IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_HOMEADDRESS,
    IFA_F_TENTATIVE, NETLINK_ROUTE, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, RTM_GETADDR, RTM_GETLINK,
    RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK,
};
use shared::netlink::{LinkRequest, NetlinkRequest, ifaddrmsg, ifinfomsg, nlmsghdr};
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
    AddressValue, Attribute, Attributes, Header, Message, Messages, ReceiveBuffer, RecvBuf,
};

define_typed_size!(SIZE_OF_SOCKADDR_NL, u32, libc::sockaddr_nl);

/// Each dump request sets its own `nlmsg_seq`. Netlink treats the value as opaque and echoes it in the replies, so an `NLMSG_DONE` shows which dump ended.
#[derive(Clone, Copy)]
enum Dump {
    Links,
    Addresses,
}

impl Dump {
    fn sequence(self) -> u32 {
        match self {
            Self::Links => 1,
            Self::Addresses => 2,
        }
    }
}

/// The kernel runs one dump per socket at a time, so a dump request waits until the running dump ends.
#[derive(Default)]
struct Dumps {
    running: Option<RunningDump>,
    resync_pending: bool,
}

struct RunningDump {
    dump: Dump,
    interrupted: bool,
}

impl Dumps {
    fn resync<F>(&mut self, request: &F)
    where
        F: Fn(Dump) -> Result<(), std::io::Error>,
    {
        if self.running.is_some() {
            self.resync_pending = true;
        } else {
            self.start(Dump::Links, request);
        }
    }

    fn start<F>(&mut self, dump: Dump, request: &F)
    where
        F: Fn(Dump) -> Result<(), std::io::Error>,
    {
        if let Err(error) = request(dump) {
            event!(Level::ERROR, ?error, "Failed to request a netlink dump");

            return;
        }

        self.running = Some(RunningDump {
            dump,
            interrupted: false,
        });
    }

    fn observe(&mut self, header: &Header) {
        if header.dump_interrupted
            && let Some(running) = self.running.as_mut()
            && running.dump.sequence() == header.sequence
        {
            running.interrupted = true;
        }
    }

    fn finish<F>(&mut self, sequence: u32, request: &F)
    where
        F: Fn(Dump) -> Result<(), std::io::Error>,
    {
        let Some(running) = self
            .running
            .take_if(|running| running.dump.sequence() == sequence)
        else {
            return;
        };

        let resync = mem::take(&mut self.resync_pending);

        if running.interrupted || resync {
            // an interrupted dump may be inconsistent, and a resync requested meanwhile was held back
            self.start(Dump::Links, request);

            return;
        }

        match running.dump {
            Dump::Links => self.start(Dump::Addresses, request),
            Dump::Addresses => {},
        }
    }

    fn fail<F>(&mut self, sequence: u32, request: &F)
    where
        F: Fn(Dump) -> Result<(), std::io::Error>,
    {
        if self
            .running
            .take_if(|running| running.dump.sequence() == sequence)
            .is_some()
            && mem::take(&mut self.resync_pending)
        {
            self.start(Dump::Links, request);
        }
    }
}

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

        let socket = socket2::Socket::new(
            libc::AF_NETLINK.into(),
            libc::SOCK_RAW.into(),
            Some(NETLINK_ROUTE.into()),
        )?;

        socket.set_nonblocking(true)?;

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
                        "allocated space not large enough"
                    );
                }

                // SAFETY: see `SockAddr::try_init` for guarantees that `addr_storage` is zeroed
                let sockaddr_nl = &mut *addr_storage.cast::<libc::sockaddr_nl>();

                sockaddr_nl.nl_family = libc::AF_NETLINK.try_into().unwrap();
                sockaddr_nl.nl_pid = 0;
                sockaddr_nl.nl_groups = rtm_groups.cast_unsigned();

                // SAFETY: `len` is initialized and `non-null`
                *len = SIZE_OF_SOCKADDR_NL;

                Ok(())
            })
        }?;

        socket.bind(&socket_addr)?;

        let socket = tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(socket))?;

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

        let request = |dump| match dump {
            Dump::Links => request_links(&self.socket),
            Dump::Addresses => request_addresses(&self.config, &self.socket),
        };

        process_changes::<&tokio::net::UdpSocket, _>(
            &self.cancellation_token,
            &self.socket,
            self.command_tx.clone(),
            &mut self.start_rx,
            &mut buffer,
            &request,
        )
        .await
    }
}

/// Reads and processes netlink messages until cancelled or a fatal receive error.
async fn process_changes<R, F>(
    cancellation_token: &CancellationToken,
    recv_buf: R,
    command_tx: Sender<Command>,
    start_rx: &mut watch::Receiver<()>,
    buffer: &mut ReceiveBuffer,
    request: &F,
) -> Result<(), eyre::Report>
where
    R: for<'a> RecvBuf<&'a mut [MaybeUninit<u8>]>,
    F: Fn(Dump) -> Result<(), std::io::Error>,
{
    let mut dumps = Dumps::default();

    let mut start_open = true;

    loop {
        let messages = tokio::select! {
            biased;
            () = cancellation_token.cancelled() => {
                return Ok(());
            },
            changed = start_rx.changed(), if start_open => {
                if changed.is_ok() {
                    event!(Level::INFO, "Requesting current network state");

                    dumps.resync(request);
                } else {
                    start_open = false;
                }

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

                        dumps.resync(request);

                        continue;
                    },
                    Err(error) => {
                        return Err(error.into());
                    },
                }
            },
        };

        if let Err(error) = parse_netlink_response(
            messages,
            cancellation_token,
            &command_tx,
            &mut dumps,
            request,
        )
        .await
        {
            event!(
                Level::ERROR,
                ?error,
                "Error parsing response as a netlink response"
            );
        }
    }
}

fn request_links(socket: &tokio::net::UdpSocket) -> Result<(), std::io::Error> {
    let request = LinkRequest {
        nh: nlmsghdr {
            nlmsg_len: U32::new(size_of::<LinkRequest>().try_into().unwrap()),
            nlmsg_type: U16::new(RTM_GETLINK),
            nlmsg_flags: U16::new(u16::try_from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP).unwrap()),
            nlmsg_seq: U32::new(Dump::Links.sequence()),
            nlmsg_pid: U32::ZERO,
        },
        ifi: ifinfomsg {
            ifi_family: AF_UNSPEC.try_into().unwrap(),
            ifi_pad: 0,
            ifi_type: U16::ZERO,
            ifi_index: I32::ZERO,
            ifi_flags: U32::ZERO,
            ifi_change: U32::ZERO,
        },
    };

    send_to_kernel(socket, request.as_bytes())
}

fn request_addresses(
    config: &Config,
    socket: &tokio::net::UdpSocket,
) -> Result<(), std::io::Error> {
    let family = match config.bind_to {
        BindTo::IPv4 => AF_INET,
        BindTo::IPv6 => AF_INET6,
        BindTo::DualStack => AF_UNSPEC,
    };

    let request = NetlinkRequest {
        nh: nlmsghdr {
            nlmsg_len: U32::new(size_of::<NetlinkRequest>().try_into().unwrap()),
            nlmsg_type: U16::new(RTM_GETADDR),
            nlmsg_flags: U16::new(u16::try_from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP).unwrap()),
            nlmsg_seq: U32::new(Dump::Addresses.sequence()),
            nlmsg_pid: U32::ZERO,
        },
        ifa: ifaddrmsg {
            ifa_family: family.try_into().unwrap(),
            ifa_prefixlen: 0,
            ifa_flags: 0,
            ifa_scope: 0,
            ifa_index: U32::ZERO,
        },
    };

    send_to_kernel(socket, request.as_bytes())
}

fn send_to_kernel(socket: &tokio::net::UdpSocket, request: &[u8]) -> Result<(), std::io::Error> {
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

            sockaddr_nl.nl_family = libc::AF_NETLINK.try_into().unwrap();
            sockaddr_nl.nl_pid = 0;
            sockaddr_nl.nl_groups = 0;

            // SAFETY: `len` is initialized and `non-null`
            *len = SIZE_OF_SOCKADDR_NL;

            Ok(())
        })
    }?;

    socket2::SockRef::from(&socket).send_to(request, &socket_addr)?;

    Ok(())
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

async fn parse_netlink_response<F>(
    messages: Messages<'_>,
    cancellation_token: &CancellationToken,
    command_tx: &Sender<Command>,
    dumps: &mut Dumps,
    request: &F,
) -> Result<(), eyre::Report>
where
    F: Fn(Dump) -> Result<(), std::io::Error>,
{
    for (header, message) in messages {
        dumps.observe(&header);

        let command = match message {
            Message::Done => {
                dumps.finish(header.sequence, request);

                break;
            },
            Message::Ack => {
                event!(Level::DEBUG, "ACK");

                break;
            },
            Message::Error(error) => {
                event!(Level::ERROR, %error, "NLMSG_ERROR");

                dumps.fail(header.sequence, request);

                None
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

        if let Some(command) = command
            && let Err(error) = command_tx.send(command).await
        {
            if cancellation_token.is_cancelled() {
                event!(Level::INFO, command = ?error.0, "Could not announce command due to shutting down");
            } else {
                event!(Level::ERROR, command = ?error.0, "Failed to announce command");
            }

            return Err(eyre::Report::msg(
                "Command receiver gone, nothing left to do but abandon buffer",
            ));
        }
    }

    Ok(())
}

fn parse_address_message(ifa: &ifaddrmsg, attributes: Attributes<'_>) -> Option<IpNet> {
    event!(
        Level::DEBUG,
        "RTM new/del addr family: {} flags: {} scope: {} idx: {}",
        ifa.ifa_family,
        ifa.ifa_flags,
        ifa.ifa_scope,
        ifa.ifa_index
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
        AF_INET, AF_INET6, AF_PHONET, AF_UNSPEC, EBUSY, ENOBUFS, IFA_ADDRESS, IFA_F_DADFAILED,
        IFA_F_DEPRECATED, IFA_F_PERMANENT, IFA_F_TENTATIVE, IFA_LOCAL, IFF_MULTICAST, IFF_RUNNING,
        IFF_UP, NLMSG_DONE, NLMSG_ERROR, RTM_DELADDR, RTM_NEWADDR, RTM_NEWLINK,
    };
    use pretty_assertions::{assert_eq, assert_matches};
    use shared::netlink::{ifaddrmsg, rtattr};
    use tokio::sync::watch;
    use tokio_util::sync::CancellationToken;
    use zerocopy::IntoBytes as _;
    use zerocopy::byteorder::native_endian::{U16, U32};

    use crate::address_monitor::netlink_address_monitor::{
        Dump, SIZE_OF_SOCKADDR_NL, SkippedStates, process_changes,
    };
    use crate::network_handler::Command;
    use crate::rtnetlink::{RTA_ALIGNTO, ReceiveBuffer, RecvBuf};
    use crate::test_utils::netlink::{
        done_message, error_payload, link_message, link_payload, netlink_message, reply,
    };
    use crate::utils::u32_to_usize;

    #[test]
    fn size_of_sockaddr_nl() {
        assert_eq!(
            u32_to_usize(SIZE_OF_SOCKADDR_NL),
            size_of::<libc::sockaddr_nl>()
        );
    }

    struct MockNetlinkSocket {
        done: AtomicBool,
    }

    impl RecvBuf<&mut [MaybeUninit<u8>]> for MockNetlinkSocket {
        #[expect(clippy::mut_mut, reason = "Mandated by the trait")]
        async fn recv_buf(&self, buf: &mut &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
            if self.done.fetch_or(true, Ordering::Relaxed) {
                // fixture exhausted; mirror a real socket and block
                return std::future::pending().await;
            }

            let bytes = include_bytes!("fixtures/commands.bin");

            buf.put_slice(bytes);

            Ok(bytes.len())
        }
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

        let cancellation_token = CancellationToken::new();

        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<Command>(100);

        {
            let cancellation_token = cancellation_token.clone();

            tokio::task::spawn(async move {
                let _guard = cancellation_token.clone().drop_guard();

                for (expected_address, expected_scope, expected_index) in expected {
                    let command = command_rx.recv().await;

                    let Command::NewAddress {
                        address,
                        scope,
                        index,
                    } = command.unwrap()
                    else {
                        panic!("Invalid command type");
                    };

                    assert_eq!(address, expected_address.parse().unwrap());
                    assert_eq!(scope, expected_scope);
                    assert_eq!(index, expected_index);
                }

                cancellation_token.cancel();

                assert_matches!(command_rx.recv().await, None);
            });
        }

        let (_start_tx, mut start_rx) = watch::channel(());

        let mut buffer = ReceiveBuffer::new();

        let result = process_changes(
            &cancellation_token,
            MockNetlinkSocket {
                done: AtomicBool::new(false),
            },
            command_tx,
            &mut start_rx,
            &mut buffer,
            &|_| Ok(()),
        )
        .await;

        assert_matches!(result, Ok(()));
    }

    /// Returns its datagrams one per receive, then cancels.
    struct ScriptedNetlinkSocket {
        datagrams: RefCell<VecDeque<std::io::Result<Vec<u8>>>>,
        cancellation_token: CancellationToken,
    }

    impl RecvBuf<&mut [MaybeUninit<u8>]> for ScriptedNetlinkSocket {
        #[expect(clippy::mut_mut, reason = "Mandated by the trait")]
        async fn recv_buf(&self, buf: &mut &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
            let next = self.datagrams.borrow_mut().pop_front();

            let Some(datagram) = next else {
                self.cancellation_token.cancel();

                return std::future::pending().await;
            };

            let bytes = datagram?;

            buf.put_slice(&bytes);

            Ok(bytes.len())
        }
    }

    struct Run {
        commands: Vec<Command>,
        requests: Vec<u32>,
    }

    /// Runs `process_changes` over `datagrams`, collecting the commands it sends and the sequences of the dumps it requests.
    async fn run(datagrams: Vec<std::io::Result<Vec<u8>>>, start: bool) -> Run {
        let cancellation_token = CancellationToken::new();

        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<Command>(100);

        let (start_tx, mut start_rx) = watch::channel(());

        if start {
            start_tx.send_replace(());
        }

        let socket = ScriptedNetlinkSocket {
            datagrams: RefCell::new(datagrams.into()),
            cancellation_token: cancellation_token.clone(),
        };

        let requests = RefCell::new(Vec::new());

        let mut buffer = ReceiveBuffer::new();

        let result = process_changes(
            &cancellation_token,
            socket,
            command_tx,
            &mut start_rx,
            &mut buffer,
            &|dump: Dump| {
                requests.borrow_mut().push(dump.sequence());

                Ok(())
            },
        )
        .await;

        assert_matches!(result, Ok(()));

        let mut commands = Vec::new();

        while let Ok(command) = command_rx.try_recv() {
            commands.push(command);
        }

        Run {
            commands,
            requests: requests.into_inner(),
        }
    }

    fn overflow() -> std::io::Result<Vec<u8>> {
        Err(std::io::Error::from_raw_os_error(ENOBUFS))
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
        run(vec![Ok(bytes.to_vec())], false).await.commands
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
    async fn device_link_is_reported_with_its_flags() {
        let flags = (IFF_UP | IFF_RUNNING | IFF_MULTICAST).cast_unsigned();

        let bytes = link_message(RTM_NEWLINK, AF_UNSPEC, 3, flags);

        assert_matches!(
            &*commands(&bytes).await,
            [Command::NewLink { index: 3, flags: reported }] if *reported == flags
        );
    }

    #[tokio::test]
    async fn receive_queue_overflow_is_recoverable() {
        let run = run(
            vec![
                overflow(),
                Ok(include_bytes!("fixtures/commands.bin").to_vec()),
            ],
            false,
        )
        .await;

        assert_eq!(run.requests, [Dump::Links.sequence()]);
        assert_matches!(&*run.commands, [Command::NewAddress { .. }, ..]);
    }

    #[tokio::test]
    async fn start_requests_a_link_dump() {
        assert_eq!(run(vec![], true).await.requests, [Dump::Links.sequence()]);
    }

    #[tokio::test]
    async fn end_of_link_dump_requests_the_addresses() {
        let run = run(
            vec![overflow(), Ok(done_message(Dump::Links.sequence()))],
            false,
        )
        .await;

        assert_eq!(
            run.requests,
            [Dump::Links.sequence(), Dump::Addresses.sequence()]
        );
    }

    #[tokio::test]
    async fn end_of_address_dump_requests_nothing() {
        let run = run(
            vec![
                overflow(),
                Ok(done_message(Dump::Links.sequence())),
                Ok(done_message(Dump::Addresses.sequence())),
            ],
            false,
        )
        .await;

        assert_eq!(
            run.requests,
            [Dump::Links.sequence(), Dump::Addresses.sequence()]
        );
    }

    #[tokio::test]
    async fn end_of_a_dump_that_is_not_running_is_ignored() {
        let run = run(vec![Ok(done_message(Dump::Links.sequence()))], false).await;

        assert_eq!(run.requests, Vec::<u32>::new());
    }

    #[tokio::test]
    async fn interrupted_dump_starts_over() {
        let interrupted_link = reply(
            RTM_NEWLINK,
            Dump::Links.sequence(),
            true,
            &link_payload(
                AF_UNSPEC,
                3,
                (IFF_UP | IFF_RUNNING | IFF_MULTICAST).cast_unsigned(),
            ),
        );

        let run = run(
            vec![
                overflow(),
                Ok(interrupted_link),
                Ok(done_message(Dump::Links.sequence())),
            ],
            false,
        )
        .await;

        assert_eq!(
            run.requests,
            [Dump::Links.sequence(), Dump::Links.sequence()]
        );
    }

    #[tokio::test]
    async fn overflow_during_a_dump_waits_for_its_end() {
        let run = run(
            vec![
                overflow(),
                overflow(),
                Ok(done_message(Dump::Links.sequence())),
            ],
            false,
        )
        .await;

        assert_eq!(
            run.requests,
            [Dump::Links.sequence(), Dump::Links.sequence()]
        );
    }

    #[tokio::test]
    async fn failed_dump_does_not_hold_back_the_next() {
        let failure = reply(
            u16::try_from(NLMSG_ERROR).unwrap(),
            Dump::Links.sequence(),
            false,
            &error_payload(-EBUSY),
        );

        let run = run(vec![overflow(), Ok(failure), overflow()], false).await;

        assert_eq!(
            run.requests,
            [Dump::Links.sequence(), Dump::Links.sequence()]
        );
    }
}
