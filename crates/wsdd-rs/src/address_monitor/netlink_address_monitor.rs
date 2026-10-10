use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::ControlFlow;
use std::sync::Arc;

use bytes::BufMut;
use color_eyre::eyre;
use ipnet::IpNet;
use libc::{
    AF_INET, AF_INET6, AF_UNSPEC, IFA_ADDRESS, IFA_F_DADFAILED, IFA_F_DEPRECATED,
    IFA_F_HOMEADDRESS, IFA_F_TENTATIVE, IFA_FLAGS, IFA_LABEL, IFA_LOCAL, NETLINK_ROUTE, NLM_F_ACK,
    NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, RTM_DELADDR, RTM_GETADDR,
    RTM_NEWADDR, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK,
};
use shared::netlink::{NetlinkRequest, ifaddrmsg, nlmsgerr, nlmsghdr};
use socket2::SockAddrStorage;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use wsdd_rs::define_typed_size;
use zerocopy::{FromBytes as _, IntoBytes as _};

use crate::config::{BindTo, Config};
use crate::ffi::getpagesize;
use crate::kernel_buffer::AlignedBuffer;
use crate::netlink::{attributes, messages};
use crate::network_handler::Command;
use crate::utils::task::spawn_with_name;

define_typed_size!(SIZE_OF_SOCKADDR_NL, u32, libc::sockaddr_nl);

pub struct NetlinkAddressMonitor {
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
    config: Arc<Config>,
    socket: Arc<tokio::net::UdpSocket>,
    start_handler: tokio::task::JoinHandle<()>,
}

trait RecvBuf<B: BufMut> {
    async fn recv_buf(&self, buf: &mut B) -> std::io::Result<usize>;
}

impl<B: BufMut> RecvBuf<B> for &tokio::net::UdpSocket {
    async fn recv_buf(&self, buf: &mut B) -> std::io::Result<usize> {
        tokio::net::UdpSocket::recv_buf::<B>(self, buf).await
    }
}

impl NetlinkAddressMonitor {
    /// Implementation for Netlink sockets, i.e. Linux.
    pub fn new(
        cancellation_token: CancellationToken,
        command_tx: Sender<Command>,
        start_rx: tokio::sync::watch::Receiver<()>,
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

        let socket = {
            let socket = std::net::UdpSocket::from(socket);
            let socket = tokio::net::UdpSocket::from_std(socket)?;
            Arc::new(socket)
        };

        let start_handler = {
            let cancellation_token = cancellation_token.clone();
            let config = Arc::clone(&config);
            let socket = Arc::clone(&socket);
            let mut start_rx = start_rx;

            spawn_with_name("request current network state", async move {
                loop {
                    tokio::select! {
                        () = cancellation_token.cancelled() => {
                            break;
                        },
                        changed = start_rx.changed() => {
                            if changed.is_err() {
                                break;
                            }
                        },
                    };

                    event!(Level::INFO, "Requesting current network state");

                    if let Err(error) = request_current_state(&config, &socket) {
                        event!(Level::ERROR, ?error, "Failed to send start packet");
                    }
                }
            })
        };

        Ok(Self {
            cancellation_token,
            command_tx,
            config,
            socket,
            start_handler,
        })
    }

    pub async fn teardown(self) {
        self.cancellation_token.cancel();

        let _r = self.start_handler.await;
    }

    pub async fn process_changes(&self) -> Result<(), eyre::Report> {
        // we originally had this on the stack (array) but tokio then moves the whole task to the heap because of size
        // Notice the buffer's alignment being equal to the alignment of `nlmsghdr`.
        // This is because we will be reading structs from this buffer who have, at max, that alignment.
        let mut buffer = build_buffer();

        loop {
            match process_changes::<&tokio::net::UdpSocket>(
                &self.cancellation_token,
                &*self.socket,
                self.command_tx.clone(),
                &mut buffer,
            )
            .await?
            {
                ControlFlow::Break(()) => {
                    return Ok(());
                },
                ControlFlow::Continue(()) => {
                    // recover the lost notifications by re-requesting the current state
                    if let Err(error) = request_current_state(&self.config, &self.socket) {
                        event!(
                            Level::ERROR,
                            ?error,
                            "Failed to re-request current network state"
                        );
                    }
                },
            }
        }
    }
}

fn build_buffer() -> AlignedBuffer<{ align_of::<nlmsghdr>() }> {
    // Can't have smaller than this on x86
    const MIN_PAGE_SIZE: usize = 4096;
    // Large enough for the kernel's max packet (see `NLMSG_GOODSIZE`)
    // https://github.com/torvalds/linux/blob/24d479d26b25bce5faea3ddd9fa8f3a6c3129ea7/include/linux/netlink.h#L272-L276
    const MAX_PAGE_SIZE: usize = 8192;

    // The kernel itself caps recvmsg sizing at `NLMSG_GOODSIZE = min(PAGE_SIZE, 8192)`,
    // so allocating more than 8192 bytes would never be filled. We mirror that cap here.
    let page_size = getpagesize().clamp(MIN_PAGE_SIZE, MAX_PAGE_SIZE);

    AlignedBuffer::<{ align_of::<nlmsghdr>() }>::new(page_size)
}

/// Reads and processes netlink messages until cancelled (`Break`), the receive queue
/// overflows (`Continue`, the caller recovers and re-enters), or a fatal receive error.
async fn process_changes<R>(
    cancellation_token: &CancellationToken,
    recv_buf: R,
    command_tx: Sender<Command>,
    buffer: &mut AlignedBuffer<{ align_of::<nlmsghdr>() }>,
) -> Result<ControlFlow<()>, eyre::Report>
where
    R: for<'a> RecvBuf<&'a mut [MaybeUninit<u8>]>,
{
    // we don't need to zero out the buffer between runs as `recv_buf` starts at 0 and returns `bytes_read`
    // since we only read that portion we don't need to worry about the leftovers

    loop {
        let bytes_read = {
            let mut buffer_byte_cursor = &mut **buffer;

            tokio::select! {
                () = cancellation_token.cancelled() => {
                    return Ok(ControlFlow::Break(()));
                },
                result = recv_buf.recv_buf(&mut buffer_byte_cursor) => {
                    match result {
                        Ok(bytes_read) => bytes_read,
                        Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {
                            // the kernel dropped notifications because our receive queue overflowed
                            event!(
                                Level::WARN,
                                "netlink receive queue overflowed, notifications were lost"
                            );

                            return Ok(ControlFlow::Continue(()));
                        },
                        Err(error) => {
                            return Err(error.into());
                        },
                    }
                },
            }
        };

        event!(
            Level::DEBUG,
            length = bytes_read,
            "netlink message received"
        );

        let buffer = {
            let raw_buffer = buffer.as_ptr().cast::<u8>();

            // SAFETY: we are only initializing the parts of the buffer `recv_buf` has written to
            unsafe { std::slice::from_raw_parts(raw_buffer, bytes_read) }
        };

        if let Err(error) = parse_netlink_response(buffer, cancellation_token, &command_tx).await {
            event!(
                Level::ERROR,
                ?error,
                "Error parsing response as a netlink response"
            );
        }
    }
}

fn request_current_state(
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
            nlmsg_len: size_of::<NetlinkRequest>().try_into().unwrap(),
            nlmsg_type: RTM_GETADDR,
            nlmsg_flags: u16::try_from(NLM_F_REQUEST | NLM_F_ACK | NLM_F_DUMP).unwrap(),
            nlmsg_seq: 1,
            nlmsg_pid: 0,
        },
        ifa: ifaddrmsg {
            ifa_family: family.try_into().unwrap(),
            ifa_prefixlen: 0,
            ifa_flags: 0,
            ifa_scope: 0,
            ifa_index: 0,
        },
    };

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

    socket2::SockRef::from(&socket).send_to(request.as_bytes(), &socket_addr)?;

    Ok(())
}

async fn parse_netlink_response(
    buffer: &[u8],
    cancellation_token: &CancellationToken,
    command_tx: &Sender<Command>,
) -> Result<(), eyre::Report> {
    for (nlh, payload) in messages(buffer) {
        let command = if Into::<i32>::into(nlh.nlmsg_type) == NLMSG_DONE {
            break;
        } else if i32::from(nlh.nlmsg_type) == NLMSG_ERROR {
            let (error, _) = nlmsgerr::ref_from_prefix(payload)
                .expect("`NLMSG_ERROR` must start with an `nlmsgerr`, as this is kernel data");

            if error.error == 0 {
                event!(Level::DEBUG, "ACK");

                break;
            }

            event!(
                Level::ERROR,
                error = %std::io::Error::from_raw_os_error(error.error.wrapping_neg()),
                "NLMSG_ERROR"
            );

            None
        } else if i32::from(nlh.nlmsg_type) == NLMSG_NOOP {
            event!(Level::DEBUG, "NLMSG_NOOP");

            None
        } else if nlh.nlmsg_type == RTM_NEWADDR {
            let (ifa, rest) = split_address_message(payload);

            if has_usable_state(ifa) {
                parse_address_message(ifa, rest).map(|address| Command::NewAddress {
                    address,
                    scope: ifa.ifa_scope,
                    index: ifa.ifa_index,
                })
            } else {
                None
            }
        } else if nlh.nlmsg_type == RTM_DELADDR {
            let (ifa, rest) = split_address_message(payload);

            // a deleted address is gone, whatever its state
            parse_address_message(ifa, rest).map(|address| Command::DeleteAddress {
                address,
                scope: ifa.ifa_scope,
                index: ifa.ifa_index,
            })
        } else {
            event!(
                Level::DEBUG,
                "unhandled rtm_message type {}",
                nlh.nlmsg_type
            );

            None
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

fn split_address_message(payload: &[u8]) -> (&ifaddrmsg, &[u8]) {
    ifaddrmsg::ref_from_prefix(payload)
        .expect("an address message must start with an `ifaddrmsg`, as this is kernel data")
}

fn has_usable_state(ifa: &ifaddrmsg) -> bool {
    let ifa_flags = u32::from(ifa.ifa_flags);

    if (ifa_flags & IFA_F_DADFAILED) != 0
        || (ifa_flags & IFA_F_HOMEADDRESS) != 0
        || (ifa_flags & IFA_F_DEPRECATED) != 0
        || (ifa_flags & IFA_F_TENTATIVE) != 0
    {
        event!(
            Level::DEBUG,
            "ignore address with invalid state {:#x}",
            ifa_flags
        );

        return false;
    }

    true
}

fn parse_address_message(ifa: &ifaddrmsg, rest: &[u8]) -> Option<IpNet> {
    event!(
        Level::DEBUG,
        "RTM new/del addr family: {} flags: {} scope: {} idx: {}",
        ifa.ifa_family,
        ifa.ifa_flags,
        ifa.ifa_scope,
        ifa.ifa_index
    );

    let mut addr = None;

    for (rta, value) in attributes(rest) {
        event!(
            Level::DEBUG,
            "rt_attr type: {} {} ({})",
            rta.rta_len,
            rta.rta_type,
            rta.label().unwrap_or("Unknown type")
        );

        if rta.rta_type == IFA_ADDRESS && i32::from(ifa.ifa_family) == AF_INET6 {
            let octets: [u8; 16] = value
                .try_into()
                .expect("an IPv6 `IFA_ADDRESS` must be 16 bytes, as this is kernel data");

            addr = Some(Ipv6Addr::from(octets).into());
        } else if rta.rta_type == IFA_LOCAL && i32::from(ifa.ifa_family) == AF_INET {
            // `libc::IFA_ADDRESS` is prefix address, rather than local interface address.
            // It makes no difference for normally configured broadcast interfaces,
            // but for point-to-point `libc::IFA_ADDRESS` is DESTINATION address,
            // local address is supplied in `libc::IFA_LOCAL` attribute.
            // https://github.com/torvalds/linux/blob/e9a6fb0bcdd7609be6969112f3fbfcce3b1d4a7c/include/uapi/linux/if_addr.h#L16-L25
            let octets: [u8; 4] = value
                .try_into()
                .expect("an IPv4 `IFA_LOCAL` must be 4 bytes, as this is kernel data");

            addr = Some(Ipv4Addr::from(octets).into());
        } else if rta.rta_type == IFA_LABEL {
            // Intentionally unused, the label (only present on IPv4 messages) is not what we name interfaces by,
            // as it might be an alias label, e.g. `eth0:0`.
        } else if rta.rta_type == IFA_FLAGS {
            // https://github.com/torvalds/linux/blob/febbc555cf0fff895546ddb8ba2c9a523692fb55/include/uapi/linux/if_addr.h#L35
            // unused
            // original:
            // _, ifa_flags = struct.unpack_from('HI', buf, i)
        } else {
            // other attributes are intentionally ignored
        }
    }

    let Some(addr) = addr else {
        event!(Level::DEBUG, "no address in RTM message");

        return None;
    };

    let address = IpNet::new(addr, ifa.ifa_prefixlen)
        .expect("`prefix_len` must be valid for this address, as this is kernel data");

    Some(address)
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;
    use std::net::Ipv6Addr;
    use std::ops::ControlFlow;
    use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

    use bytes::BufMut as _;
    use ipnet::IpNet;
    use libc::{
        AF_INET6, EINVAL, IFA_ADDRESS, IFA_F_DEPRECATED, NLMSG_DONE, NLMSG_ERROR, RTM_DELADDR,
        RTM_NEWADDR,
    };
    use pretty_assertions::{assert_eq, assert_matches};
    use shared::netlink::{ifaddrmsg, nlmsghdr, rtattr};
    use tokio_util::sync::CancellationToken;
    use zerocopy::{FromZeros as _, IntoBytes as _};

    use crate::address_monitor::netlink_address_monitor::{
        RecvBuf, SIZE_OF_SOCKADDR_NL, build_buffer, process_changes,
    };
    use crate::network_handler::Command;
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

        let mut buffer = build_buffer();

        let result = process_changes(
            &cancellation_token,
            MockNetlinkSocket {
                done: AtomicBool::new(false),
            },
            command_tx,
            &mut buffer,
        )
        .await;

        assert_matches!(result, Ok(ControlFlow::Break(())));
    }

    struct OverflowingNetlinkSocket {
        calls: AtomicU8,
    }

    impl RecvBuf<&mut [MaybeUninit<u8>]> for &OverflowingNetlinkSocket {
        #[expect(clippy::mut_mut, reason = "Mandated by the trait")]
        async fn recv_buf(&self, buf: &mut &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
            match self.calls.fetch_add(1, Ordering::Relaxed) {
                0 => Err(std::io::Error::from_raw_os_error(libc::ENOBUFS)),
                1 => {
                    let bytes = include_bytes!("fixtures/commands.bin");

                    buf.put_slice(bytes);

                    Ok(bytes.len())
                },
                _ => {
                    // fixture exhausted; mirror a real socket and block
                    std::future::pending().await
                },
            }
        }
    }

    #[tokio::test]
    async fn receive_queue_overflow_is_recoverable() {
        let cancellation_token = CancellationToken::new();

        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<Command>(100);

        let socket = OverflowingNetlinkSocket {
            calls: AtomicU8::new(0),
        };

        let mut buffer = build_buffer();

        // the first pass ends at the overflow, asking the caller to recover and re-enter
        let result = process_changes(
            &cancellation_token,
            &socket,
            command_tx.clone(),
            &mut buffer,
        )
        .await;

        assert_matches!(result, Ok(ControlFlow::Continue(())));

        let consumer = {
            let cancellation_token = cancellation_token.clone();

            tokio::task::spawn(async move {
                let _guard = cancellation_token.clone().drop_guard();

                // a command arriving proves the re-entered loop picks up where the kernel left off
                let command = command_rx.recv().await;

                assert_matches!(command, Some(Command::NewAddress { .. }));
            })
        };

        let result = process_changes(&cancellation_token, &socket, command_tx, &mut buffer).await;

        assert_matches!(result, Ok(ControlFlow::Break(())));

        consumer.await.unwrap();
    }

    /// Delivers `bytes` once, then cancels.
    struct DrainingNetlinkSocket<'b> {
        bytes: &'b [u8],
        cancellation_token: CancellationToken,
        done: AtomicBool,
    }

    impl RecvBuf<&mut [MaybeUninit<u8>]> for DrainingNetlinkSocket<'_> {
        #[expect(clippy::mut_mut, reason = "Mandated by the trait")]
        async fn recv_buf(&self, buf: &mut &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
            if self.done.fetch_or(true, Ordering::Relaxed) {
                self.cancellation_token.cancel();

                return std::future::pending().await;
            }

            buf.put_slice(self.bytes);

            Ok(self.bytes.len())
        }
    }

    fn netlink_message(nlmsg_type: u16, payload: &[u8]) -> Vec<u8> {
        let header = nlmsghdr {
            nlmsg_len: u32::try_from(size_of::<nlmsghdr>() + payload.len()).unwrap(),
            nlmsg_type,
            nlmsg_flags: 0,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };

        [header.as_bytes(), payload].concat()
    }

    fn ipv6_address_message(nlmsg_type: u16, ifa_flags: u32, address: Ipv6Addr) -> Vec<u8> {
        let octets = address.octets();

        let ifa = ifaddrmsg {
            ifa_family: u8::try_from(AF_INET6).unwrap(),
            ifa_prefixlen: 64,
            ifa_flags: u8::try_from(ifa_flags).unwrap(),
            ifa_scope: 0,
            ifa_index: 2,
        };

        let rta = rtattr {
            rta_len: u16::try_from(size_of::<rtattr>() + octets.len()).unwrap(),
            rta_type: IFA_ADDRESS,
        };

        netlink_message(
            nlmsg_type,
            &[ifa.as_bytes(), rta.as_bytes(), octets.as_slice()].concat(),
        )
    }

    fn error_message(error: i32) -> Vec<u8> {
        netlink_message(
            u16::try_from(NLMSG_ERROR).unwrap(),
            &[error.as_bytes(), nlmsghdr::new_zeroed().as_bytes()].concat(),
        )
    }

    /// Every command `process_changes` sends for `bytes`.
    async fn commands(bytes: &[u8]) -> Vec<Command> {
        let cancellation_token = CancellationToken::new();

        let (command_tx, mut command_rx) = tokio::sync::mpsc::channel::<Command>(10);

        let socket = DrainingNetlinkSocket {
            bytes,
            cancellation_token: cancellation_token.clone(),
            done: AtomicBool::new(false),
        };

        let mut buffer = build_buffer();

        let result = process_changes(&cancellation_token, socket, command_tx, &mut buffer).await;

        assert_matches!(result, Ok(ControlFlow::Break(())));

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
    async fn ack_sends_no_command() {
        assert_matches!(&*commands(&error_message(0)).await, []);
    }

    #[tokio::test]
    async fn failed_request_sends_no_command() {
        assert_matches!(&*commands(&error_message(-EINVAL)).await, []);
    }
}
