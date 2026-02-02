use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use bytes::BufMut;
use color_eyre::eyre;
use ipnet::IpNet;
use libc::{
    AF_INET, AF_INET6, AF_UNSPEC, IFA_ADDRESS, IFA_F_DADFAILED, IFA_F_DEPRECATED,
    IFA_F_HOMEADDRESS, IFA_F_TENTATIVE, IFA_FLAGS, IFA_LABEL, IFA_LOCAL, NETLINK_ROUTE, NLM_F_ACK,
    NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, RTM_DELADDR, RTM_GETADDR,
    RTM_NEWADDR, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK, nlmsgerr,
};
use socket2::SockAddrStorage;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use wsdd_rs::define_typed_size;
use zerocopy::IntoBytes as _;

use crate::config::{BindTo, Config};
use crate::ffi::{SendPtr, getpagesize};
use crate::kernel_buffer::AlignedBuffer;
use crate::netlink::{
    IFA_PAYLOAD, IFA_RTA, NLMSG_DATA, NLMSG_NEXT, NLMSG_OK, NetlinkRequest, RTA_DATA, RTA_NEXT,
    RTA_OK, ifaddrmsg, nlmsghdr,
};
use crate::network_handler::Command;
use crate::utils::task::spawn_with_name;

define_typed_size!(SIZE_OF_SOCKADDR_NL, u32, libc::sockaddr_nl);

pub struct NetlinkAddressMonitor {
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
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
            let socket = Arc::clone(&socket);
            let mut start_rx = start_rx;

            spawn_with_name("start processing task", async move {
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

                    if let Err(error) = request_current_state(&config, &socket) {
                        event!(Level::ERROR, ?error, "Failed to send start packet");
                    }
                }
            })
        };

        Ok(Self {
            cancellation_token,
            command_tx,
            socket,
            start_handler,
        })
    }

    pub async fn teardown(self) {
        self.cancellation_token.cancel();

        let _r = self.start_handler.await;
    }

    pub async fn process_changes(&self) -> Result<(), eyre::Report> {
        process_changes::<&tokio::net::UdpSocket>(
            &self.cancellation_token,
            &*self.socket,
            self.command_tx.clone(),
        )
        .await
    }
}

fn build_buffer() -> Result<AlignedBuffer<{ align_of::<nlmsghdr>() }>, eyre::Report> {
    // Can't have smaller than this on x86
    const MIN_PAGE_SIZE: usize = 4096;
    // Large enough for the kernel's max packet (see `NLMSG_GOODSIZE`)
    // https://github.com/torvalds/linux/blob/24d479d26b25bce5faea3ddd9fa8f3a6c3129ea7/include/linux/netlink.h#L272-L276
    const MAX_PAGE_SIZE: usize = 8192;

    let page_size = getpagesize().clamp(MIN_PAGE_SIZE, MAX_PAGE_SIZE);

    AlignedBuffer::<{ align_of::<nlmsghdr>() }>::new(page_size).map_err(eyre::Report::msg)
}

async fn process_changes<R>(
    cancellation_token: &CancellationToken,
    recv_buf: R,
    command_tx: Sender<Command>,
) -> Result<(), eyre::Report>
where
    R: for<'a> RecvBuf<&'a mut [MaybeUninit<u8>]>,
{
    // we originally had this on the stack (array) but tokio then moves the whole task to the heap because of size

    // we don't need to zero out the buffer between runs as `recv_buf` starts at 0 and returns `bytes_read`
    // since we only read that portion we don't need to worry about the leftovers
    // Notice the buffer's alignment being equal to the alignment of `nlmsghdr`.
    // This is because we will be reading structs from this buffer who have, at max, that alignment.

    let mut buffer = build_buffer().map_err(eyre::Report::msg)?;

    loop {
        let bytes_read = {
            let mut buffer_byte_cursor = &mut *buffer;

            tokio::select! {
                () = cancellation_token.cancelled() => {
                    break;
                },
                result = recv_buf.recv_buf(&mut buffer_byte_cursor) => {
                    result?
                },
            }
        };

        event!(
            Level::DEBUG,
            length = bytes_read,
            "netlink message received"
        );

        let buffer = {
            let raw_buffer = buffer.as_ref().as_ptr().cast::<u8>();

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

    Ok(())
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
    let mut remaining_len = buffer.len();

    let mut nlh_wrapper = SendPtr::from_start(buffer);

    while NLMSG_OK(nlh_wrapper.get_ptr(), remaining_len) {
        // SAFETY: `NLMSG_OK`
        let nlh = unsafe { &*nlh_wrapper.get_ptr() };

        let command = if Into::<i32>::into(nlh.nlmsg_type) == NLMSG_DONE {
            break;
        } else if i32::from(nlh.nlmsg_type) == NLMSG_ERROR {
            // SAFETY: `nlh.nlmsg_type` guarantees
            let error = unsafe { &*NLMSG_DATA::<nlmsgerr>(nlh_wrapper.get_ptr()) };

            event!(Level::ERROR, "NLMSG_ERROR");

            if error.error == 0 {
                event!(Level::ERROR, "ACK");

                break;
            }

            None
        } else if i32::from(nlh.nlmsg_type) == NLMSG_NOOP {
            event!(Level::ERROR, "NLMSG_ERROR");

            None
        } else if nlh.nlmsg_type == RTM_NEWADDR {
            parse_address_message(nlh_wrapper.get_ptr()).map(|(ip_net, scope, index)| {
                Command::NewAddress {
                    address: ip_net,
                    scope,
                    index,
                }
            })
        } else if nlh.nlmsg_type == RTM_DELADDR {
            parse_address_message(nlh_wrapper.get_ptr()).map(|(ip_net, scope, index)| {
                Command::DeleteAddress {
                    address: ip_net,
                    scope,
                    index,
                }
            })
        } else {
            event!(
                Level::DEBUG,
                "unhandled rtm_message type {}",
                nlh.nlmsg_type
            );

            None
        };

        if let Some(command) = command {
            if let Err(error) = command_tx.send(command).await {
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

        nlh_wrapper.mutate(|p| NLMSG_NEXT(p, &mut remaining_len));
    }

    Ok(())
}

fn parse_address_message(raw_nlh: *const nlmsghdr) -> Option<(IpNet, u8, u32)> {
    let raw_ifa = NLMSG_DATA::<ifaddrmsg>(raw_nlh);

    // SAFETY:`nlh` is valid, and has an `ifa`
    let ifa = unsafe { &*raw_ifa };

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

        // skip this message and its data
        return None;
    }

    event!(
        Level::DEBUG,
        "RTM new/del addr family: {} flags: {} scope: {} idx: {}",
        ifa.ifa_family,
        ifa.ifa_flags,
        ifa.ifa_scope,
        ifa.ifa_index
    );

    let mut addr = None;

    let mut raw_rta = IFA_RTA(raw_ifa);
    let mut ifa_payload_remaining_length = IFA_PAYLOAD(raw_nlh);

    #[expect(clippy::big_endian_bytes, reason = "We're reading network data")]
    while RTA_OK(raw_rta, ifa_payload_remaining_length) {
        // SAFETY: See `RTA_OK`
        let rta = unsafe { &*raw_rta };

        event!(
            Level::DEBUG,
            "rt_attr type: {} {} ({})",
            rta.rta_len,
            rta.rta_type,
            rta.label().unwrap_or("Unknown type")
        );

        if rta.rta_type == IFA_ADDRESS && i32::from(ifa.ifa_family) == AF_INET6 {
            // SAFETY: Combination of `rta.rta_type` and `ifa.ifa_family`
            let ipv6_in_network_order = unsafe { &*RTA_DATA::<[u8; 16]>(raw_rta) };

            addr = Some(Ipv6Addr::from_bits(u128::from_be_bytes(*ipv6_in_network_order)).into());
        } else if rta.rta_type == IFA_LOCAL && i32::from(ifa.ifa_family) == AF_INET {
            // `libc::IFA_ADDRESS` is prefix address, rather than local interface address.
            // It makes no difference for normally configured broadcast interfaces,
            // but for point-to-point `libc::IFA_ADDRESS` is DESTINATION address,
            // local address is supplied in `libc::IFA_LOCAL` attribute.
            // https://github.com/torvalds/linux/blob/e9a6fb0bcdd7609be6969112f3fbfcce3b1d4a7c/include/uapi/linux/if_addr.h#L16-L25
            // SAFETY: Combination of `rta.rta_type` and `ifa.ifa_family`
            let ipv4_in_network_order = unsafe { &*RTA_DATA::<[u8; 4]>(raw_rta) };

            addr = Some(Ipv4Addr::from_bits(u32::from_be_bytes(*ipv4_in_network_order)).into());
        } else if rta.rta_type == IFA_LABEL {
            // unused, original codebase extracted
            // the labels in here for ipv4, but ipv6 requires another way
            // we do both the ipv6 way
        } else if rta.rta_type == IFA_FLAGS {
            // https://github.com/torvalds/linux/blob/febbc555cf0fff895546ddb8ba2c9a523692fb55/include/uapi/linux/if_addr.h#L35
            // unused
            // original:
            // _, ifa_flags = struct.unpack_from('HI', buf, i)
        } else {
            // other attributes are intentionally ignored
        }

        raw_rta = RTA_NEXT(raw_rta, &mut ifa_payload_remaining_length);
    }

    let Some(addr) = addr else {
        event!(Level::DEBUG, "no address in RTM message");

        return None;
    };

    Some((
        IpNet::new(addr, ifa.ifa_prefixlen)
            .expect("`prefix_len` must be valid for this address, as this is kernel data"),
        ifa.ifa_scope,
        ifa.ifa_index,
    ))
}

#[cfg(test)]
mod tests {
    use std::mem::MaybeUninit;
    use std::sync::atomic::{AtomicBool, Ordering};

    use bytes::BufMut as _;
    use pretty_assertions::{assert_eq, assert_matches};
    use tokio_util::sync::CancellationToken;

    use crate::address_monitor::netlink_address_monitor::{
        RecvBuf, SIZE_OF_SOCKADDR_NL, process_changes,
    };
    use crate::network_handler::Command;

    #[test]
    fn size_of_sockaddr_nl() {
        assert_eq!(size_of::<libc::sockaddr_nl>(), SIZE_OF_SOCKADDR_NL as usize);
    }

    struct MockNetlinkSocket {
        done: AtomicBool,
    }

    impl RecvBuf<&mut [MaybeUninit<u8>]> for MockNetlinkSocket {
        #[expect(clippy::mut_mut, reason = "Mandated by the trait")]
        async fn recv_buf(&self, buf: &mut &mut [MaybeUninit<u8>]) -> std::io::Result<usize> {
            if self.done.fetch_or(true, Ordering::Relaxed) {
                tokio::task::yield_now().await;

                return Ok(0);
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

        let result = process_changes(
            &cancellation_token,
            MockNetlinkSocket {
                done: AtomicBool::new(false),
            },
            command_tx,
        )
        .await;

        assert_matches!(result, Ok(()));
    }
}
