use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use color_eyre::eyre;
use libc::{
    AF_PACKET, IFA_ADDRESS, IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_HOMEADDRESS, IFA_F_TENTATIVE,
    IFA_FLAGS, IFA_LABEL, IFA_LOCAL, NETLINK_ROUTE, NLM_F_DUMP, NLM_F_REQUEST, NLMSG_DONE,
    NLMSG_ERROR, NLMSG_NOOP, RTM_DELADDR, RTM_GETADDR, RTM_NEWADDR, RTMGRP_IPV4_IFADDR,
    RTMGRP_IPV6_IFADDR, RTMGRP_LINK,
};
use socket2::SockAddrStorage;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use zerocopy::IntoBytes as _;

use crate::config::Config;
use crate::ffi::{
    IFA_PAYLOAD, IFA_RTA, NLMSG_DATA, NLMSG_NEXT, NLMSG_OK, RTA_DATA, RTA_NEXT, RTA_OK,
    RTA_PAYLOAD, ifaddrmsg, netlink_req, nlmsghdr, rtattr,
};
use crate::network_handler::Command;

#[expect(clippy::cast_possible_truncation, reason = "Compile-time checked")]
const SIZE_OF_SOCKADDR_NL: u32 = const {
    const SIZE: usize = size_of::<libc::sockaddr_nl>();

    assert!(
        SIZE <= u32::MAX as usize,
        "`sockaddr_nl`'s size needs to fit in a `u32`"
    );

    SIZE as u32
};

pub struct NetlinkAddressMonitor {
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
    socket: tokio::net::UdpSocket,
    start_rx: tokio::sync::watch::Receiver<()>,
}

impl NetlinkAddressMonitor {
    /// Implementation for Netlink sockets, i.e. Linux
    pub fn new(
        cancellation_token: CancellationToken,
        command_tx: Sender<Command>,
        start_rx: tokio::sync::watch::Receiver<()>,
        config: &Config,
    ) -> Result<Self, std::io::Error> {
        let mut rtm_groups = RTMGRP_LINK;

        if !config.ipv4only {
            rtm_groups |= RTMGRP_IPV6_IFADDR;
        }

        if !config.ipv6only {
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

        Ok(Self {
            cancellation_token,
            command_tx,
            socket: tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(socket))?,
            start_rx,
        })
    }

    pub fn request_current_state(&mut self) -> Result<(), std::io::Error> {
        let request = netlink_req {
            nh: nlmsghdr {
                nlmsg_len: size_of::<netlink_req>().try_into().unwrap(),
                nlmsg_type: RTM_GETADDR,
                nlmsg_flags: u16::try_from(NLM_F_REQUEST | NLM_F_DUMP).unwrap(),
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },

            ifa: ifaddrmsg {
                ifa_family: AF_PACKET.try_into().unwrap(),
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

        socket2::SockRef::from(&self.socket).send_to(request.as_bytes(), &socket_addr)?;

        Ok(())
    }

    #[expect(clippy::too_many_lines, reason = "WIP")]
    pub async fn process_changes(&mut self) -> Result<(), eyre::Report> {
        // we originally had this on the stack (array) but tokio then moves the whole task to the heap because of size

        // we don't need to zero out the buffer between runs as `recv_buf` starts at 0 and returns `bytes_read`
        // sine we only read that portion we don't need to worry about the leftovers
        let mut buffer = vec![MaybeUninit::<u8>::uninit(); 4096];

        loop {
            let mut buffer_slice = buffer.as_mut_slice();

            let bytes_read = tokio::select! {
                () = self.cancellation_token.cancelled() => {
                    break;
                },
                changed = self.start_rx.changed() => {
                    if changed.is_err() {
                        break;
                    }

                    self.request_current_state()?;

                    continue;
                },
                result = self.socket.recv_buf(&mut buffer_slice) => {
                    result?
                }
            };

            event!(Level::DEBUG, "netlink message with {} bytes", bytes_read);

            // `recv_buf` tells us that `bytes_read` were read from the socket into our `buffer`, so they're initialized
            // SaAbFcEdTeY: we are only initializing the parts of the buffer `recv_buf_from` has written to
            // let buffer = unsafe { &*(&raw const buffer[0..bytes_read] as *const [u8]) };

            #[expect(clippy::cast_possible_truncation, reason = "")]
            let mut len = { bytes_read as u32 };

            #[expect(clippy::cast_ptr_alignment, reason = "")]
            // SAFETY: This is how it's done
            let mut nlh = unsafe { &mut *buffer.as_mut_ptr().cast::<nlmsghdr>() };

            while NLMSG_OK(nlh, len) {
                if i32::from(nlh.nlmsg_type) == NLMSG_NOOP {
                    event!(Level::DEBUG, "NOOP");
                } else if i32::from(nlh.nlmsg_type) == NLMSG_DONE {
                    event!(Level::DEBUG, "DONE");
                } else if i32::from(nlh.nlmsg_type) == NLMSG_ERROR {
                    event!(Level::DEBUG, "ERROR");
                    break;
                } else if nlh.nlmsg_type != RTM_NEWADDR && nlh.nlmsg_type != RTM_DELADDR {
                    event!(Level::DEBUG, "invalid rtm_message type {}", nlh.nlmsg_type);
                } else {
                    #[expect(
                        clippy::cast_possible_truncation,
                        reason = "Payload cannot be larger than `u16`"
                    )]
                    let mut attr_len = { IFA_PAYLOAD(nlh) as u16 };

                    let ifa: &mut ifaddrmsg = NLMSG_DATA(nlh);

                    // TODO: these are repeated on the `IFA_FLAGS` below, can we remove this checks?
                    // Are we at risk of discarding packages?
                    // How do the `ifa_flags` here relate to the `IFA_FLAGS` on the `rtattr` below?
                    let ifa_flags = u32::from(ifa.ifa_flags);

                    if ((ifa_flags) & IFA_F_DADFAILED == IFA_F_DADFAILED)
                        || (ifa_flags & IFA_F_HOMEADDRESS == IFA_F_HOMEADDRESS)
                        || (ifa_flags & IFA_F_DEPRECATED == IFA_F_DEPRECATED)
                        || (ifa_flags & IFA_F_TENTATIVE == IFA_F_TENTATIVE)
                    {
                        event!(
                            Level::DEBUG,
                            "ignore address with invalid state {:#x}",
                            ifa_flags
                        );
                    } else {
                        event!(
                            Level::DEBUG,
                            "RTM new/del addr family: {} flags: {} scope: {} idx: {}",
                            ifa.ifa_family,
                            ifa.ifa_flags,
                            ifa.ifa_scope,
                            ifa.ifa_index
                        );

                        let ifa_scope = ifa.ifa_scope;
                        let ifa_index = ifa.ifa_index;

                        let mut rta: &mut rtattr = IFA_RTA(ifa);

                        let mut addr: Option<IpAddr> = None;

                        #[expect(clippy::big_endian_bytes, reason = "Networking code")]
                        while RTA_OK(rta, attr_len) {
                            event!(Level::DEBUG, "rt_attr {} {}", rta.rta_len, rta.rta_type);

                            // TODO validate if we need `IFA_LOCAL`, it only matters for PPP connections, and I'm unsure if we can do broadcasts on that?
                            // If we can remove it we can rely solely on `IFA_ADDR`

                            if rta.rta_type == IFA_LABEL {
                                // unused, original codebase extracted
                                // the labels in here for ipv4, but ipv6 requires another way
                                // we do both the ipv6 way
                            } else if rta.rta_type == IFA_LOCAL {
                                let payload_size = RTA_PAYLOAD(rta);

                                if payload_size == 4 {
                                    let ipv4_in_network_order: &[u8; 4] = &*RTA_DATA(rta);

                                    let new = Ipv4Addr::from_bits(u32::from_be_bytes(
                                        *ipv4_in_network_order,
                                    ));

                                    if let Some(addr) = addr {
                                        event!(Level::ERROR, old = %addr, %new);
                                    }

                                    addr = Some(new.into());
                                } else {
                                    // `IFA_LOCAL` is only issued for IPv4 addresses
                                }
                            } else if rta.rta_type == IFA_ADDRESS {
                                let payload_size = RTA_PAYLOAD(rta);

                                if payload_size == 4 {
                                    let ipv4_in_network_order: &[u8; 4] = &*RTA_DATA(rta);

                                    let new = Ipv4Addr::from_bits(u32::from_be_bytes(
                                        *ipv4_in_network_order,
                                    ));

                                    if let Some(addr) = addr {
                                        event!(Level::ERROR, old = %addr, %new);
                                    }

                                    addr = Some(new.into());
                                } else if payload_size == 16 {
                                    let ipv6_in_network_order: &[u8; 16] = &*RTA_DATA(rta);

                                    let new = Ipv6Addr::from_bits(u128::from_be_bytes(
                                        *ipv6_in_network_order,
                                    ));

                                    if let Some(addr) = addr {
                                        event!(Level::ERROR, old = %addr, %new);
                                    }

                                    addr = Some(new.into());
                                } else {
                                    // IPv4, IPv6, what's next? IPv8?
                                }
                            } else if rta.rta_type == IFA_FLAGS {
                                // https://github.com/torvalds/linux/blob/febbc555cf0fff895546ddb8ba2c9a523692fb55/include/uapi/linux/if_addr.h#L35
                                // unused
                                // original:
                                // _, ifa_flags = struct.unpack_from('HI', buf, i)
                            } else {
                                // ...
                            }

                            rta = RTA_NEXT(rta, &mut attr_len);
                        }

                        if let Some(addr) = addr {
                            let command = if nlh.nlmsg_type == RTM_NEWADDR {
                                Command::NewAddress {
                                    address: addr,
                                    scope: ifa_scope,
                                    index: ifa_index,
                                }
                            } else if nlh.nlmsg_type == RTM_DELADDR {
                                Command::DeleteAddress {
                                    address: addr,
                                    scope: ifa_scope,
                                    index: ifa_index,
                                }
                            } else {
                                // unreachable because we checked above
                                unreachable!()
                            };

                            if let Err(error) = self.command_tx.send(command).await {
                                if self.cancellation_token.is_cancelled() {
                                    event!(Level::INFO, command = ?error.0, "Could not announce command due to shutting down");
                                    break;
                                } else {
                                    event!(Level::ERROR, command = ?error.0, "Failed to announce command");
                                }
                            }
                        } else {
                            event!(Level::DEBUG, "no address in RTM message");
                        }
                    }
                }

                nlh = NLMSG_NEXT(nlh, &mut len);
            }
        }

        Ok(())
    }

    #[expect(unused, reason = "WIP")]
    fn cleanup() {
        // self.aio_loop.remove_reader(self.socket.fileno())
        // self.socket.close()
        // super().cleanup()
    }
}
