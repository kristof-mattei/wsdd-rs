use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use color_eyre::eyre;
use libc::{
    AF_INET, AF_INET6, AF_PACKET, IFA_ADDRESS, IFA_F_DADFAILED, IFA_F_DEPRECATED,
    IFA_F_HOMEADDRESS, IFA_F_TENTATIVE, IFA_FLAGS, IFA_LABEL, IFA_LOCAL, NETLINK_ROUTE, NLM_F_DUMP,
    NLM_F_REQUEST, RTM_DELADDR, RTM_GETADDR, RTM_NEWADDR, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR,
    RTMGRP_LINK,
};
use socket2::SockAddrStorage;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use zerocopy::{FromBytes as _, IntoBytes as _};

use crate::config::Config;
use crate::ffi::{
    NLMSG_ALIGNTO, RTA_ALIGNTO, ifaddrmsg, netlink_req, nlmsghdr, rta_type_to_label, rtattr,
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

fn align_to(offset: usize, align_to: usize) -> usize {
    // this doesn't work for offset = 0
    // offset + align_to - (offset % align_to)

    offset.div_ceil(align_to) * align_to
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
        // Notice the buffer is u32 because all of our structs written here by the kernel
        // are aligned to 4 bytes
        let mut buffer = vec![MaybeUninit::<u32>::uninit(); 1024];

        // SAFETY: created from a valid vector, so all the slice guarantees are upheld
        let buffer = unsafe {
            std::slice::from_raw_parts_mut(
                buffer.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                buffer.len() * std::mem::size_of::<MaybeUninit<u32>>(),
            )
        };

        loop {
            let bytes_read = {
                let mut buffer_byte_cursor = &mut *buffer;

                tokio::select! {
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
                        result = self.socket.recv_buf(&mut buffer_byte_cursor) => {
                            result?
                        }
                }
            };

            event!(Level::DEBUG, "netlink message with {} bytes", bytes_read);

            // SAFETY: created from a valid vector, so all the slice guarantees are upheld
            let buffer = unsafe {
                std::slice::from_raw_parts(
                    buffer.as_ptr().cast::<MaybeUninit<u8>>(),
                    buffer.len() * std::mem::size_of::<MaybeUninit<u32>>(),
                )
            };

            // SAFETY: we are only initializing the parts of the buffer `recv_buf_from` has written to
            let buffer = unsafe { &*(&raw const buffer[..bytes_read] as *const [u8]) };

            let mut message_offset = 0;

            while message_offset < bytes_read {
                let (message, _suffix) = nlmsghdr::ref_from_prefix(&buffer[message_offset..])
                    .map_err(|error| eyre::Report::msg(error.to_string()))?;

                if message.nlmsg_type != RTM_NEWADDR && message.nlmsg_type != RTM_DELADDR {
                    event!(
                        Level::DEBUG,
                        "invalid rtm_message type {}",
                        message.nlmsg_type
                    );

                    // skip this message and its data
                    message_offset += align_to(message.nlmsg_len as usize, NLMSG_ALIGNTO as usize);

                    continue;
                }

                let data_offset =
                    message_offset + align_to(size_of::<nlmsghdr>(), NLMSG_ALIGNTO as usize);

                // decode ifaddrmsg as in if_addr.h
                let (ifa, _suffix) = ifaddrmsg::ref_from_prefix(&buffer[data_offset..])
                    .map_err(|error| eyre::Report::msg(error.to_string()))?;

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

                    // skip this message and its data
                    message_offset += align_to(message.nlmsg_len as usize, NLMSG_ALIGNTO as usize);

                    continue;
                }

                event!(
                    Level::DEBUG,
                    "RTM new/del addr family: {} flags: {} scope: {} idx: {}",
                    ifa.ifa_family,
                    ifa.ifa_flags,
                    ifa.ifa_scope,
                    ifa.ifa_index
                );

                // Based on `RTA_LENGTH`
                let data_length = message.nlmsg_len as usize
                    - (align_to(
                        size_of::<ifaddrmsg>()
                            + align_to(size_of::<nlmsghdr>(), NLMSG_ALIGNTO as usize),
                        NLMSG_ALIGNTO as usize,
                    ));

                // Second parameter is based on `IFA_RTA`
                // to find out the start of the first `rtattr`
                let addr = parse_attributes(
                    buffer,
                    data_offset + align_to(size_of::<ifaddrmsg>(), NLMSG_ALIGNTO as usize),
                    data_offset,
                    data_length,
                    ifa,
                )?;

                let Some(addr) = addr else {
                    event!(Level::DEBUG, "no address in RTM message");

                    message_offset += align_to(message.nlmsg_len as usize, NLMSG_ALIGNTO as usize);

                    continue;
                };

                let command = if message.nlmsg_type == RTM_NEWADDR {
                    Command::NewAddress {
                        address: addr,
                        scope: ifa.ifa_scope,
                        index: ifa.ifa_index,
                    }
                } else if message.nlmsg_type == RTM_DELADDR {
                    Command::DeleteAddress {
                        address: addr,
                        scope: ifa.ifa_scope,
                        index: ifa.ifa_index,
                    }
                } else {
                    // unreachable because we checked above
                    unreachable!()
                };

                // event!(Level::INFO, ?command);

                if let Err(error) = self.command_tx.send(command).await {
                    if self.cancellation_token.is_cancelled() {
                        event!(Level::INFO, command = ?error.0, "Could not announce command due to shutting down");
                        break;
                    } else {
                        event!(Level::ERROR, command = ?error.0, "Failed to announce command");
                    }
                }

                message_offset += align_to(message.nlmsg_len as usize, NLMSG_ALIGNTO as usize);
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

#[expect(clippy::big_endian_bytes, reason = "We're reading network data")]
fn parse_attributes(
    buffer: &[u8],
    mut attribute_offset: usize,
    data_offset: usize,
    data_length: usize,
    ifa: &ifaddrmsg,
) -> Result<Option<IpAddr>, eyre::Report> {
    let mut addr: Option<IpAddr> = None;

    while attribute_offset < data_length + data_offset {
        let rta = match rtattr::ref_from_prefix(&buffer[attribute_offset..]) {
            Ok((rta, _suffix)) => rta,
            Err(error) => {
                event!(Level::ERROR, ?error, "Error mapping buffer to `rtattr`");

                // TODO use thiserror
                return Err(eyre::Report::msg(
                    "ConvertError: Error mapping buffer to `rtattr`",
                ));
            },
        };

        let rta_payload =
            Into::<usize>::into(rta.rta_len) - align_to(size_of::<rtattr>(), RTA_ALIGNTO.into());

        event!(
            Level::DEBUG,
            "rt_attr type: {} ({}), payload length: {}",
            rta.rta_type,
            rta_type_to_label(rta.rta_type).unwrap_or("Unknown type"),
            rta_payload,
        );

        if usize::from(rta.rta_len) < size_of::<rtattr>() {
            event!(Level::DEBUG, "Invalid `rta_len`. skipping remainder.");
            break;
        }

        if rta.rta_type == IFA_LABEL {
            // unused, original codebase extracted
            // the labels in here for ipv4, but ipv6 requires another way
            // we do both the ipv6 way
        } else if rta.rta_type == IFA_LOCAL && i32::from(ifa.ifa_family) == AF_INET {
            if rta_payload == 4 {
                // for `IFA_LOCAL` and a payload of 4 we have an IPv4 address
                let (ipv4_in_network_order, _suffix) =
                    <[u8; 4]>::ref_from_prefix(&buffer[attribute_offset + size_of::<rtattr>()..])
                        .unwrap();

                addr = Some(Ipv4Addr::from_bits(u32::from_be_bytes(*ipv4_in_network_order)).into());
            }
        } else if rta.rta_type == IFA_ADDRESS && i32::from(ifa.ifa_family) == AF_INET6 {
            if rta_payload == 16 {
                // for `IFA_ADDRESS` and a payload of 16 we have an IPv6 address
                let (ipv6_in_network_order, _suffix) =
                    <[u8; 16]>::ref_from_prefix(&buffer[attribute_offset + size_of::<rtattr>()..])
                        .unwrap();

                addr =
                    Some(Ipv6Addr::from_bits(u128::from_be_bytes(*ipv6_in_network_order)).into());
            }
        } else if rta.rta_type == IFA_FLAGS {

            // https://github.com/torvalds/linux/blob/febbc555cf0fff895546ddb8ba2c9a523692fb55/include/uapi/linux/if_addr.h#L35
            // unused
            // original:
            // _, ifa_flags = struct.unpack_from('HI', buf, i)
        } else {
            // ...
        }

        attribute_offset += align_to(usize::from(rta.rta_len), RTA_ALIGNTO as usize);
    }

    Ok(addr)
}
