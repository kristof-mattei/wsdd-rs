use std::io::Error;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::FromRawFd as _;
use std::sync::Arc;

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
use zerocopy::{FromBytes as _, Immutable, IntoBytes};

use crate::config::Config;
use crate::ffi::{self, NLMSG_ALIGNTO, ifaddrmsg, nlmsghdr, rtattr};
use crate::network_handler::Command;

#[expect(clippy::cast_possible_truncation, reason = "Compile-time checked")]
const SIZE_OF_SOCKADDR_NL: u32 = const {
    const SIZE: usize = size_of::<libc::sockaddr_nl>();

    assert!(
        SIZE <= u32::MAX as usize,
        "`socketaddr_nl`'s size needs to fit in a `u32`"
    );

    SIZE as u32
};

pub struct NetlinkAddressMonitor {
    cancellation_token: CancellationToken,
    channel: Sender<Command>,
    socket: tokio::net::UdpSocket,
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
        channel: Sender<Command>,
        config: &Arc<Config>,
    ) -> Result<Self, std::io::Error> {
        let mut rtm_groups = RTMGRP_LINK;

        if !config.ipv4only {
            rtm_groups |= RTMGRP_IPV6_IFADDR;
        }

        if !config.ipv6only {
            rtm_groups |= RTMGRP_IPV4_IFADDR;
        }

        let raw_socket_fd =
            // SAFETY: libc call
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };

        if raw_socket_fd < 0 {
            return Err(Error::last_os_error());
        }

        // SAFETY: `raw_socket_fd` is a raw socket
        let socket = unsafe { socket2::Socket::from_raw_fd(raw_socket_fd) };

        socket.set_nonblocking(true)?;

        // SAFETY: this is how to do it as per the API docs
        let ((), socket_addr) = unsafe {
            socket2::SockAddr::try_init(
                |addr_storage: *mut SockAddrStorage, len: *mut libc::socklen_t| {
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
                },
            )
        }?;

        socket.bind(&socket_addr)?;

        Ok(Self {
            cancellation_token,
            channel,
            socket: tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(socket))?,
        })
    }

    pub fn request_current_state(&mut self) -> Result<(), std::io::Error> {
        #[derive(IntoBytes, Immutable)]
        #[repr(C)]
        struct Request {
            nh: ffi::nlmsghdr,
            ifa: ffi::ifaddrmsg,
        }

        let request = Request {
            nh: ffi::nlmsghdr {
                nlmsg_len: size_of::<Request>().try_into().unwrap(),
                nlmsg_type: RTM_GETADDR,
                nlmsg_flags: u16::try_from(NLM_F_REQUEST | NLM_F_DUMP).unwrap(),
                nlmsg_seq: 1,
                nlmsg_pid: 0,
            },

            ifa: ffi::ifaddrmsg {
                ifa_family: AF_PACKET.try_into().unwrap(),
                ifa_prefixlen: 0,
                ifa_flags: 0,
                ifa_scope: 0,
                ifa_index: 0,
            },
        };

        // SAFETY: this is how to do it as per the API docs
        let ((), socket_addr) = unsafe {
            socket2::SockAddr::try_init(
                |addr_storage: *mut SockAddrStorage, len: *mut libc::socklen_t| {
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
                    sockaddr_nl.nl_groups = 0;

                    // SAFETY: `len` is initialized and `non-null`
                    *len = SIZE_OF_SOCKADDR_NL;

                    Ok(())
                },
            )
        }?;

        socket2::SockRef::from(&self.socket).send_to(request.as_bytes(), &socket_addr)?;

        Ok(())
    }

    #[expect(clippy::too_many_lines, reason = "WIP")]
    pub async fn handle_change(&mut self) -> Result<(), eyre::Report> {
        loop {
            // we originally had this on the stack (array) but tokio moves it to the heap because of size
            let mut buffer = vec![MaybeUninit::<u8>::uninit(); 4096];

            let mut buffer_slice = buffer.as_mut_slice();

            #[expect(clippy::pattern_type_mismatch, reason = "Tokio macro")]
            let bytes_read = {
                tokio::select! {
                    () = self.cancellation_token.cancelled() => {
                        break;
                    },
                    result = self.socket.recv_buf(&mut buffer_slice) => {
                        result?
                    }
                }
            };

            // `recv_buf` tells us that `bytes_read` were read from the socket into our `buffer`, so they're initialized
            buffer.shrink_to(bytes_read);

            event!(Level::DEBUG, "netlink message with {} bytes", bytes_read);

            let buffer = Arc::<[_]>::from(buffer);

            // SAFETY: we are only initializing the parts of the buffer `recv_buf_from` has written to
            let buffer = unsafe { buffer.assume_init() };

            let mut offset = 0;

            while offset < bytes_read {
                let (message, _suffix) = nlmsghdr::ref_from_prefix(&buffer[offset..])
                    .map_err(|error| eyre::Report::msg(error.to_string()))?;

                offset += size_of::<ffi::nlmsghdr>();

                let Some(length) =
                    (message.nlmsg_len as usize).checked_sub(size_of::<ffi::nlmsghdr>())
                else {
                    break;
                };

                if message.nlmsg_type != RTM_NEWADDR && message.nlmsg_type != RTM_DELADDR {
                    event!(
                        Level::DEBUG,
                        "invalid rtm_message type {}",
                        message.nlmsg_type
                    );

                    offset += align_to(length, align_of::<nlmsghdr>());

                    continue;
                }

                // decode ifaddrmsg as in if_addr.h
                let (ifaddr_message, _suffix) = ffi::ifaddrmsg::ref_from_prefix(&buffer[offset..])
                    .map_err(|error| eyre::Report::msg(error.to_string()))?;

                let ifa_flags = u32::from(ifaddr_message.ifa_flags);

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

                    offset += align_to(length, NLMSG_ALIGNTO);
                    continue;
                }

                event!(
                    Level::DEBUG,
                    "RTM new/del addr family: {} flags: {} scope: {} idx: {}",
                    ifaddr_message.ifa_family,
                    ifaddr_message.ifa_flags,
                    ifaddr_message.ifa_scope,
                    ifaddr_message.ifa_index
                );

                let mut addr: Option<IpAddr> = None;

                let mut i = offset + size_of::<ifaddrmsg>();

                #[expect(clippy::big_endian_bytes, reason = "We're reading network data")]
                while i - offset < length {
                    let ifa_header = match ffi::rtattr::ref_from_prefix(&buffer[i..]) {
                        Ok((ifa_header, _suffix)) => ifa_header,
                        Err(err) => {
                            event!(Level::ERROR, ?err, "Error mapping buffer to `rtattr`");

                            // TODO use thiserror
                            return Err(eyre::Report::msg(
                                "ConvertError: Error mapping buffer to `rtattr`",
                            ));
                        },
                    };

                    event!(
                        Level::DEBUG,
                        "rt_attr {} {}",
                        ifa_header.rta_len,
                        ifa_header.rta_type
                    );

                    if usize::from(ifa_header.rta_len) < size_of::<rtattr>() {
                        event!(Level::DEBUG, "Invalid `rta_len`. skipping remainder.");
                        break;
                    }

                    if ifa_header.rta_type == IFA_LABEL {
                        // unused, original codebase extracted
                        // the labels in here for ipv4, but ipv6 requires another way
                        // we do both the ipv6 way
                    } else if ifa_header.rta_type == IFA_LOCAL
                        && i32::from(ifaddr_message.ifa_family) == AF_INET
                    {
                        let (ipv4_in_network_order, _suffix) =
                            <[u8; 4]>::ref_from_prefix(&buffer[i + size_of::<rtattr>()..]).unwrap();

                        addr = Some(
                            Ipv4Addr::from_bits(u32::from_be_bytes(*ipv4_in_network_order)).into(),
                        );
                    } else if ifa_header.rta_type == IFA_ADDRESS
                        && i32::from(ifaddr_message.ifa_family) == AF_INET6
                    {
                        let (ipv6_in_network_order, _suffix) =
                            <[u8; 16]>::ref_from_prefix(&buffer[i + size_of::<rtattr>()..])
                                .unwrap();

                        addr = Some(
                            Ipv6Addr::from_bits(u128::from_be_bytes(*ipv6_in_network_order)).into(),
                        );
                    } else if ifa_header.rta_type == IFA_FLAGS {

                        // https://github.com/torvalds/linux/blob/febbc555cf0fff895546ddb8ba2c9a523692fb55/include/uapi/linux/if_addr.h#L35
                        // unused
                        // original:
                        // _, ifa_flags = struct.unpack_from('HI', buf, i)
                    } else {
                        // ...
                    }

                    i += align_to(usize::from(ifa_header.rta_len), ffi::RTA_ALIGNTO);
                }

                let Some(addr) = addr else {
                    event!(Level::DEBUG, "no address in RTM message");
                    offset += align_to(length, align_of::<nlmsghdr>());
                    continue;
                };

                let command = if message.nlmsg_type == RTM_NEWADDR {
                    Command::NewAddress {
                        address: addr,
                        scope: ifaddr_message.ifa_scope,
                        index: ifaddr_message.ifa_index,
                    }
                } else if message.nlmsg_type == RTM_DELADDR {
                    Command::DeleteAddress {
                        address: addr,
                        scope: ifaddr_message.ifa_scope,
                        index: ifaddr_message.ifa_index,
                    }
                } else {
                    // unreachable because we checked baove
                    unreachable!()
                };

                if let Err(err) = self.channel.send(command).await {
                    event!(Level::ERROR, ?err, "Failed to announce command");
                }

                offset += align_to(length, align_of::<nlmsghdr>());
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
