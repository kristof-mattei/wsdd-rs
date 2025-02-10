use std::{io::Error, mem::MaybeUninit, net::UdpSocket, os::fd::FromRawFd, sync::Arc};

use bytemuck::NoUninit;
use libc::{
    NETLINK_ROUTE, NLM_F_DUMP, NLM_F_REQUEST, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK,
    RTM_GETADDR,
};
use socket2::Socket;
use zerocopy::{Immutable, IntoBytes};

use crate::{config::Config, ffi};

pub struct NetlinkAddressMonitor {
    socket: socket2::Socket,
}

// libc doesn't have this... Why not?
pub const AF_PACKET: i32 = 17;

const RTM_NEWADDR: u32 = 20;
const RTM_DELADDR: u32 = 21;

impl NetlinkAddressMonitor {
    //     """
    //     Implementation of the AddressMonitor for Netlink sockets, i.e. Linux
    //     """
    pub fn new(config: Arc<Config>) -> Result<Self, std::io::Error> {
        let mut rtm_groups = RTMGRP_LINK;

        if !config.ipv4only {
            rtm_groups |= RTMGRP_IPV6_IFADDR;
        }

        if !config.ipv6only {
            rtm_groups |= RTMGRP_IPV4_IFADDR;
        }

        let raw_socket_fd =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, NETLINK_ROUTE) };

        if raw_socket_fd < 0 {
            return Err(Error::last_os_error());
        }

        let socket = unsafe { socket2::Socket::from_raw_fd(raw_socket_fd) };

        #[expect(clippy::cast_possible_truncation)]
        let ((), socket_addr) = unsafe {
            socket2::SockAddr::try_init(|addr_storage, len| {
                let sockaddr_nl: *mut libc::sockaddr_nl = addr_storage.cast();

                (*sockaddr_nl).nl_family = libc::AF_NETLINK.try_into().unwrap();
                (*sockaddr_nl).nl_groups = rtm_groups.try_into().unwrap();

                *len = std::mem::size_of_val(&addr_storage) as libc::socklen_t;

                Ok(())
            })
        }?;

        socket.bind(&socket_addr)?;

        // TODO
        // self.aio_loop.add_reader(self.socket.fileno(), self.handle_change)

        Ok(Self { socket })
    }

    //     def do_enumerate(self) -> None:
    fn do_enumerate(&self) -> Result<(), std::io::Error> {
        //         kernel = (0, 0)
        //         # Append an unsigned byte to the header for the request.

        #[derive(IntoBytes, Immutable)]
        pub struct Request {
            pub nh: ffi::nlmsghdr,
            pub ifa: ffi::ifaddrmsg,
        }

        let request = Request {
            nh: ffi::nlmsghdr {
                nlmsg_len: size_of::<Request>().try_into().unwrap(),
                nlmsg_type: RTM_GETADDR as u16,
                nlmsg_flags: (NLM_F_REQUEST | NLM_F_DUMP) as u16,
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

        #[expect(clippy::cast_possible_truncation)]
        let ((), socket_addr) = unsafe {
            socket2::SockAddr::try_init(|addr_storage, len| {
                let sockaddr_nl: *mut libc::sockaddr_nl = addr_storage.cast();

                (*sockaddr_nl).nl_family = libc::AF_NETLINK.try_into().unwrap();
                (*sockaddr_nl).nl_pid = 0;
                (*sockaddr_nl).nl_groups = 0;

                *len = std::mem::size_of_val(&addr_storage) as libc::socklen_t;

                Ok(())
            })
        }?;

        let x = UdpSocket::bind("addr")?;

        self.socket
            .send_to(request.as_bytes(), &socket_addr.into())
            .map(|_| ())

        //         req = struct.pack(NLM_HDR_DEF + 'B', self.NLM_HDR_LEN + 1, self.RTM_GETADDR, NLM_F_REQUEST | NLM_F_DUMP, 1, 0,
        //                           socket.AF_PACKET)
        //         self.socket.sendto(req, kernel)
    }

    //     def handle_change(self) -> None:
    fn handle_change(&self) {
        let mut buffer = [{ MaybeUninit::uninit() }; 4096];
        let res = self.socket.recv(&mut buffer);
        //         buf, src = self.socket.recvfrom(4096)
        //         logger.debug('netlink message with {} bytes'.format(len(buf)))

        //         offset = 0
        //         while offset < len(buf):
        //             h_len, h_type, _, _, _ = struct.unpack_from(NLM_HDR_DEF, buf, offset)
        //             offset += self.NLM_HDR_LEN

        //             msg_len = h_len - self.NLM_HDR_LEN
        //             if msg_len < 0:
        //                 break

        //             if h_type != self.RTM_NEWADDR and h_type != self.RTM_DELADDR:
        //                 logger.debug('invalid rtm_message type {}'.format(h_type))
        //                 offset += align_to(msg_len, NLM_HDR_ALIGNTO)
        //                 continue

        //             # decode ifaddrmsg as in if_addr.h
        //             ifa_family, _, ifa_flags, ifa_scope, ifa_idx = struct.unpack_from(IFADDR_MSG_DEF, buf, offset)
        //             if ((ifa_flags & IFA_F_DADFAILED) or (ifa_flags & IFA_F_HOMEADDRESS) or (ifa_flags & IFA_F_DEPRECATED) or
        //                 (ifa_flags & IFA_F_TENTATIVE)):
        //                 logger.debug('ignore address with invalid state {}'.format(hex(ifa_flags)))
        //                 offset += align_to(msg_len, NLM_HDR_ALIGNTO)
        //                 continue

        //             logger.debug('RTM new/del addr family: {} flags: {} scope: {} idx: {}'.format(
        //                 ifa_family, ifa_flags, ifa_scope, ifa_idx))
        //             addr = None
        //             i = offset + IFA_MSG_LEN
        //             while i - offset < msg_len:
        //                 attr_len, attr_type = struct.unpack_from('HH', buf, i)
        //                 logger.debug('rt_attr {} {}'.format(attr_len, attr_type))

        //                 if attr_len < RTA_LEN:
        //                     logger.debug('invalid rtm_attr_len. skipping remainder')
        //                     break

        //                 if attr_type == IFA_LABEL:
        //                     name, = struct.unpack_from(str(attr_len - 4 - 1) + 's', buf, i + 4)
        //                     self.add_interface(NetworkInterface(name.decode(), ifa_scope, ifa_idx))
        //                 elif attr_type == IFA_LOCAL and ifa_family == socket.AF_INET:
        //                     addr = buf[i + 4:i + 4 + 4]
        //                 elif attr_type == IFA_ADDRESS and ifa_family == socket.AF_INET6:
        //                     addr = buf[i + 4:i + 4 + 16]
        //                 elif attr_type == IFA_FLAGS:
        //                     _, ifa_flags = struct.unpack_from('HI', buf, i)
        //                 i += align_to(attr_len, RTA_ALIGNTO)

        //             if addr is None:
        //                 logger.debug('no address in RTM message')
        //                 offset += align_to(msg_len, NLM_HDR_ALIGNTO)
        //                 continue

        //             # In case of IPv6 only addresses, there appears to be no IFA_LABEL
        //             # message. Therefore, the name is requested by other means (#94)
        //             if ifa_idx not in self.interfaces:
        //                 try:
        //                     logger.debug('unknown interface name for idx {}. resolving manually'.format(ifa_idx))
        //                     if_name = socket.if_indextoname(ifa_idx)
        //                     self.add_interface(NetworkInterface(if_name, ifa_scope, ifa_idx))
        //                 except OSError:
        //                     logger.exception('interface detection failed')
        //                     # accept this exception (which should not occur)
        //                     pass

        //             # In case really strange things happen and we could not find out the
        //             # interface name for the returned ifa_idx, we... log a message.
        //             if ifa_idx in self.interfaces:
        //                 address = NetworkAddress(ifa_family, addr, self.interfaces[ifa_idx])
        //                 if h_type == self.RTM_NEWADDR:
        //                     self.handle_new_address(address)
        //                 elif h_type == self.RTM_DELADDR:
        //                     self.handle_deleted_address(address)
        //             else:
        //                 logger.debug('unknown interface index: {}'.format(ifa_idx))

        //             offset += align_to(msg_len, NLM_HDR_ALIGNTO)
    }

    //     def cleanup(self) -> None:
    //         self.aio_loop.remove_reader(self.socket.fileno())
    //         self.socket.close()
    //         super().cleanup()
}
