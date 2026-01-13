use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use color_eyre::eyre;
use ipnet::IpNet;
use libc::{
    AF_INET, AF_INET6, AF_UNSPEC, IFA_ADDRESS, IFA_F_DADFAILED, IFA_F_DEPRECATED,
    IFA_F_HOMEADDRESS, IFA_F_TENTATIVE, IFA_FLAGS, IFA_LABEL, IFA_LOCAL, NETLINK_ROUTE, NLM_F_DUMP,
    NLM_F_REQUEST, RTM_DELADDR, RTM_GETADDR, RTM_NEWADDR, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR,
    RTMGRP_LINK, getpid,
};
use socket2::SockAddrStorage;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use wsdd_rs::define_typed_size;
use zerocopy::IntoBytes as _;

use crate::config::{BindTo, Config};
use crate::ffi::{
    IFA_PAYLOAD, IFA_RTA, NLMSG_DATA, NLMSG_NEXT, NLMSG_OK, RTA_DATA, RTA_NEXT, RTA_OK, SendPtr,
    ifaddrmsg, netlink_req, nlmsghdr, rta_type_to_label,
};
use crate::kernel_buffer::KernelBuffer;
use crate::network_handler::Command;
use crate::utils::task::spawn_with_name;

define_typed_size!(SIZE_OF_SOCKADDR_NL, u32, libc::sockaddr_nl);

pub struct NetlinkAddressMonitor {
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
    socket: Arc<tokio::net::UdpSocket>,
    start_handler: tokio::task::JoinHandle<()>,
}

impl NetlinkAddressMonitor {
    /// Implementation for Netlink sockets, i.e. Linux
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
        // we originally had this on the stack (array) but tokio then moves the whole task to the heap because of size

        // we don't need to zero out the buffer between runs as `recv_buf` starts at 0 and returns `bytes_read`
        // sine we only read that portion we don't need to worry about the leftovers
        // Notice the buffer is u32 because all of our structs written here by the kernel
        // are aligned to 4 bytes
        // Notice the buffer is u32 because all of our structs written here by the kernel
        // are aligned to 4 bytes

        let mut buffer = KernelBuffer::<4096>::new_boxed();

        loop {
            let bytes_read = {
                let mut buffer_byte_cursor = &mut buffer;

                tokio::select! {
                    () = self.cancellation_token.cancelled() => {
                        break;
                    },
                    result = self.socket.recv_buf(&mut buffer_byte_cursor) => {
                        result?
                    },
                }
            };

            event!(
                Level::DEBUG,
                length = bytes_read,
                "netlink message received"
            );

            // SAFETY: we are only initializing the parts of the buffer `recv_buf_from` has written to
            let buffer = unsafe { &*(&raw const buffer[..bytes_read] as *const [u8]) };

            if let Err(error) =
                parse_netlink_response(buffer, &self.cancellation_token, &self.command_tx).await
            {
                event!(
                    Level::ERROR,
                    ?error,
                    "Error parsing response as a netlink response"
                );
            }
        }

        Ok(())
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

    // SAFETY: `getpid` always succeeds
    let pid = unsafe { getpid() }.cast_unsigned();

    let request = netlink_req {
        nh: nlmsghdr {
            nlmsg_len: size_of::<netlink_req>().try_into().unwrap(),
            nlmsg_type: RTM_GETADDR,
            nlmsg_flags: u16::try_from(NLM_F_REQUEST | NLM_F_DUMP).unwrap(),
            nlmsg_seq: 1,
            nlmsg_pid: pid,
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
    let mut remaining_bytes = buffer.len();

    #[expect(
        clippy::cast_ptr_alignment,
        reason = "The data we're parsing is 4-byte aligned"
    )]
    let mut raw_nlh = SendPtr::new(buffer, buffer.as_ptr().cast::<u8>().cast::<nlmsghdr>());

    while NLMSG_OK(raw_nlh.get(), remaining_bytes) {
        // SAFETY: `NLMSG_OK`
        let nlh = unsafe { &*raw_nlh.get() };

        let command = if nlh.nlmsg_type == RTM_NEWADDR {
            parse_address_message(nlh).map(|(ip_net, scope, index)| Command::NewAddress {
                address: ip_net,
                scope,
                index,
            })
        } else if nlh.nlmsg_type == RTM_DELADDR {
            parse_address_message(nlh).map(|(ip_net, scope, index)| Command::DeleteAddress {
                address: ip_net,
                scope,
                index,
            })
        } else {
            event!(Level::DEBUG, "invalid rtm_message type {}", nlh.nlmsg_type);

            None
        };

        if let Some(command) = command {
            if let Err(error) = command_tx.send(command).await {
                if cancellation_token.is_cancelled() {
                    event!(Level::INFO, command = ?error.0, "Could not announce command due to shutting down");
                } else {
                    event!(Level::ERROR, command = ?error.0, "Failed to announce command");
                }
            }
        }

        raw_nlh = SendPtr::new(buffer, NLMSG_NEXT(raw_nlh.get(), &mut remaining_bytes));
    }

    Ok(())
}

fn parse_address_message(raw_nlh: *const nlmsghdr) -> Option<(IpNet, u8, u32)> {
    let raw_ifa = NLMSG_DATA::<ifaddrmsg>(raw_nlh);

    // SAFETY:`nlh` is valid, and has an `ifa`
    let ifa = unsafe { &*raw_ifa };

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

    let mut addr: Option<IpAddr> = None;

    let mut raw_rta = IFA_RTA(raw_ifa);
    let mut ifa_payload = IFA_PAYLOAD(raw_nlh);

    #[expect(clippy::big_endian_bytes, reason = "We're reading network data")]
    while RTA_OK(raw_rta, ifa_payload) {
        // SAFETY: See `RTA_OK`
        let rta = unsafe { &*raw_rta };

        event!(
            Level::DEBUG,
            "rt_attr type: {} {} ({})",
            rta.rta_len,
            rta.rta_type,
            rta_type_to_label(rta.rta_type).unwrap_or("Unknown type")
        );

        if rta.rta_type == IFA_ADDRESS && i32::from(ifa.ifa_family) == AF_INET6 {
            // SAFETY: Combination of `rta.rta_type` and `ifa.ifa_family`
            let ipv6_in_network_order = unsafe { &*RTA_DATA::<[u8; 16]>(raw_rta) };

            addr = Some(Ipv6Addr::from_bits(u128::from_be_bytes(*ipv6_in_network_order)).into());
        } else if rta.rta_type == IFA_LOCAL && i32::from(ifa.ifa_family) == AF_INET {
            // IFA_ADDRESS (`AddressAttribute::Address`) is prefix address, rather than local interface address.
            // It makes no difference for normally configured broadcast interfaces,
            // but for point-to-point IFA_ADDRESS (`AddressAttribute::Address`) is DESTINATION address,
            // local address is supplied in IFA_LOCAL (`AddressAttribute::Local`) attribute.
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

            // ....
        }

        raw_rta = RTA_NEXT(raw_rta, &mut ifa_payload);
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
    use pretty_assertions::assert_eq;

    use crate::address_monitor::netlink_address_monitor::SIZE_OF_SOCKADDR_NL;

    #[test]
    fn size_of_sockaddr_nl() {
        assert_eq!(size_of::<libc::sockaddr_nl>(), SIZE_OF_SOCKADDR_NL as usize);
    }
}
