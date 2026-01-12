use std::mem::MaybeUninit;
use std::sync::Arc;

use color_eyre::eyre;
use ipnet::IpNet;
use libc::{NETLINK_ROUTE, RTMGRP_IPV4_IFADDR, RTMGRP_IPV6_IFADDR, RTMGRP_LINK};
use netlink_packet_core::{
    Emitable as _, NLM_F_DUMP, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
    Nla as _,
};
use netlink_packet_route::address::{AddressHeaderFlags, AddressMessage, AddressScope};
use netlink_packet_route::{RouteNetlinkMessage, address};
use socket2::SockAddrStorage;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use wsdd_rs::define_typed_size;

use crate::config::{BindTo, Config};
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
    let address_message = {
        let mut address_message = AddressMessage::default();

        match config.bind_to {
            BindTo::IPv4 => {
                address_message.header.family = netlink_packet_route::AddressFamily::Inet;
            },
            BindTo::IPv6 => {
                address_message.header.family = netlink_packet_route::AddressFamily::Inet6;
            },
            BindTo::DualStack => {
                address_message.header.family = netlink_packet_route::AddressFamily::Unspec;
            },
        }

        address_message
    };

    let packet = {
        let mut packet = NetlinkMessage::new(
            NetlinkHeader::default(),
            NetlinkPayload::from(RouteNetlinkMessage::GetAddress(address_message)),
        );
        packet.header.flags = NLM_F_DUMP | NLM_F_REQUEST;
        packet.header.sequence_number = 1;
        packet.finalize();

        packet
    };

    let mut buffer = vec![0; packet.header.length as usize];

    packet.serialize(&mut buffer);

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

    socket2::SockRef::from(&socket).send_to(&buffer, &socket_addr)?;

    Ok(())
}

async fn parse_netlink_response(
    buffer: &[u8],
    cancellation_token: &CancellationToken,
    command_tx: &Sender<Command>,
) -> Result<(), eyre::Report> {
    let mut message_offset = 0;

    loop {
        let message: NetlinkMessage<RouteNetlinkMessage> =
            match NetlinkMessage::deserialize(&buffer[message_offset..]) {
                Ok(message) => message,
                Err(error) => {
                    event!(
                        Level::ERROR,
                        ?error,
                        offset = message_offset,
                        "Failed to deserialize netlink message, abandoning the rest in the buffer"
                    );

                    break Err(eyre::Report::msg("Invalid netlink message"));
                },
            };

        let command = match message.payload {
            NetlinkPayload::Done(_) => {
                break Ok(());
            },
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::NewAddress(new_address_message)) => {
                parse_address_message(&new_address_message).map(|(new_address, scope, index)| {
                    Command::NewAddress {
                        address: new_address,
                        scope: scope.into(),
                        index,
                    }
                })
            },
            NetlinkPayload::InnerMessage(RouteNetlinkMessage::DelAddress(del_address_message)) => {
                parse_address_message(&del_address_message).map(|(del_address, scope, index)| {
                    Command::DeleteAddress {
                        address: del_address,
                        scope: scope.into(),
                        index,
                    }
                })
            },
            NetlinkPayload::Error(_)
            | NetlinkPayload::Noop
            | NetlinkPayload::Overrun(_)
            | NetlinkPayload::InnerMessage(_)
            | _ => {
                event!(
                    Level::DEBUG,
                    "invalid rtm_message type {}",
                    message.payload.message_type()
                );

                None
            },
        };

        if let Some(command) = command {
            if let Err(error) = command_tx.send(command).await {
                if cancellation_token.is_cancelled() {
                    event!(Level::INFO, command = ?error.0, "Could not announce command due to shutting down");
                } else {
                    event!(Level::ERROR, command = ?error.0, "Failed to announce command");
                }

                break Err(eyre::Report::msg(
                    "Command receiver gone, nothing left to do but abandon buffer",
                ));
            }
        }

        message_offset += message.header.length as usize;

        if message_offset == buffer.len() || message.header.length == 0 {
            break Ok(());
        }
    }
}

fn parse_address_message(address_message: &AddressMessage) -> Option<(IpNet, AddressScope, u32)> {
    let header = &address_message.header;

    if header.flags.contains(AddressHeaderFlags::Dadfailed)
        || header.flags.contains(AddressHeaderFlags::Homeaddress)
        || header.flags.contains(AddressHeaderFlags::Deprecated)
        || header.flags.contains(AddressHeaderFlags::Tentative)
    {
        event!(
            Level::DEBUG,
            "ignore address with invalid state {:#x}",
            header.flags
        );

        // skip this message and its data
        return None;
    }

    event!(
        Level::DEBUG,
        "RTM new/del addr family: {:?} flags: {:?} scope: {:?} idx: {}",
        header.family,
        header.flags,
        header.scope,
        header.index
    );

    let mut addr = None;

    for rta in &address_message.attributes {
        event!(
            Level::DEBUG,
            "rt_attr type: {} {}",
            rta.buffer_len(),
            rta.kind(),
        );

        #[expect(clippy::match_same_arms, reason = "Comments have more of the story")]
        match *rta {
            address::AddressAttribute::Address(ip_addr) => {
                if ip_addr.is_ipv6() {
                    addr = Some(ip_addr);
                } else {
                    // event!(Level::ERROR, ?ip_addr, "IFA_ADDRESS");
                }
            },
            address::AddressAttribute::Local(ip_addr) => {
                // IFA_ADDRESS (`AddressAttribute::Address`) is prefix address, rather than local interface address.
                // It makes no difference for normally configured broadcast interfaces,
                // but for point-to-point IFA_ADDRESS (`AddressAttribute::Address`) is DESTINATION address,
                // local address is supplied in IFA_LOCAL (`AddressAttribute::Local`) attribute.
                // https://github.com/torvalds/linux/blob/e9a6fb0bcdd7609be6969112f3fbfcce3b1d4a7c/include/uapi/linux/if_addr.h#L16-L25

                if ip_addr.is_ipv4() {
                    addr = Some(ip_addr);
                } else {
                    // event!(Level::ERROR, ?ip_addr, "IFA_LOCAL");
                }
            },
            address::AddressAttribute::Label(_) => {
                // unused, original codebase extracted
                // the labels in here for ipv4, but ipv6 requires another way
                // we do both the ipv6 way
            },
            address::AddressAttribute::Flags(_) => {
                // https://github.com/torvalds/linux/blob/febbc555cf0fff895546ddb8ba2c9a523692fb55/include/uapi/linux/if_addr.h#L35
                // unused
                // original:
                // _, ifa_flags = struct.unpack_from('HI', buf, i)
            },
            address::AddressAttribute::Broadcast(_)
            | address::AddressAttribute::Anycast(_)
            | address::AddressAttribute::CacheInfo(_)
            | address::AddressAttribute::Multicast(_)
            | address::AddressAttribute::Other(_)
            | _ => {
                // ...
            },
        }
    }

    let Some(addr) = addr else {
        event!(Level::DEBUG, "no address in RTM message");

        return None;
    };

    Some((
        IpNet::new(addr, address_message.header.prefix_len)
            .expect("prefix_len must be valid for this address"),
        address_message.header.scope,
        address_message.header.index,
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
