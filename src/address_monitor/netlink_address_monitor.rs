use std::mem::MaybeUninit;
use std::net::IpAddr;

use color_eyre::eyre;
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

use crate::config::Config;
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
        let address_message = {
            let mut address_message = AddressMessage::default();

            address_message.header.family = netlink_packet_route::AddressFamily::Packet;

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

        socket2::SockRef::from(&self.socket).send_to(&buffer, &socket_addr)?;

        Ok(())
    }

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

    #[expect(unused, reason = "WIP")]
    fn cleanup() {
        // self.aio_loop.remove_reader(self.socket.fileno())
        // self.socket.close()
        // super().cleanup()
    }
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
                Ok(msg) => msg,
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
                    break Ok(());
                } else {
                    event!(Level::ERROR, command = ?error.0, "Failed to announce command");
                }
            }
        }

        message_offset += message.header.length as usize;

        if message_offset == buffer.len() || message.header.length == 0 {
            break Ok(());
        }
    }
}

fn parse_address_message(address_message: &AddressMessage) -> Option<(IpAddr, AddressScope, u32)> {
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
        addr,
        address_message.header.scope,
        address_message.header.index,
    ))
}
