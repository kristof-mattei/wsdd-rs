use std::io;
use std::mem::MaybeUninit;
use std::net::IpAddr;

use bytes::BufMut;
use libc::{
    AF_INET, AF_INET6, AF_UNSPEC, IFA_ADDRESS, IFA_LOCAL, MSG_PEEK, MSG_TRUNC, NLM_F_DUMP_INTR,
    NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, RTM_DELADDR, RTM_DELLINK, RTM_NEWADDR, RTM_NEWLINK,
};
use shared::netlink::{ifaddrmsg, ifinfomsg, nlmsgerr, nlmsghdr, rtattr};
use tokio::io::Interest;
use tracing::{Level, event};
use zerocopy::FromBytes as _;

use crate::ffi::getpagesize;
use crate::utils::{u16_to_usize, u32_to_usize};

const NLMSG_ALIGNTO: usize = 4;

/// Larger than `align_of::<rtattr>()`, which is 2.
pub const RTA_ALIGNTO: usize = 4;

pub trait RecvBuf<B: BufMut> {
    /// Returns the full length of the next datagram and leaves it queued.
    async fn peek_len(&self) -> io::Result<usize>;

    async fn recv_buf(&self, buf: &mut B) -> io::Result<usize>;

    fn try_recv_buf(&self, buf: &mut B) -> io::Result<usize>;
}

impl<B: BufMut> RecvBuf<B> for &tokio::net::UdpSocket {
    async fn peek_len(&self) -> io::Result<usize> {
        self.async_io(Interest::READABLE, || {
            socket2::SockRef::from(*self).recv_with_flags(&mut [], MSG_PEEK | MSG_TRUNC)
        })
        .await
    }

    async fn recv_buf(&self, buf: &mut B) -> io::Result<usize> {
        tokio::net::UdpSocket::recv_buf::<B>(self, buf).await
    }

    fn try_recv_buf(&self, buf: &mut B) -> io::Result<usize> {
        tokio::net::UdpSocket::try_recv_buf::<B>(self, buf)
    }
}

pub struct ReceiveBuffer(Box<[MaybeUninit<u8>]>);

impl ReceiveBuffer {
    pub fn new() -> Self {
        // Can't have smaller than this on x86
        const MIN_PAGE_SIZE: usize = 4096;
        // `NLMSG_GOODSIZE` uses at most 8192 bytes, whatever the page size
        // https://github.com/torvalds/linux/blob/24d479d26b25bce5faea3ddd9fa8f3a6c3129ea7/include/linux/netlink.h#L272-L276
        const MAX_PAGE_SIZE: usize = 8192;

        // the kernel sizes most datagrams to `NLMSG_GOODSIZE`
        let page_size = getpagesize().clamp(MIN_PAGE_SIZE, MAX_PAGE_SIZE);

        Self(Box::new_uninit_slice(page_size))
    }

    pub async fn receive<R>(&mut self, socket: &R) -> io::Result<Messages<'_>>
    where
        R: for<'a> RecvBuf<&'a mut [MaybeUninit<u8>]>,
    {
        let length = socket.peek_len().await?;

        // a link notification is sized to its message, which can exceed `NLMSG_GOODSIZE`
        if length > self.0.len() {
            self.0 = Box::new_uninit_slice(length);
        }

        let bytes_read = {
            let mut cursor = &mut *self.0;

            socket.recv_buf(&mut cursor).await?
        };

        event!(
            Level::TRACE,
            length = bytes_read,
            "netlink message received"
        );

        // SAFETY: `recv_buf` initialized the first `bytes_read` bytes
        let received = unsafe { self.0[..bytes_read].assume_init_ref() };

        Ok(Messages(received))
    }

    pub fn discard_queued<R>(&mut self, socket: &R) -> io::Result<()>
    where
        R: for<'a> RecvBuf<&'a mut [MaybeUninit<u8>]>,
    {
        loop {
            let mut cursor = &mut *self.0;

            match socket.try_recv_buf(&mut cursor) {
                Ok(_) => {},
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Ok(());
                },
                Err(error) if error.raw_os_error() == Some(libc::ENOBUFS) => {},
                Err(error) => {
                    return Err(error);
                },
            }
        }
    }
}

pub struct Messages<'a>(&'a [u8]);

pub struct Header {
    pub dump_interrupted: bool,
}

impl<'a> Iterator for Messages<'a> {
    type Item = (Header, Message<'a>);

    fn next(&mut self) -> Option<Self::Item> {
        let (header, _) = nlmsghdr::ref_from_prefix(self.0).ok()?;

        let message_len = u32_to_usize(header.nlmsg_len.get());

        let payload = &self.0[size_of::<nlmsghdr>()..message_len];

        self.0 = &self.0[message_len.next_multiple_of(NLMSG_ALIGNTO)..];

        let message_header = Header {
            dump_interrupted: i32::from(header.nlmsg_flags.get()) & NLM_F_DUMP_INTR != 0,
        };

        Some((
            message_header,
            Message::decode(header.nlmsg_type.get(), payload),
        ))
    }
}

pub enum Message<'a> {
    Done,
    /// An `NLMSG_ERROR` with error code 0.
    Ack,
    Error(io::Error),
    Noop,
    NewAddress(&'a ifaddrmsg, Attributes<'a>),
    DeleteAddress(&'a ifaddrmsg, Attributes<'a>),
    NonIpAddress(u8),
    NewLink(&'a ifinfomsg),
    DeleteLink(&'a ifinfomsg),
    /// A link message about the device's role in a protocol, such as `AF_BRIDGE` for the device as a bridge port.
    ProtocolLink(u8),
    Other(u16),
}

impl<'a> Message<'a> {
    fn decode(message_type: u16, payload: &'a [u8]) -> Self {
        match message_type {
            RTM_NEWADDR => {
                let (ifa, rest) = address_header(payload);

                match IpFamily::from_family(ifa.ifa_family) {
                    Some(family) => Self::NewAddress(
                        ifa,
                        Attributes {
                            family,
                            buffer: rest,
                        },
                    ),
                    None => Self::NonIpAddress(ifa.ifa_family),
                }
            },
            RTM_DELADDR => {
                let (ifa, rest) = address_header(payload);

                match IpFamily::from_family(ifa.ifa_family) {
                    Some(family) => Self::DeleteAddress(
                        ifa,
                        Attributes {
                            family,
                            buffer: rest,
                        },
                    ),
                    None => Self::NonIpAddress(ifa.ifa_family),
                }
            },
            RTM_NEWLINK => {
                let ifi = link_header(payload);

                if i32::from(ifi.ifi_family) == AF_UNSPEC {
                    Self::NewLink(ifi)
                } else {
                    Self::ProtocolLink(ifi.ifi_family)
                }
            },
            RTM_DELLINK => {
                let ifi = link_header(payload);

                if i32::from(ifi.ifi_family) == AF_UNSPEC {
                    Self::DeleteLink(ifi)
                } else {
                    Self::ProtocolLink(ifi.ifi_family)
                }
            },
            _ => match i32::from(message_type) {
                NLMSG_DONE => Self::Done,
                NLMSG_ERROR => {
                    let (error, _) = nlmsgerr::ref_from_prefix(payload).expect(
                        "`NLMSG_ERROR` must start with an `nlmsgerr`, as this is kernel data",
                    );

                    let code = error.error.get();

                    if code == 0 {
                        Self::Ack
                    } else {
                        Self::Error(io::Error::from_raw_os_error(code.wrapping_neg()))
                    }
                },
                NLMSG_NOOP => Self::Noop,
                _ => Self::Other(message_type),
            },
        }
    }
}

fn link_header(payload: &[u8]) -> &ifinfomsg {
    let (ifi, _) = ifinfomsg::ref_from_prefix(payload)
        .expect("a link message must start with an `ifinfomsg`, as this is kernel data");

    ifi
}

fn address_header(payload: &[u8]) -> (&ifaddrmsg, &[u8]) {
    ifaddrmsg::ref_from_prefix(payload)
        .expect("an address message must start with an `ifaddrmsg`, as this is kernel data")
}

#[derive(Clone, Copy)]
enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn from_family(family: u8) -> Option<Self> {
        match i32::from(family) {
            AF_INET => Some(Self::V4),
            AF_INET6 => Some(Self::V6),
            _ => None,
        }
    }
}

pub struct Attributes<'a> {
    family: IpFamily,
    buffer: &'a [u8],
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Attribute<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (rta, _) = rtattr::ref_from_prefix(self.buffer).ok()?;

        let attribute_len = u16_to_usize(rta.rta_len.get());

        let value = &self.buffer[size_of::<rtattr>()..attribute_len];

        self.buffer = &self.buffer[attribute_len.next_multiple_of(RTA_ALIGNTO)..];

        event!(
            Level::TRACE,
            rta_len = rta.rta_len.get(),
            rta_type = rta.rta_type.get(),
            label = rta.label(),
            "attribute"
        );

        let attribute = match rta.rta_type.get() {
            IFA_ADDRESS => Attribute::Address(AddressValue {
                family: self.family,
                value,
            }),
            IFA_LOCAL => Attribute::Local(AddressValue {
                family: self.family,
                value,
            }),
            _ => Attribute::Other,
        };

        Some(attribute)
    }
}

pub enum Attribute<'a> {
    Address(AddressValue<'a>),
    Local(AddressValue<'a>),
    Other,
}

pub struct AddressValue<'a> {
    family: IpFamily,
    value: &'a [u8],
}

impl AddressValue<'_> {
    pub fn decode(self) -> IpAddr {
        match self.family {
            IpFamily::V4 => {
                let octets: [u8; 4] = self
                    .value
                    .try_into()
                    .expect("an `AF_INET` address must be 4 bytes, as this is kernel data");

                IpAddr::from(octets)
            },
            IpFamily::V6 => {
                let octets: [u8; 16] = self
                    .value
                    .try_into()
                    .expect("an `AF_INET6` address must be 16 bytes, as this is kernel data");

                IpAddr::from(octets)
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use libc::{AF_BRIDGE, EINVAL, IFF_UP, RTM_DELLINK};
    use pretty_assertions::assert_eq;

    use crate::rtnetlink::{Message, Messages};
    use crate::test_utils::netlink::{
        done_message, error_message, interrupted_message, link_message,
    };

    #[test]
    fn error_code_zero_decodes_as_ack() {
        let bytes = error_message(0);

        let mut messages = Messages(&bytes);

        assert!(matches!(messages.next(), Some((_, Message::Ack))));
    }

    #[test]
    fn negative_errno_decodes_as_error() {
        let bytes = error_message(-EINVAL);

        let mut messages = Messages(&bytes);

        let Some((_, Message::Error(error))) = messages.next() else {
            panic!("expected `Message::Error`");
        };

        assert_eq!(error.raw_os_error(), Some(EINVAL));
    }

    #[test]
    fn header_reports_an_interrupted_dump() {
        let mut bytes = done_message();

        bytes.extend(interrupted_message(&done_message()));

        let headers = Messages(&bytes)
            .map(|(header, _)| header.dump_interrupted)
            .collect::<Vec<_>>();

        assert_eq!(headers, [false, true]);
    }

    #[test]
    fn bridge_port_link_decodes_as_protocol_link() {
        let bytes = link_message(RTM_DELLINK, AF_BRIDGE, 3, IFF_UP.cast_unsigned());

        let mut messages = Messages(&bytes);

        let Some((_, Message::ProtocolLink(family))) = messages.next() else {
            panic!("expected `Message::ProtocolLink`");
        };

        assert_eq!(i32::from(family), AF_BRIDGE);
    }
}
