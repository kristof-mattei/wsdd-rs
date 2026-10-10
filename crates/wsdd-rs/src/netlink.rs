use std::io;
use std::mem::MaybeUninit;
use std::net::IpAddr;

use bytes::BufMut;
use libc::{
    AF_INET, AF_INET6, IFA_ADDRESS, IFA_LOCAL, NLMSG_DONE, NLMSG_ERROR, NLMSG_NOOP, RTM_DELADDR,
    RTM_NEWADDR,
};
use shared::netlink::{ifaddrmsg, nlmsgerr, nlmsghdr, rtattr};
use tracing::{Level, event};
use zerocopy::FromBytes as _;

use crate::ffi::getpagesize;
use crate::kernel_buffer::AlignedBuffer;
use crate::utils::{u16_to_usize, u32_to_usize};

const NLMSG_ALIGNTO: usize = 4;

/// Larger than `align_of::<rtattr>()`, which is 2.
pub const RTA_ALIGNTO: usize = 4;

pub trait RecvBuf<B: BufMut> {
    async fn recv_buf(&self, buf: &mut B) -> io::Result<usize>;
}

impl<B: BufMut> RecvBuf<B> for &tokio::net::UdpSocket {
    async fn recv_buf(&self, buf: &mut B) -> io::Result<usize> {
        tokio::net::UdpSocket::recv_buf::<B>(self, buf).await
    }
}

/// Aligned for `nlmsghdr`, the largest alignment of the structs read from it.
pub struct ReceiveBuffer(AlignedBuffer<{ align_of::<nlmsghdr>() }>);

impl ReceiveBuffer {
    pub fn new() -> Self {
        // Can't have smaller than this on x86
        const MIN_PAGE_SIZE: usize = 4096;
        // Large enough for the kernel's max packet (see `NLMSG_GOODSIZE`)
        // https://github.com/torvalds/linux/blob/24d479d26b25bce5faea3ddd9fa8f3a6c3129ea7/include/linux/netlink.h#L272-L276
        const MAX_PAGE_SIZE: usize = 8192;

        // The kernel itself caps recvmsg sizing at `NLMSG_GOODSIZE = min(PAGE_SIZE, 8192)`,
        // so allocating more than 8192 bytes would never be filled. We mirror that cap here.
        let page_size = getpagesize().clamp(MIN_PAGE_SIZE, MAX_PAGE_SIZE);

        Self(AlignedBuffer::new(page_size))
    }

    pub async fn receive<R>(&mut self, socket: &R) -> io::Result<Messages<'_>>
    where
        R: for<'a> RecvBuf<&'a mut [MaybeUninit<u8>]>,
    {
        let bytes_read = {
            let mut cursor = &mut *self.0;

            socket.recv_buf(&mut cursor).await?
        };

        event!(
            Level::DEBUG,
            length = bytes_read,
            "netlink message received"
        );

        // SAFETY: `recv_buf` initialized the first `bytes_read` bytes
        let received = unsafe { self.0[..bytes_read].assume_init_ref() };

        Ok(Messages(received))
    }
}

pub struct Messages<'a>(&'a [u8]);

impl<'a> Iterator for Messages<'a> {
    type Item = Message<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (header, _) = nlmsghdr::ref_from_prefix(self.0).ok()?;

        let message_len = u32_to_usize(header.nlmsg_len);

        let payload = &self.0[size_of::<nlmsghdr>()..message_len];

        self.0 = &self.0[message_len.next_multiple_of(NLMSG_ALIGNTO)..];

        Some(Message::decode(header.nlmsg_type, payload))
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
    Other(u16),
}

impl<'a> Message<'a> {
    fn decode(message_type: u16, payload: &'a [u8]) -> Self {
        match message_type {
            RTM_NEWADDR => match split_address_message(payload) {
                Ok((ifa, attributes)) => Self::NewAddress(ifa, attributes),
                Err(family) => Self::NonIpAddress(family),
            },
            RTM_DELADDR => match split_address_message(payload) {
                Ok((ifa, attributes)) => Self::DeleteAddress(ifa, attributes),
                Err(family) => Self::NonIpAddress(family),
            },
            _ => match i32::from(message_type) {
                NLMSG_DONE => Self::Done,
                NLMSG_ERROR => {
                    let (error, _) = nlmsgerr::ref_from_prefix(payload).expect(
                        "`NLMSG_ERROR` must start with an `nlmsgerr`, as this is kernel data",
                    );

                    if error.error == 0 {
                        Self::Ack
                    } else {
                        Self::Error(io::Error::from_raw_os_error(error.error.wrapping_neg()))
                    }
                },
                NLMSG_NOOP => Self::Noop,
                _ => Self::Other(message_type),
            },
        }
    }
}

/// Returns the family of a non-IP address message as the error.
fn split_address_message(payload: &[u8]) -> Result<(&ifaddrmsg, Attributes<'_>), u8> {
    let (ifa, rest) = ifaddrmsg::ref_from_prefix(payload)
        .expect("an address message must start with an `ifaddrmsg`, as this is kernel data");

    let family = match i32::from(ifa.ifa_family) {
        AF_INET => IpFamily::V4,
        AF_INET6 => IpFamily::V6,
        _ => return Err(ifa.ifa_family),
    };

    let attributes = Attributes {
        family,
        buffer: rest,
    };

    Ok((ifa, attributes))
}

#[derive(Clone, Copy)]
enum IpFamily {
    V4,
    V6,
}

pub struct Attributes<'a> {
    family: IpFamily,
    buffer: &'a [u8],
}

impl<'a> Iterator for Attributes<'a> {
    type Item = Attribute<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let (rta, _) = rtattr::ref_from_prefix(self.buffer).ok()?;

        let attribute_len = u16_to_usize(rta.rta_len);

        let value = &self.buffer[size_of::<rtattr>()..attribute_len];

        self.buffer = &self.buffer[attribute_len.next_multiple_of(RTA_ALIGNTO)..];

        event!(
            Level::DEBUG,
            "rt_attr type: {} {} ({})",
            rta.rta_len,
            rta.rta_type,
            rta.label().unwrap_or("Unknown type")
        );

        let attribute = match rta.rta_type {
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
