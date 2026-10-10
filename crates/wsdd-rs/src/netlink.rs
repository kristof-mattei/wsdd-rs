use shared::netlink::{nlmsghdr, rtattr};
use zerocopy::FromBytes as _;

use crate::utils::{u16_to_usize, u32_to_usize};

const NLMSG_ALIGNTO: usize = 4;

/// Larger than `align_of::<rtattr>()`, which is 2.
const RTA_ALIGNTO: usize = 4;

/// Walks the netlink messages in `buffer`, yielding each header with its payload.
pub fn messages(mut buffer: &[u8]) -> impl Iterator<Item = (&nlmsghdr, &[u8])> {
    std::iter::from_fn(move || {
        let (nlh, _) = nlmsghdr::ref_from_prefix(buffer).ok()?;

        let message_len = u32_to_usize(nlh.nlmsg_len);

        let payload = &buffer[size_of::<nlmsghdr>()..message_len];

        buffer = &buffer[message_len.next_multiple_of(NLMSG_ALIGNTO)..];

        Some((nlh, payload))
    })
}

/// Walks the `rtattr` entries in `buffer`, yielding each header with its payload.
pub fn attributes(mut buffer: &[u8]) -> impl Iterator<Item = (&rtattr, &[u8])> {
    std::iter::from_fn(move || {
        let (rta, _) = rtattr::ref_from_prefix(buffer).ok()?;

        let attribute_len = u16_to_usize(rta.rta_len);

        let payload = &buffer[size_of::<rtattr>()..attribute_len];

        buffer = &buffer[attribute_len.next_multiple_of(RTA_ALIGNTO)..];

        Some((rta, payload))
    })
}
