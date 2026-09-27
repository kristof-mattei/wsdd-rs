use shared::netlink::{ifaddrmsg, nlmsghdr, rtattr};

use crate::utils::{u16_to_usize, u32_to_usize};

const SIZE_OF_IFADDRMSG: usize = size_of::<ifaddrmsg>();
const SIZE_OF_RTATTR: usize = size_of::<rtattr>();
const SIZE_OF_NLMSGHDR: usize = size_of::<nlmsghdr>();

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Returns a pointer to the `rtattr` following the `ifaddrmsg` header.
pub const fn IFA_RTA(r: *const ifaddrmsg) -> *const rtattr {
    let offset: usize = const { NLMSG_ALIGN(SIZE_OF_IFADDRMSG) };

    // SAFETY: This is how we walk through the buffer received from the kernel
    unsafe { r.byte_add(offset).cast::<rtattr>() }
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Returns the payload size, in bytes, of an `ifaddrmsg` netlink message.
pub const fn IFA_PAYLOAD(n: *const nlmsghdr) -> usize {
    NLMSG_PAYLOAD(n, SIZE_OF_IFADDRMSG)
}

// Macros to handle rtattributes
/// Alignment boundary for `rtattr` structures. While `rtattr` has an alignment of 2,
/// netlink messages use 4-byte alignment due to additional data following the header.
pub const RTA_ALIGNTO: usize = 4;

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Aligns the given length up to the nearest `RTA_ALIGNTO` boundary.
pub const fn RTA_ALIGN(len: usize) -> usize {
    (len + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Validates that `rta` pointer points to a valid `rtattr` header, given the remaining buffer `len`.
pub const fn RTA_OK(rta: *const rtattr, len: usize) -> bool {
    len >= SIZE_OF_RTATTR && {
        // SAFETY: This is how the macros work
        let rta_len: usize = u16_to_usize(unsafe { (*rta).rta_len });

        rta_len >= SIZE_OF_RTATTR && rta_len <= len
    }
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Advance to the next `rtattr` entry in a netlink attribute buffer.
/// Validate the returned pointer with `RTA_OK`.
pub const fn RTA_NEXT(rta: *const rtattr, attrlen: &mut usize) -> *const rtattr {
    let aligned_len = {
        // SAFETY: This is how the macros work
        let rtattr_len = unsafe { u16_to_usize((*rta).rta_len) };

        RTA_ALIGN(rtattr_len)
    };

    // well-formed netlink pads every attribute, but a malformed buffer can end before the final attribute's padding, then saturating to 0 lets `RTA_OK` end the walk
    *attrlen = attrlen.saturating_sub(aligned_len);

    let offset = aligned_len;

    // SAFETY: This is how we walk through the buffer received from the kernel
    unsafe { rta.byte_add(offset) }
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Returns the total length of an `rtattr` with `len` bytes of payload.
pub const fn RTA_LENGTH(len: usize) -> usize {
    RTA_ALIGN(SIZE_OF_RTATTR + len)
}

#[expect(non_snake_case, unused, reason = "Mirror the macros")]
pub const fn RTA_SPACE(len: usize) -> usize {
    RTA_ALIGN(RTA_LENGTH(len))
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Returns a pointer to the data following the `rtattr` header.
pub const fn RTA_DATA<T>(rta: *const rtattr) -> *const T {
    let offset: usize = const { RTA_LENGTH(0) };

    // SAFETY: This is how we walk through the buffer received from the kernel
    unsafe { rta.byte_add(offset).cast::<T>() }
}

#[expect(non_snake_case, unused, reason = "Mirror the macros")]
// Calculates the length of the payload of the `rtattr`.
pub const fn RTA_PAYLOAD(rta: &rtattr) -> usize {
    u16_to_usize(rta.rta_len).saturating_sub(RTA_LENGTH(0))
}

pub const NLMSG_ALIGNTO: usize = 4;

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Aligns a netlink message length.
pub const fn NLMSG_ALIGN(len: usize) -> usize {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Returns the aligned length of the netlink message header.
pub const fn NLMSG_HDRLEN() -> usize {
    NLMSG_ALIGN(SIZE_OF_NLMSGHDR)
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Returns the total length of a netlink message.
pub const fn NLMSG_LENGTH(len: usize) -> usize {
    len + NLMSG_HDRLEN()
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Returns the total space required for a netlink message carrying a payload of size `len`.
pub const fn NLMSG_SPACE(len: usize) -> usize {
    NLMSG_ALIGN(NLMSG_LENGTH(len))
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Returns a pointer to the payload data that follows the `nlmsghdr` header.
pub const fn NLMSG_DATA<T>(nlh: *const nlmsghdr) -> *const T {
    let offset: usize = const { NLMSG_LENGTH(0) };

    // SAFETY: This is how we walk through the buffer received from the kernel
    unsafe { nlh.byte_add(offset).cast::<T>() }
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Advance to the next `nlmsghdr` in a contiguous netlink message buffer.
/// Validate the returned pointer with `NLMSG_OK`.
pub const fn NLMSG_NEXT(nlh: *const nlmsghdr, len: &mut usize) -> *const nlmsghdr {
    let aligned_len = {
        // SAFETY: This is how the macros work
        let nlmsg_len = u32_to_usize(unsafe { (*nlh).nlmsg_len });

        NLMSG_ALIGN(nlmsg_len)
    };

    // well-formed netlink pads every message, but a malformed buffer can end before the final message's padding, then saturating to 0 lets `NLMSG_OK` end the walk
    *len = len.saturating_sub(aligned_len);

    let offset = aligned_len;

    // SAFETY: This is how we walk through the buffer received from the kernel
    unsafe { nlh.byte_add(offset) }
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Validates that the pointer to `nlmsghdr` points to a valid `nlmsghdr` based to the remaining `len`.
pub const fn NLMSG_OK(nlh: *const nlmsghdr, len: usize) -> bool {
    len >= SIZE_OF_NLMSGHDR && {
        // SAFETY: This is how the macros work
        let nlmsg_len = u32_to_usize(unsafe { (*nlh).nlmsg_len });

        nlmsg_len >= SIZE_OF_NLMSGHDR && nlmsg_len <= len
    }
}

#[expect(non_snake_case, reason = "Mirror the macros")]
/// Returns the number of payload bytes that follow the given `nlmsghdr`.
pub const fn NLMSG_PAYLOAD(nlh: *const nlmsghdr, len: usize) -> usize {
    // SAFETY: This is how the macros work
    let nlmsg_len = u32_to_usize(unsafe { (*nlh).nlmsg_len });

    // a well-formed message holds at least its header plus `len`, but a malformed one can be shorter, then it has no payload
    nlmsg_len.saturating_sub(NLMSG_SPACE(len))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;
    use shared::netlink::{ifaddrmsg, nlmsghdr, rtattr};

    use crate::netlink::{IFA_PAYLOAD, NLMSG_NEXT, NLMSG_OK, RTA_NEXT, RTA_OK};

    #[test]
    fn attribute_walk_stops_after_unpadded_final_attribute() {
        // `rta_len`, `rta_type` and payload of a padded 8-byte attribute, then of an unpadded 5-byte one, then 3 spare bytes
        let buffer: &[u16] = &[8, 1, 0, 0, 5, 2, 0, 0];

        let mut rta = buffer.as_ptr().cast::<rtattr>();
        let mut remaining = 13;
        let mut types = Vec::new();

        while RTA_OK(rta, remaining) {
            // SAFETY: `RTA_OK`
            types.push(unsafe { (*rta).rta_type });

            rta = RTA_NEXT(rta, &mut remaining);
        }

        assert_eq!(types, [1, 2]);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn message_walk_stops_after_unpadded_final_message() {
        // a 16-byte `nlmsghdr` with `nlmsg_len` 17, then 1 payload byte, then 3 spare bytes
        let buffer: &[u32] = &[17, 0, 0, 0, 0];

        let mut nlh = buffer.as_ptr().cast::<nlmsghdr>();
        let mut remaining = 17;
        let mut messages = 0_usize;

        while NLMSG_OK(nlh, remaining) {
            messages += 1;

            nlh = NLMSG_NEXT(nlh, &mut remaining);
        }

        assert_eq!(messages, 1);
        assert_eq!(remaining, 0);
    }

    #[test]
    fn ifa_payload_is_zero_for_message_without_room_for_ifaddrmsg() {
        // `nlmsg_len` 16 covers the header only
        let buffer: &[u32] = &[16, 0, 0, 0];

        assert!(16 < size_of::<nlmsghdr>() + size_of::<ifaddrmsg>());
        assert_eq!(IFA_PAYLOAD(buffer.as_ptr().cast::<nlmsghdr>()), 0);
    }
}
