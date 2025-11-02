#![expect(clippy::struct_field_names, reason = "WIP")]
#![expect(non_snake_case, reason = "WIP")]
#![expect(clippy::multiple_unsafe_ops_per_block, reason = "FFI")]
use zerocopy::{Immutable, IntoBytes};

pub fn IFA_RTA(r: &mut ifaddrmsg) -> &mut rtattr {
    #[expect(clippy::cast_possible_truncation, reason = "")]
    #[expect(clippy::cast_possible_wrap, reason = "")]
    const OFFSET: isize = const {
        let align = NLMSG_ALIGN(size_of::<ifaddrmsg>() as u32);

        align as isize
    };

    // SAFETY: This is how we walk through the buffer received from the kernel
    #[expect(clippy::cast_ptr_alignment, reason = "")]
    unsafe {
        (&raw mut *r)
            .cast::<u8>()
            .offset(OFFSET)
            .cast::<rtattr>()
            .as_mut()
    }
    .unwrap()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "`nlmsg_len` is `u32`, so we need to downcast. Plus, the size is 16 which fits in a `u32`"
)]
pub fn IFA_PAYLOAD(n: &nlmsghdr) -> u32 {
    NLMSG_PAYLOAD(n, size_of::<ifaddrmsg>() as u32)
}

// Macros to handle rtattributes
/// Alignment of `rtattr`. `rtattr`'s `align_of()` is 2, but in a message received there's more because there's extra info in there
/// not described in the header. Padding bytes will mess up `size_of`.
pub const RTA_ALIGNTO: u16 = 4;

pub const fn RTA_ALIGN(len: u16) -> u16 {
    (len + RTA_ALIGNTO - 1) & !(RTA_ALIGNTO - 1)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "`rta_len` is `u16`, so we need to downcast. Plus, the size is 4 which fits in a `u16`"
)]
pub const fn RTA_OK(rta: &rtattr, len: u16) -> bool {
    len >= size_of::<rtattr>() as u16
        && rta.rta_len >= size_of::<rtattr>() as u16
        && rta.rta_len <= len
}

pub fn RTA_NEXT<'a>(rta: &'a mut rtattr, attrlen: &mut u16) -> &'a mut rtattr {
    *attrlen -= RTA_ALIGN(rta.rta_len);

    #[expect(clippy::cast_possible_wrap, reason = "")]
    let offset: isize = { rta.rta_len as isize };

    // SAFETY: This is how we walk through the buffer received from the kernel
    #[expect(clippy::cast_ptr_alignment, reason = "")]
    unsafe {
        std::ptr::from_mut(rta)
            .cast::<u8>()
            .offset(offset)
            .cast::<rtattr>()
            .as_mut()
    }
    .unwrap()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "`rta_len` is `u16`, so we need to downcast. Plus, the size is 4 which fits in a `u16`"
)]
pub const fn RTA_LENGTH(len: u16) -> u16 {
    RTA_ALIGN(size_of::<rtattr>() as u16 + len)
}

#[expect(unused, reason = "WIP")]
pub const fn RTA_SPACE(len: u16) -> u16 {
    RTA_ALIGN(RTA_LENGTH(len))
}

pub const fn RTA_DATA<T>(rta: &mut rtattr) -> &mut T {
    #[expect(clippy::cast_possible_wrap, reason = "")]
    const OFFSET: isize = const {
        let length = RTA_LENGTH(0);

        length as isize
    };

    // SAFETY: This is how we walk through the buffer received from the kernel
    unsafe {
        std::ptr::from_mut(rta)
            .cast::<u8>()
            .offset(OFFSET)
            .cast::<T>()
            .as_mut()
    }
    .unwrap()
}

pub const fn RTA_PAYLOAD(rta: &rtattr) -> u16 {
    rta.rta_len - RTA_LENGTH(0)
}

pub const NLMSG_ALIGNTO: u32 = 4;

pub const fn NLMSG_ALIGN(len: u32) -> u32 {
    (len + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "`nlmsg_len` is `u32`, so we need to downcast. Plus, the size is 16 which fits in a `u32`"
)]
pub const fn NLMSG_HDRLEN() -> u32 {
    NLMSG_ALIGN(size_of::<nlmsghdr>() as u32)
}

pub const fn NLMSG_LENGTH(len: u32) -> u32 {
    len + NLMSG_HDRLEN()
}

pub fn NLMSG_SPACE(len: u32) -> u32 {
    NLMSG_ALIGN(NLMSG_LENGTH(len))
}

pub fn NLMSG_DATA<T>(nlh: &mut nlmsghdr) -> &mut T {
    #[expect(clippy::cast_possible_wrap, reason = "")]
    const OFFSET: isize = {
        let length = NLMSG_LENGTH(0);

        length as isize
    };

    // SAFETY: This is how we walk through the buffer received from the kernel
    unsafe {
        std::ptr::from_mut(nlh)
            .cast::<u8>()
            .offset(OFFSET)
            .cast::<T>()
            .as_mut()
    }
    .unwrap()
}

pub fn NLMSG_NEXT<'a>(nlh: &'a mut nlmsghdr, len: &mut u32) -> &'a mut nlmsghdr {
    *len -= NLMSG_ALIGN(nlh.nlmsg_len);

    #[expect(clippy::cast_possible_wrap, reason = "")]
    let OFFSET: isize = {
        let align = NLMSG_ALIGN(nlh.nlmsg_len);

        align as isize
    };

    // SAFETY: This is how we walk through the buffer received from the kernel
    #[expect(clippy::cast_ptr_alignment, reason = "")]
    unsafe {
        std::ptr::from_mut(nlh)
            .cast::<u8>()
            .offset(OFFSET)
            .cast::<nlmsghdr>()
            .as_mut()
    }
    .unwrap()
}

#[expect(
    clippy::cast_possible_truncation,
    reason = "`nlmsg_len` is `u32`, so we need to downcast. Plus, the size is 16 which fits in a `u32`"
)]
pub fn NLMSG_OK(nlh: &nlmsghdr, len: u32) -> bool {
    len >= size_of::<nlmsghdr>() as u32
        && nlh.nlmsg_len >= size_of::<nlmsghdr>() as u32
        && nlh.nlmsg_len <= len
}

pub fn NLMSG_PAYLOAD(nlh: &nlmsghdr, len: u32) -> u32 {
    nlh.nlmsg_len - NLMSG_SPACE(len)
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
pub struct netlink_req {
    pub nh: nlmsghdr,
    pub ifa: ifaddrmsg,
}

#[repr(C)]
pub struct rtattr {
    pub rta_len: u16,
    pub rta_type: u16,
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
/// Copy from `libc::nlmsghdr`, but we need zerocopy
pub struct nlmsghdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
pub struct ifaddrmsg {
    pub ifa_family: u8,    /* Address type */
    pub ifa_prefixlen: u8, /* Prefixlength of address */
    pub ifa_flags: u8,     /* Address flags */
    pub ifa_scope: u8,     /* Address scope */
    pub ifa_index: u32,    /* Interface index */
}
