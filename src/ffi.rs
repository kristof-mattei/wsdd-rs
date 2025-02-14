#![expect(clippy::struct_field_names)]
#![expect(non_snake_case)]
#![expect(unused)]
#![expect(non_camel_case_types)]
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Alignment of `rtattr`. `rtattr`'s `align_of()` is 2, but in a message received there's more because there's extra info in there
/// not described in the header. Padding bytes will mess up `size_of`.
pub const RTA_ALIGNTO: usize = 4;

pub const NLMSG_ALIGNTO: usize = 4;
pub const fn NLMSG_ALIGN(len: usize) -> usize {
    ((len) + NLMSG_ALIGNTO - 1) & !(NLMSG_ALIGNTO - 1)
}

// #define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
pub const NLMSG_HDRLEN: usize = NLMSG_ALIGN(size_of::<nlmsghdr>());

// #define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
pub const fn NLMSG_LENGTH(len: usize) -> usize {
    ((len) + NLMSG_HDRLEN)
}

// #define NLMSG_SPACE(len) NLMSG_ALIGN(NLMSG_LENGTH(len))
pub const fn NLMSG_SPACE(len: usize) -> usize {
    NLMSG_ALIGN(NLMSG_LENGTH(len))
}

// #define NLMSG_DATA(nlh)  ((void *)(((char *)nlh) + NLMSG_HDRLEN))
// #define NLMSG_NEXT(nlh,len)	 ((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
// 				  (struct nlmsghdr *)(((char *)(nlh)) + \
// 				  NLMSG_ALIGN((nlh)->nlmsg_len)))
// #define NLMSG_OK(nlh,len) ((len) >= (int)sizeof(struct nlmsghdr) && \
// 			   (nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
// 			   (nlh)->nlmsg_len <= (len))
// #define NLMSG_PAYLOAD(nlh,len) ((nlh)->nlmsg_len - NLMSG_SPACE((len)))

#[derive(KnownLayout, FromBytes, Immutable)]
#[repr(C)]
pub struct rtattr {
    pub rta_len: u16,
    pub rta_type: u16,
}

#[derive(KnownLayout, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
/// Copy from `libc::nlmsghdr`, but we need zerocopy
pub struct nlmsghdr {
    pub nlmsg_len: u32,
    pub nlmsg_type: u16,
    pub nlmsg_flags: u16,
    pub nlmsg_seq: u32,
    pub nlmsg_pid: u32,
}

#[derive(KnownLayout, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct ifaddrmsg {
    pub ifa_family: u8,    /* Address type */
    pub ifa_prefixlen: u8, /* Prefixlength of address */
    pub ifa_flags: u8,     /* Address flags */
    pub ifa_scope: u8,     /* Address scope */
    pub ifa_index: u32,    /* Interface index */
}
