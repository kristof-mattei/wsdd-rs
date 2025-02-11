#![expect(clippy::struct_field_names)]
use zerocopy::{Immutable, IntoBytes};

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
