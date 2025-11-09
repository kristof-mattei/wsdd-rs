use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

/// Alignment of `rtattr`. `rtattr`'s `align_of()` is 2, but in a message received there's more because there's extra info in there
/// not described in the header. Padding bytes will mess up `size_of`.
pub const RTA_ALIGNTO: u16 = 4;

pub const NLMSG_ALIGNTO: u32 = 4;

pub fn rta_type_to_label(rta_type: u16) -> Option<&'static str> {
    const RTA_TYPES: [&str; 12] = [
        "IFA_UNSPEC",
        "IFA_ADDRESS",
        "IFA_LOCAL",
        "IFA_LABEL",
        "IFA_BROADCAST",
        "IFA_ANYCAST",
        "IFA_CACHEINFO",
        "IFA_MULTICAST",
        "IFA_FLAGS",
        "IFA_RT_PRIORITY", /* u32, priority/metric for prefix route */
        "IFA_TARGET_NETNSID",
        "IFA_PROTO", /* u8, address protocol */
    ];

    RTA_TYPES.get(Into::<usize>::into(rta_type)).copied()
}

#[derive(IntoBytes, Immutable)]
#[repr(C)]
pub struct netlink_req {
    pub nh: nlmsghdr,
    pub ifa: ifaddrmsg,
}

#[repr(C)]
#[derive(KnownLayout, FromBytes, Immutable)]

pub struct rtattr {
    pub rta_len: u16,
    pub rta_type: u16,
}

#[derive(KnownLayout, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
#[expect(clippy::struct_field_names, reason = "Mirror the libc struct names")]
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
#[expect(clippy::struct_field_names, reason = "Mirror the libc struct names")]
pub struct ifaddrmsg {
    pub ifa_family: u8,    /* Address type */
    pub ifa_prefixlen: u8, /* Prefixlength of address */
    pub ifa_flags: u8,     /* Address flags */
    pub ifa_scope: u8,     /* Address scope */
    pub ifa_index: u32,    /* Interface index */
}
