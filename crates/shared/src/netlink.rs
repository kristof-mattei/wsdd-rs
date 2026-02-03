use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

#[derive(IntoBytes, Immutable)]
#[repr(C)]
/// Netlink messages consist of a byte stream with one or multiple `nlmsghdr` headers and associated payload.
/// Note: This is how we send data to the kernel, but it doesn't mirror a pre-defined struct.
pub struct NetlinkRequest {
    /// Header.
    pub nh: nlmsghdr,
    /// Payload.
    pub ifa: ifaddrmsg,
}

/// Copy from `libc::nlmsghdr`, but we need zerocopy.
#[derive(KnownLayout, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct nlmsghdr {
    /// Size of message including header.
    pub nlmsg_len: u32,
    /// Type of message content.
    pub nlmsg_type: u16,
    /// Additional flags.
    pub nlmsg_flags: u16,
    /// Sequence number.
    pub nlmsg_seq: u32,
    /// Sender port ID.
    pub nlmsg_pid: u32,
}

#[derive(KnownLayout, FromBytes, Immutable)]
#[repr(C)]
pub struct nlmsgerr {
    pub error: libc::c_int,
    pub msg: nlmsghdr,
}

#[derive(KnownLayout, FromBytes, IntoBytes, Immutable)]
#[repr(C)]
pub struct ifaddrmsg {
    /// Address type.
    pub ifa_family: u8,
    /// Prefix length of address.
    pub ifa_prefixlen: u8,
    /// Address flags.
    pub ifa_flags: u8,
    /// Address scope.
    pub ifa_scope: u8,
    /// Interface index.
    pub ifa_index: u32,
}

#[derive(KnownLayout, FromBytes, Immutable)]
#[repr(C)]
pub struct rtattr {
    /// Length of option.
    pub rta_len: u16,
    /// Type of option.
    pub rta_type: u16,
    // Data follows
}

impl rtattr {
    #[must_use]
    pub fn label(&self) -> Option<&'static str> {
        const RTA_TYPES: [&str; 9] = [
            "IFA_UNSPEC",
            "IFA_ADDRESS",
            "IFA_LOCAL",
            "IFA_LABEL",
            "IFA_BROADCAST",
            "IFA_ANYCAST",
            "IFA_CACHEINFO",
            "IFA_MULTICAST",
            "IFA_FLAGS",
        ];

        RTA_TYPES.get(usize::from(self.rta_type)).copied()
    }
}
