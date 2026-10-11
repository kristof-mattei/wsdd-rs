use zerocopy::byteorder::native_endian::{I32, U16, U32};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

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

#[derive(IntoBytes, Immutable)]
#[repr(C)]
pub struct LinkRequest {
    pub nh: nlmsghdr,
    pub ifi: ifinfomsg,
}

/// Copy from `libc::nlmsghdr`, but we need zerocopy.
#[derive(KnownLayout, FromBytes, IntoBytes, Immutable, Unaligned)]
#[repr(C)]
pub struct nlmsghdr {
    /// Size of message including header.
    pub nlmsg_len: U32,
    /// Type of message content.
    pub nlmsg_type: U16,
    /// Additional flags.
    pub nlmsg_flags: U16,
    /// Sequence number.
    pub nlmsg_seq: U32,
    /// Sender port ID.
    pub nlmsg_pid: U32,
}

#[derive(KnownLayout, FromBytes, Immutable, Unaligned)]
#[repr(C)]
pub struct nlmsgerr {
    pub error: I32,
    pub msg: nlmsghdr,
}

#[derive(KnownLayout, FromBytes, IntoBytes, Immutable, Unaligned)]
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
    pub ifa_index: U32,
}

#[derive(KnownLayout, FromBytes, IntoBytes, Immutable, Unaligned)]
#[repr(C)]
pub struct ifinfomsg {
    pub ifi_family: u8,
    pub ifi_pad: u8,
    /// `ARPHRD_*`.
    pub ifi_type: U16,
    pub ifi_index: I32,
    /// `IFF_*`.
    pub ifi_flags: U32,
    /// `IFF_*` change mask.
    pub ifi_change: U32,
}

#[derive(KnownLayout, FromBytes, IntoBytes, Immutable, Unaligned)]
#[repr(C)]
pub struct rtattr {
    /// Length of option.
    pub rta_len: U16,
    /// Type of option.
    pub rta_type: U16,
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

        RTA_TYPES.get(usize::from(self.rta_type.get())).copied()
    }
}
