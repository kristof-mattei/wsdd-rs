#![expect(unused, reason = "Not used")]
#![expect(clippy::pub_use, reason = "Mimize code changes")]
use std::marker::PhantomData;

#[cfg(feature = "systemd")]
use libc::c_int;
pub use structs::{NetlinkRequest, ifaddrmsg, nlmsghdr, rtattr};
#[cfg(feature = "systemd")]
use tracing::{Level, event};

#[cfg(feature = "systemd")]
/// Wrapper around <https://www.man7.org/linux/man-pages/man3/sd_listen_fds.3.html>.
///
/// # Errors
/// See the underlying `sd_listen_fds(3)` systemd function.
pub fn listen_fds(unset_environment: bool) -> Result<Vec<i32>, std::io::Error> {
    #[link(name = "systemd")]
    unsafe extern "C" {
        fn sd_listen_fds(unset_environment: c_int) -> c_int;
    }

    // SAFETY: normal ffi call
    let result = unsafe { sd_listen_fds(unset_environment.into()) };

    if result < 0 {
        Err(std::io::Error::from_raw_os_error(-result))
    } else {
        let v = (3..(3 + result)).collect::<Vec<_>>();

        event!(Level::TRACE, received_fds = ?v, "Received fds from systemd");

        Ok(v)
    }
}

#[cfg(not(feature = "systemd"))]
#[expect(clippy::unnecessary_wraps, reason = "Mirror systemd API")]
pub fn listen_fds(_unset_environment: bool) -> Result<Vec<i32>, std::io::Error> {
    Ok(vec![])
}

#[repr(transparent)]
pub struct SendPtr<'a, T, U>
where
    T: ?Sized,
{
    ptr: *const U,
    _marker: PhantomData<&'a T>,
}

impl<'a, T, U> SendPtr<'a, T, U>
where
    T: ?Sized,
{
    /// Creates a new `SendPtr` from a buffer, starting at the buffer's base address.
    pub fn from_start(anchor: &'a T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self {
            ptr: anchor.as_ref().as_ptr().cast::<U>(),
            _marker: PhantomData,
        }
    }

    /// Creates a new `SendPtr` from an existing pointer, anchored to a buffer's lifetime.
    #[expect(unused, reason = "Not used")]
    pub fn from_ptr(_anchor: &'a T, ptr: *const U) -> Self {
        Self {
            ptr,
            _marker: PhantomData,
        }
    }

    pub fn get_ptr(&self) -> *const U {
        self.ptr
    }

    /// Mutate the pointer using the given function, preserving the lifetime.
    pub fn mutate<F>(&mut self, f: F)
    where
        F: FnOnce(*const U) -> *const U,
    {
        self.ptr = f(self.ptr);
    }
}
// SAFETY: We are only wrapping a pointer to a buffer that is guaranteed
// to live for 'a. The user must ensure no concurrent writes occur to the underlying buffer.
unsafe impl<T, U> Send for SendPtr<'_, T, U> where T: ?Sized {}

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
        let rta_len = unsafe { (*rta).rta_len } as usize;

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

    *attrlen -= aligned_len;

    let offset = aligned_len;

    // SAFETY: This is how we walk through the buffer received from the kernel
    unsafe { rta.byte_add(offset).cast::<rtattr>() }
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
    u16_to_usize(rta.rta_len) - RTA_LENGTH(0)
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

#[expect(non_snake_case, unused, reason = "Mirror the macros")]
/// Advance to the next `nlmsghdr` in a contiguous netlink message buffer.
/// Validate the returned pointer with `NLMSG_OK`.
pub const fn NLMSG_NEXT(nlh: *const nlmsghdr, len: &mut usize) -> *const nlmsghdr {
    let aligned_len = {
        // SAFETY: This is how the macros work
        let nlh_len = unsafe { &*nlh }.nlmsg_len;

        NLMSG_ALIGN(u32_to_usize(nlh_len))
    };

    *len -= aligned_len;

    let offset = aligned_len;

    // SAFETY: This is how we walk through the buffer received from the kernel
    unsafe { (nlh.byte_add(offset).cast::<nlmsghdr>()) }
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
    let nlh = unsafe { &*nlh };

    u32_to_usize(nlh.nlmsg_len) - NLMSG_SPACE(len)
}

mod structs {
    #![expect(non_ascii_idents, reason = "zerocopy")]

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

    #[repr(C)]
    #[derive(KnownLayout, FromBytes, Immutable)]
    pub struct rtattr {
        /// Length of option.
        pub rta_len: u16,
        /// Type of option.
        pub rta_type: u16,
        // Data follows
    }

    impl rtattr {
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

    #[derive(KnownLayout, FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    #[expect(clippy::struct_field_names, reason = "Mirror the libc struct names")]
    /// Copy from `libc::nlmsghdr`, but we need zerocopy.
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

    #[derive(KnownLayout, FromBytes, IntoBytes, Immutable)]
    #[repr(C)]
    #[expect(clippy::struct_field_names, reason = "Mirror the libc struct names")]
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
}

// because `From::from` cannot be called in `const` yet
const fn u16_to_usize(from: u16) -> usize {
    const _: () = assert!(
        usize::BITS >= u16::BITS,
        "We only support 32-bit/64-bit platforms so this should not fail"
    );

    from as usize
}

// because `From::from` cannot be called in `const` yet
// having raw `as usize` is dangerous, as copy-pasting might
// do it on a `value_u64 as usize` on a 32-bit platform which truncates
const fn u32_to_usize(from: u32) -> usize {
    const _: () = assert!(
        usize::BITS >= 32,
        "rtnetlink doesn't support 16-bit, so we don't either"
    );

    from as usize
}

#[cfg(not(miri))]
pub fn getpagesize() -> usize {
    unsafe extern "C" {
        fn getpagesize() -> i32;
    }

    // SAFETY: libc call
    let page_size: u32 = unsafe { getpagesize() }.unsigned_abs();

    u32_to_usize(page_size)
}

#[cfg(miri)]
pub fn getpagesize() -> usize {
    const { 1024 * 8 }
}

#[cfg(test)]
mod tests {
    #[cfg_attr(not(miri), test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    fn ui() {
        let t = trybuild::TestCases::new();
        t.compile_fail("tests/ui/*.rs");
    }
}
