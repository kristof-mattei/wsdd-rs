use std::os::fd::AsFd;
use std::os::unix::prelude::AsRawFd as _;

use libc::c_int;

macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) , $err: literal) => {{
        #[expect(clippy::allow_attributes, reason = "Not all libc calls are unsafe")]
        #[allow(unused_unsafe, reason = "libc function can be unsafe")]
        // SAFETY: libc call
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == $err {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

#[expect(unused, reason = "WIP")]
/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub unsafe fn setsockopt<F: AsFd, T>(
    fd: F,
    opt: c_int,
    val: c_int,
    payload: &T,
) -> std::io::Result<()> {
    let payload = std::ptr::addr_of!(*payload).cast();

    #[expect(clippy::cast_possible_truncation, reason = "Standard way of doing")]
    let length = std::mem::size_of::<T>() as libc::socklen_t;

    syscall!(
        setsockopt(fd.as_fd().as_raw_fd(), opt, val, payload, length),
        -1
    )
    .map(|_| ())
}
