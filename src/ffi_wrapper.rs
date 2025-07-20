use std::io::Error;
use std::os::fd::AsFd;
use std::os::unix::prelude::AsRawFd as _;
use std::ptr::null_mut;

use color_eyre::eyre;
use libc::{c_int, sigaction};
use tracing::Level;

use crate::wrap_and_report;

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

#[expect(unused, reason = "WIP")]
pub fn set_up_handler(
    signum: c_int,
    sig_handler: extern "C" fn(_: c_int),
) -> Result<(), eyre::Report> {
    #[expect(
        clippy::fn_to_numeric_cast_any,
        reason = "We actually need the function as a pointer, and this is well-defined"
    )]
    let sig_handler_ptr = sig_handler as usize;
    #[cfg(not(target_os = "macos"))]
    // SAFETY: all zeroes are valid for `sigset_t`
    let sa_mask = unsafe { std::mem::MaybeUninit::<libc::sigset_t>::zeroed().assume_init() };

    #[cfg(target_os = "macos")]
    let sa_mask = 0;

    let sa = sigaction {
        sa_sigaction: sig_handler_ptr,
        sa_flags: 0,
        sa_mask,
        #[cfg(not(target_os = "macos"))]
        sa_restorer: None,
    };

    // SAFETY: libc call
    if unsafe { sigaction(signum, &raw const sa, null_mut()) } == -1 {
        return Err(wrap_and_report!(
            Level::ERROR,
            Error::last_os_error(),
            "Failure to install signal handler"
        ));
    }

    Ok(())
}
