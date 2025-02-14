use std::io::Error;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::unix::prelude::AsRawFd;
use std::ptr::null_mut;

use color_eyre::eyre;
use libc::{c_int, sigaction, sigset_t};
use tracing::Level;

use crate::wrap_and_report;

macro_rules! syscall {
    ($fn: ident ( $($arg: expr),* $(,)* ) , $err: literal) => {{
        #[allow(unused_unsafe)]
        let res = unsafe { libc::$fn($($arg, )*) };
        if res == $err {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(res)
        }
    }};
}

/// Caller must ensure `T` is the correct type for `opt` and `val`.
pub(crate) unsafe fn setsockopt<F: AsFd, T>(
    fd: F,
    opt: c_int,
    val: c_int,
    payload: &T,
) -> std::io::Result<()> {
    let payload = std::ptr::addr_of!(*payload).cast();

    #[expect(clippy::cast_possible_truncation)]
    let length = std::mem::size_of::<T>() as libc::socklen_t;

    syscall!(
        setsockopt(fd.as_fd().as_raw_fd(), opt, val, payload, length),
        -1
    )
    .map(|_| ())
}

#[allow(unused)]
pub fn set_up_handler(signum: c_int, handler: extern "C" fn(_: c_int)) -> Result<(), eyre::Report> {
    let sa = sigaction {
        sa_sigaction: handler as usize,
        sa_flags: 0,
        sa_mask: unsafe { MaybeUninit::<sigset_t>::zeroed().assume_init() },
        #[cfg(not(target_os = "macos"))]
        sa_restorer: None,
    };

    if unsafe { sigaction(signum, &sa, null_mut()) } == -1 {
        return Err(wrap_and_report!(
            Level::ERROR,
            Error::last_os_error(),
            "Failure to install signal handler"
        ));
    }

    Ok(())
}
