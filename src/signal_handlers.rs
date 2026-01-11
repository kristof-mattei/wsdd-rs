use std::io::Error;
use std::ptr::null_mut;

use color_eyre::eyre;
use libc::{c_int, sigaction};
#[cfg(not(any(target_os = "windows", miri)))]
use tokio::signal::unix::SignalKind;
#[cfg(not(any(target_os = "windows", miri)))]
use tokio::signal::unix::signal;
use tracing::Level;

use crate::wrap_and_report;

/// Waits forever for a `SIGTERM`
pub async fn wait_for_sigterm() -> Result<(), std::io::Error> {
    #[cfg(not(any(target_os = "windows", miri)))]
    {
        signal(SignalKind::terminate())?.recv().await;
    };

    #[cfg(any(target_os = "windows", miri))]
    let _r = std::future::pending::<Result<(), std::io::Error>>().await;

    Ok(())
}

/// Waits forever for a `SIGINT`
pub async fn wait_for_sigint() -> Result<(), std::io::Error> {
    #[cfg(not(any(target_os = "windows", miri)))]
    {
        tokio::signal::ctrl_c().await?;
    };

    #[cfg(any(target_os = "windows", miri))]
    let _r = std::future::pending::<Result<(), std::io::Error>>().await;

    Ok(())
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
