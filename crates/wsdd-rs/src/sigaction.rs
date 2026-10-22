use std::io::Error;
use std::ptr::null_mut;

use color_eyre::eyre;
use libc::{c_int, sigaction};
use tracing::Level;

use crate::wrap_and_report;

#[expect(unused, reason = "Unused")]
/// Installs `sig_handler` for `signum` via `sigaction`.
///
/// # Safety
///
/// `sig_handler` runs in signal context.
/// It must only call async-signal-safe functions (signal-safety(7)), anything else is undefined behavior.
/// That rules out allocation, locks, and most of std.
pub(crate) unsafe fn set_up_handler(
    signum: c_int,
    sig_handler: extern "C" fn(_: c_int),
) -> Result<(), eyre::Report> {
    // The kernel reconstitutes a callable pointer from this integer when it delivers the signal.
    // `addr` documents a promise that the integer is never turned back into a pointer, so we use `expose_provenance`.
    #[expect(
        clippy::as_conversions,
        reason = "There is no cast-free conversion from a fn pointer to a data pointer"
    )]
    let sig_handler_ptr = (sig_handler as *const ()).expose_provenance();

    let sa_mask = {
        let mut sa_mask = std::mem::MaybeUninit::<libc::sigset_t>::uninit();

        // SAFETY: the pointer is valid for writes of `sigset_t`
        if unsafe { libc::sigemptyset(sa_mask.as_mut_ptr()) } == -1 {
            return Err(wrap_and_report!(
                Level::ERROR,
                Error::last_os_error(),
                "Failure to initialize the signal mask"
            ));
        }

        // SAFETY: `sigemptyset` returned 0, so the set is initialized
        unsafe { sa_mask.assume_init() }
    };

    let sa = sigaction {
        sa_sigaction: sig_handler_ptr,
        // No SA_RESTART: blocking syscalls interrupted by this signal fail with EINTR instead of resuming.
        sa_flags: 0,
        sa_mask,
        // Not for application use per sigaction(2), POSIX does not specify this field.
        #[cfg(not(target_os = "macos"))]
        sa_restorer: None,
    };

    // SAFETY: `sa` is initialized and valid for reads. A null `oldact` is
    // permitted by sigaction(2).
    if unsafe { sigaction(signum, &raw const sa, null_mut()) } == -1 {
        return Err(wrap_and_report!(
            Level::ERROR,
            Error::last_os_error(),
            "Failure to install signal handler"
        ));
    }

    Ok(())
}
