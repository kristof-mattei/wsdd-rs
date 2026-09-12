use std::io::Error;
use std::ptr::null_mut;

use color_eyre::eyre;
use libc::{c_int, sigaction};
#[cfg(not(any(target_os = "windows", miri)))]
use tokio::signal::unix::SignalKind;
#[cfg(not(any(target_os = "windows", miri)))]
use tokio::signal::unix::signal;
use tracing::{Level, event};

use crate::shutdown::Shutdown;
use crate::wrap_and_report;

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "Waiting for `try_into()` to become const"
)]
const SIGINT: u8 = libc::SIGINT as u8;

#[expect(
    clippy::as_conversions,
    clippy::cast_possible_truncation,
    reason = "Waiting for `try_into()` to become const"
)]
const SIGTERM: u8 = libc::SIGTERM as u8;

async fn receive_sigterm() -> Result<(), std::io::Error> {
    #[cfg(not(any(target_os = "windows", miri)))]
    signal(SignalKind::terminate())?.recv().await;

    #[cfg(any(target_os = "windows", miri))]
    let _r = std::future::pending::<Result<(), std::io::Error>>().await;

    Ok(())
}

/// Waits forever for a `SIGTERM`.
pub async fn wait_for_sigterm() -> Shutdown {
    if let Err(error) = receive_sigterm().await {
        Shutdown::UnexpectedError(wrap_and_report!(
            Level::ERROR,
            error,
            "Failed to register SIGTERM handler"
        ))
    } else {
        event!(Level::WARN, "SIGTERM detected, stopping all tasks");

        Shutdown::Signal(SIGTERM)
    }
}

async fn receive_sigint() -> Result<(), std::io::Error> {
    #[cfg(not(miri))]
    tokio::signal::ctrl_c().await?;

    #[cfg(miri)]
    let _r = std::future::pending::<Result<(), std::io::Error>>().await;

    Ok(())
}

/// Waits forever for a `SIGINT`.
pub async fn wait_for_sigint() -> Shutdown {
    if let Err(error) = receive_sigint().await {
        Shutdown::UnexpectedError(wrap_and_report!(
            Level::ERROR,
            error,
            "Failed to register CTRL+c handler"
        ))
    } else {
        event!(Level::WARN, "CTRL+c detected, stopping all tasks");

        Shutdown::Signal(SIGINT)
    }
}

/// Sets signal back to its default action and raises it, killing this process.
/// Returns when the raise did not terminate the process: PID 1 of a PID namespace only receives signals it has a handler for, and the reset removes it.
pub fn terminate_by_signal(signal: u8) {
    let signum = c_int::from(signal);

    // tokio's handler stays installed for the rest of the process (`Signal`'s caveats), so without this reset the raise runs it instead
    // SAFETY: `signal(2)` with `SIG_DFL` has no preconditions
    if unsafe { libc::signal(signum, libc::SIG_DFL) } == libc::SIG_ERR {
        event!(
            Level::ERROR,
            error = %Error::last_os_error(),
            signal,
            "Failed to restore the default signal disposition"
        );

        return;
    }

    // SAFETY: `raise(3)` has no preconditions
    if unsafe { libc::raise(signum) } != 0 {
        event!(
            Level::ERROR,
            error = %Error::last_os_error(),
            signal,
            "Failed to raise the signal"
        );
    }
}

#[expect(unused, reason = "Unused")]
/// Installs `sig_handler` for `signum` via `sigaction`.
///
/// # Safety
///
/// `sig_handler` runs in signal context.
/// It must only call async-signal-safe functions (signal-safety(7)), anything else is undefined behavior.
/// That rules out allocation, locks, and most of std.
pub unsafe fn set_up_handler(
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

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt as _;
    use std::process::{Command, Stdio};

    use pretty_assertions::assert_eq;
    use tokio::signal::unix::{SignalKind, signal};

    use super::{SIGTERM, terminate_by_signal};

    const CHILD_MARKER: &str = "WSDD_RS_TERMINATE_BY_SIGNAL_CHILD";

    // the raise kills the calling process, so the scenario runs in a re-executed copy of this test binary
    #[cfg_attr(not(miri), test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    fn dies_by_the_raised_signal_despite_tokio_handler() {
        if std::env::var_os(CHILD_MARKER).is_some() {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_io()
                .build()
                .unwrap();

            // installs tokio's handler, the case under test
            runtime.block_on(async {
                let _listener = signal(SignalKind::terminate()).unwrap();
            });

            drop(runtime);

            terminate_by_signal(SIGTERM);

            // surviving the raise exits 0, which fails the parent's assertion
            return;
        }

        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "signal_handlers::tests::dies_by_the_raised_signal_despite_tokio_handler",
            ])
            .env(CHILD_MARKER, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();

        assert_eq!(status.signal(), Some(libc::SIGTERM));
    }
}
