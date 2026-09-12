use std::process::{ExitCode, Termination};

use color_eyre::eyre;
use tracing::{Level, event};

use crate::signal_handlers::terminate_by_signal;

/// Represents all ways the application can terminate.
pub enum Shutdown {
    #[expect(unused, reason = "Application is a daemon")]
    Success,
    Signal(u8),
    OperationalFailure {
        code: ExitCode,
        message: &'static str,
    },
    UnexpectedError(eyre::Report),
}

impl std::fmt::Display for Shutdown {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Shutdown::Success => write!(f, "Clean shutdown"),
            Shutdown::Signal(s) => write!(f, "Signal {}", s),
            Shutdown::OperationalFailure { code, message } => {
                write!(
                    f,
                    "Expected failure (e.g., chroot denied, bad config). Code {:?} ({})",
                    code, message
                )
            },
            Shutdown::UnexpectedError(ref report) => write!(
                f,
                "Bug or system failure we didn't or can't (reasonably) anticipate {}",
                report
            ),
        }
    }
}

impl Termination for Shutdown {
    fn report(self) -> ExitCode {
        match self {
            Shutdown::Success => ExitCode::SUCCESS,
            Shutdown::Signal(signal) => {
                event!(Level::INFO, signal, "Terminating by re-raising the signal");

                terminate_by_signal(signal);

                // the process survived the raise, 128 + n is the shell's exit code for death by signal n
                let exit_code = ExitCode::from(128 + signal);

                event!(
                    Level::WARN,
                    signal,
                    exit_code = ?exit_code,
                    "Survived the re-raise, falling back to an exit code"
                );

                exit_code
            },
            Shutdown::OperationalFailure { code, message } => {
                event!(Level::ERROR, ?code, message);

                code
            },
            Shutdown::UnexpectedError(report) => {
                Err::<std::convert::Infallible, _>(report).report()
            },
        }
    }
}

impl<E: Into<eyre::Report>> From<E> for Shutdown {
    fn from(error: E) -> Self {
        Shutdown::UnexpectedError(error.into())
    }
}
