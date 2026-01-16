use std::process::{ExitCode, Termination};

use color_eyre::eyre;
use tracing::{Level, event};

/// Represents all ways the application can terminate.
pub enum Shutdown {
    Success,
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
            Shutdown::OperationalFailure { code, message } => {
                event!(Level::ERROR, ?code, ?message);

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
