use std::process::{ExitCode, Termination};

use color_eyre::eyre;
use thiserror::Error;
use tracing::{Level, event};
/// Represents all ways the application can terminate.
///
/// - `Success`: Clean shutdown
/// - `OperationalFailure`: Expected failure (e.g., chroot denied, bad config)
/// - `UnexpectedError`: Programmer error or system failure we didn't anticipate
#[derive(Error, Debug)]
pub enum Shutdown {
    #[error("Exited normally")]
    Success,
    #[error("Operational Failure")]
    OperationalFailure {
        code: ExitCode,
        message: &'static str,
    },
    #[error("Unexpected Error")]
    UnexpectedError(#[from] eyre::Report),
}

impl Termination for Shutdown {
    fn report(self) -> ExitCode {
        match self {
            Shutdown::Success => ExitCode::SUCCESS,
            Shutdown::OperationalFailure { code, message } => {
                event!(Level::ERROR, "{}", message);

                code
            },
            Shutdown::UnexpectedError(report) => {
                Err::<std::convert::Infallible, _>(report).report()
            },
        }
    }
}
