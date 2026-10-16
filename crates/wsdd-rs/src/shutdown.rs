use std::process::{ExitCode, Termination};

use color_eyre::eyre;
use tracing::{Level, event};

use crate::signal_handlers::{Signal, terminate_by_signal};

/// Represents all ways the application can terminate.
pub enum Shutdown {
    #[expect(unused, reason = "Application is a daemon")]
    Success,
    Signal(Signal),
    OperationalFailure {
        code: ExitCode,
        message: &'static str,
        error: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    UnexpectedError(eyre::Report),
}

impl Termination for Shutdown {
    fn report(self) -> ExitCode {
        match self {
            Shutdown::Success => ExitCode::SUCCESS,
            Shutdown::Signal(signal) => {
                // 128 + n is the shell's exit code for death by signal n
                let exit_code = ExitCode::from(128 + signal.number());

                // `terminate_by_signal` cannot kill PID 1
                if std::process::id() == 1 {
                    event!(
                        Level::INFO,
                        signal = signal.number(),
                        exit_code = ?exit_code,
                        "Running as PID 1, exiting with an exit code instead of re-raising the signal"
                    );

                    return exit_code;
                }

                event!(
                    Level::INFO,
                    signal = signal.number(),
                    "Terminating by re-raising the signal"
                );

                terminate_by_signal(signal);

                event!(
                    Level::WARN,
                    signal = signal.number(),
                    exit_code = ?exit_code,
                    "Survived the re-raise, falling back to an exit code"
                );

                exit_code
            },
            Shutdown::OperationalFailure {
                code,
                message,
                error,
            } => {
                if let Some(error) = error {
                    event!(Level::ERROR, ?code, %error, message);
                } else {
                    event!(Level::ERROR, ?code, message);
                }

                code
            },
            Shutdown::UnexpectedError(report) => {
                event!(
                    Level::ERROR,
                    error = AsRef::<dyn std::error::Error>::as_ref(&report),
                    "Exiting because of an unexpected error"
                );

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
