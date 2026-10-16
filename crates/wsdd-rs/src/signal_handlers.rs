#[cfg(not(target_os = "windows"))]
use std::io::Write as _;

use color_eyre::eyre;
#[cfg(not(target_os = "windows"))]
use libc::c_int;
#[cfg(not(any(target_os = "windows", miri)))]
use tokio::signal::unix::{self, SignalKind, signal};
#[cfg(all(target_os = "windows", not(miri)))]
use tokio::signal::windows;
use tracing::{Level, event};

#[cfg(not(miri))]
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

#[derive(Clone, Copy)]
#[cfg_attr(miri, expect(dead_code, reason = "No signal listeners in Miri"))]
pub enum Signal {
    Interrupt,
    #[cfg_attr(
        all(target_os = "windows", not(miri)),
        expect(dead_code, reason = "No SIGTERM on Windows")
    )]
    Terminate,
}

impl Signal {
    pub const fn number(self) -> u8 {
        match self {
            Signal::Interrupt => SIGINT,
            Signal::Terminate => SIGTERM,
        }
    }
}

/// A signal that arrives while no `wait` is running is buffered for a later `wait`.
pub struct SignalListeners {
    #[cfg(not(any(target_os = "windows", miri)))]
    terminate: unix::Signal,
    #[cfg(not(any(target_os = "windows", miri)))]
    interrupt: unix::Signal,
    #[cfg(all(target_os = "windows", not(miri)))]
    interrupt: windows::CtrlC,
}

impl SignalListeners {
    #[cfg(not(any(target_os = "windows", miri)))]
    pub fn register() -> Result<Self, eyre::Report> {
        let terminate = signal(SignalKind::terminate()).map_err(|error| {
            wrap_and_report!(Level::ERROR, error, "Failed to register SIGTERM handler")
        })?;

        let interrupt = signal(SignalKind::interrupt()).map_err(|error| {
            wrap_and_report!(Level::ERROR, error, "Failed to register CTRL+c handler")
        })?;

        Ok(Self {
            terminate,
            interrupt,
        })
    }

    #[cfg(all(target_os = "windows", not(miri)))]
    pub fn register() -> Result<Self, eyre::Report> {
        let interrupt = windows::ctrl_c().map_err(|error| {
            wrap_and_report!(Level::ERROR, error, "Failed to register CTRL+c handler")
        })?;

        Ok(Self { interrupt })
    }

    #[cfg(miri)]
    pub fn register() -> Result<Self, eyre::Report> {
        Ok(Self {})
    }

    pub async fn wait(&mut self) -> Signal {
        let signal = self.receive().await;

        match signal {
            Signal::Terminate => event!(Level::WARN, "SIGTERM received"),
            Signal::Interrupt => event!(Level::WARN, "CTRL+c received"),
        }

        signal
    }

    #[cfg(not(any(target_os = "windows", miri)))]
    async fn receive(&mut self) -> Signal {
        tokio::select! {
            _ = self.terminate.recv() => Signal::Terminate,
            _ = self.interrupt.recv() => Signal::Interrupt,
        }
    }

    #[cfg(all(target_os = "windows", not(miri)))]
    async fn receive(&mut self) -> Signal {
        self.interrupt.recv().await;

        Signal::Interrupt
    }

    #[cfg(miri)]
    async fn receive(&mut self) -> Signal {
        std::future::pending().await
    }
}

/// Sets signal back to its default action and raises it, killing this process.
/// Returns when the raise did not terminate the process: PID 1 of a PID namespace only receives signals it has a handler for, and the reset removes it.
#[cfg(not(target_os = "windows"))]
pub fn terminate_by_signal(signal: Signal) {
    let signum = c_int::from(signal.number());

    // neither call can fail for SIGINT or SIGTERM

    // tokio's handler stays installed for the rest of the process (`tokio::signal::unix::Signal`'s caveats), so without this reset the raise runs it instead
    // SAFETY: `signal(2)` with `SIG_DFL` has no preconditions
    unsafe {
        libc::signal(signum, libc::SIG_DFL);
    }

    // the raise terminates without flushing stdout
    let _r = std::io::stdout().flush();

    // SAFETY: `raise(3)` has no preconditions
    unsafe {
        libc::raise(signum);
    }
}

#[cfg(target_os = "windows")]
pub fn terminate_by_signal(_signal: Signal) {}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "windows"))]
    mod unix {
        use std::os::unix::process::ExitStatusExt as _;
        use std::process::{Command, Stdio};

        use pretty_assertions::assert_eq;
        use tokio::signal::unix::{SignalKind, signal};

        use crate::signal_handlers::{Signal, SignalListeners, terminate_by_signal};

        const CHILD_MARKER: &str = "TERMINATE_BY_SIGNAL_CHILD";

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

                terminate_by_signal(Signal::Terminate);

                // surviving the raise exits 0, which fails the parent's assertion
                return;
            }

            let status = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "signal_handlers::tests::unix::dies_by_the_raised_signal_despite_tokio_handler",
                ])
                .env(CHILD_MARKER, "1")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();

            assert_eq!(status.signal(), Some(libc::SIGTERM));
        }

        #[cfg_attr(not(miri), tokio::test)]
        #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
        async fn wait_returns_a_signal_raised_before_the_call() {
            let mut signal_listeners = SignalListeners::register().unwrap();

            // SAFETY: `raise(3)` has no preconditions
            unsafe {
                libc::raise(libc::SIGINT);
            }

            let signal = signal_listeners.wait().await;

            assert!(matches!(signal, Signal::Interrupt));
        }
    }
}
