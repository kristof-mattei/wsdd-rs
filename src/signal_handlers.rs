#[cfg(not(target_os = "windows"))]
use tokio::signal::unix::SignalKind;

macro_rules! await_linux_only_signal {
    ($signal:expr) => {{
        #[cfg(not(target_os = "windows"))]
        use tokio::signal::unix::signal;

        #[cfg(not(target_os = "windows"))]
        signal($signal)?.recv().await;

        #[cfg(target_os = "windows")]
        let _r = std::future::pending::<Result<(), std::io::Error>>().await;
    }};
}

/// Waits forever for a SIGTERM
pub async fn wait_for_sigterm() -> Result<(), std::io::Error> {
    await_linux_only_signal!(SignalKind::terminate());

    Ok(())
}

/// Waits forever for a SIGINT
pub async fn wait_for_sigint() -> Result<(), std::io::Error> {
    tokio::signal::ctrl_c().await?;

    Ok(())
}
