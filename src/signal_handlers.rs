use tokio::signal::unix::{SignalKind, signal};

/// Waits forever for a SIGTERM
pub async fn wait_for_sigterm() -> Result<(), std::io::Error> {
    signal(SignalKind::terminate())?.recv().await;

    Ok(())
}

/// Waits forever for a SIGINT
pub async fn wait_for_sigint() -> Result<(), std::io::Error> {
    tokio::signal::ctrl_c().await?;

    Ok(())
}
