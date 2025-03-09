use std::sync::Arc;

use color_eyre::eyre;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::config::Config;
use crate::network_handler::Command;

#[cfg(target_os = "linux")]
type Monitor = crate::netlink_address_monitor::NetlinkAddressMonitor;

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "openbsd"))]
type Monitor = RouteSocketAddressMonitor;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "openbsd"
)))]
type Monitor = !;

pub fn create_address_monitor(
    cancellation_token: CancellationToken,
    channel: Sender<Command>,
    config: &Arc<Config>,
) -> Result<Monitor, eyre::Report> {
    Monitor::new(cancellation_token, channel, config).map_err(|e| {
        event!(Level::ERROR, ?e);
        e.into()
    })
}
