#[cfg(target_os = "linux")]
mod netlink_address_monitor;

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "openbsd"))]
mod route_socket_address_monitor;

use color_eyre::eyre;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::config::Config;
use crate::network_handler::Command;

#[cfg(target_os = "linux")]
type Monitor = netlink_address_monitor::NetlinkAddressMonitor;

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "openbsd"))]
type Monitor = route_socket_address_monitor::RouteSocketAddressMonitor;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "openbsd"
)))]
type Monitor = !;

pub fn create_address_monitor(
    cancellation_token: CancellationToken,
    new_address_tx: Sender<Command>,
    start_rx: tokio::sync::watch::Receiver<()>,
    config: &Config,
) -> Result<Monitor, eyre::Report> {
    Monitor::new(cancellation_token, new_address_tx, start_rx, config).map_err(|error| {
        event!(Level::ERROR, ?error);
        error.into()
    })
}
