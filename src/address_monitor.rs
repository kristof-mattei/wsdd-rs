use std::sync::Arc;

use color_eyre::eyre;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::config::Config;
use crate::network_address_monitor::NetworkAddressMonitor;

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
    config: &Arc<Config>,
) -> Result<Monitor, eyre::Report> {
    let nma = NetworkAddressMonitor::new(config);

    Monitor::new(nma, cancellation_token, config).map_err(|e| {
        event!(Level::ERROR, ?e);
        e.into()
    })
}
