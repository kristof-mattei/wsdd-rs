use std::sync::Arc;

use color_eyre::eyre;
use tracing::{event, Level};

use crate::config::Config;
use crate::network_address_monitor::NetworkAddressMonitor;

#[cfg(target_os = "linux")]
type Monitor<'nma> = crate::netlink_address_monitor::NetlinkAddressMonitor<'nma>;

#[cfg(any(target_os = "freebsd", target_os = "macos", target_os = "openbsd"))]
type Monitor = RouteSocketAddressMonitor;

#[cfg(not(any(
    target_os = "linux",
    target_os = "freebsd",
    target_os = "macos",
    target_os = "openbsd"
)))]
type Monitor = !;

pub fn create_address_monitor<'nma>(config: &Arc<Config>) -> Result<Monitor<'nma>, eyre::Report> {
    let nma = NetworkAddressMonitor::new(config);

    Monitor::new(nma, config).map_err(|e| {
        event!(Level::ERROR, ?e);
        e.into()
    })
}
