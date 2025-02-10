use std::sync::Arc;

use crate::config::Config;

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

pub  fn create_address_monitor(config: Arc<Config>) -> Result<Monitor, String> {
    Monitor::new(config).map_err(|err| format!("{}", err))
}
