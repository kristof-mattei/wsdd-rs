use std::os::fd::RawFd;
use std::path::PathBuf;
use std::time::Duration;

use tracing::{Level, event};
use uuid::Uuid;

use crate::wsd::device::DeviceUri;

#[expect(clippy::struct_excessive_bools, reason = "Main config")]
#[derive(Debug)]
pub struct Config {
    pub interfaces: Vec<Box<str>>,
    pub hoplimit: u8,
    pub uuid: Uuid,
    pub uuid_as_device_uri: DeviceUri,
    #[cfg_attr(not(test), expect(unused, reason = "WIP"))]
    pub verbosity: Level,
    pub hostname: Box<str>,
    pub full_hostname: Box<str>,
    pub no_autostart: bool,
    pub no_http: bool,
    pub ipv4only: bool,
    pub ipv6only: bool,
    //     if args.shortlog:
    //         fmt = '%(levelname)s: %(message)s'
    //     else:
    //         fmt = '%(asctime)s:%(name)s %(levelname)s(pid %(process)d): %(message)s'

    //     logging.basicConfig(level=log_level, format=fmt)
    //     logger = logging.getLogger('wsdd')
    #[expect(unused, reason = "WIP")]
    pub shortlog: bool,
    pub chroot: Option<PathBuf>,
    pub user: Option<(u32, u32)>,
    pub discovery: bool,
    pub listen: Option<PortOrSocket>,
    pub no_host: bool,
    pub metadata_timeout: Duration,
    pub source_port: u16,
    pub wsd_instance_id: Box<str>,
    #[expect(clippy::struct_field_names, reason = "Sub-config")]
    pub ssl_config: SSLConfig,
}

#[derive(Debug, Clone)]
pub enum PortOrSocket {
    Port(u16),
    Socket(RawFd),
    SocketPath(PathBuf),
}

#[derive(Debug)]
pub enum SSLConfig {
    None,
    Half,
    Full,
}

impl Config {
    pub fn log(&self) {
        event!(Level::INFO, ?self);
    }
}
