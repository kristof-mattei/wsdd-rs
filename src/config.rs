use std::path::PathBuf;

use tracing::{event, Level};
use uuid::Uuid;

#[expect(clippy::struct_excessive_bools)]
#[derive(Debug, PartialEq)]
pub  struct Config {
    pub  interface: Vec<String>,
    pub  hoplimit: u8,
    pub  uuid: Uuid,
    // pub  verbose: u8,
    pub  domain: Option<String>,
    pub  hostname: String,
    pub  workgroup: String,
    pub  no_autostart: bool,
    pub  no_http: bool,
    pub  ipv4only: bool,
    pub  ipv6only: bool,
    // pub  shortlog: bool,
    pub  preserve_case: bool,
    pub  chroot: Option<PathBuf>,
    pub  user: Option<(u32, u32)>,
    pub  discovery: bool,
    pub  listen: Option<PortOrSocket>,
    pub  no_host: bool,
    pub  metadata_timeout: f32,
    pub  source_port: u16,
}

#[derive(Debug, PartialEq, Clone)]
pub  enum PortOrSocket {
    Port(u16),
    SocketPath(PathBuf),
}

impl Config {
    pub  fn log(&self) {
        event!(Level::INFO, "{:?}", self);
    }
}
