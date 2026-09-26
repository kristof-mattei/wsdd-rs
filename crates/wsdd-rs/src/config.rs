use std::net::IpAddr;
use std::os::fd::RawFd;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tracing::{Level, event};
use uuid::Uuid;

use crate::network_interface::DevName;
use crate::wsd::device::DeviceUri;

#[expect(clippy::struct_excessive_bools, reason = "Main config")]
#[derive(Debug)]
pub struct Config {
    pub interfaces: Vec<InterfaceFilter>,
    pub hoplimit: u8,
    pub uuid: Uuid,
    pub uuid_as_device_uri: DeviceUri,
    pub hostname: Box<str>,
    pub full_hostname: Box<str>,
    pub no_autostart: bool,
    pub no_http: bool,
    pub chroot: Option<PathBuf>,
    pub user: Option<(u32, u32)>,
    pub discovery: bool,
    pub listen: Option<PortOrSocket>,
    pub no_host: bool,
    pub metadata_timeout: Duration,
    pub source_port: u16,
    pub app_sequence: AppSequence,
    pub bind_to: BindTo,
}

/// WS-Discovery, Appendix I. `MessageNumber` orders every message of the Target Service, so all interfaces share this counter.
#[derive(Debug)]
pub struct AppSequence {
    instance_id: Box<str>,
    sequence_id: Box<str>,
    message_number: AtomicU64,
}

impl AppSequence {
    pub fn new(instance_id: Box<str>, sequence_id: Box<str>) -> Self {
        Self {
            instance_id,
            sequence_id,
            message_number: AtomicU64::new(0),
        }
    }

    pub fn instance_id(&self) -> &str {
        &self.instance_id
    }

    pub fn sequence_id(&self) -> &str {
        &self.sequence_id
    }

    pub fn next_message_number(&self) -> u64 {
        self.message_number.fetch_add(1, Ordering::Relaxed)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum InterfaceFilter {
    Name(DevName),
    Address(IpAddr),
}

#[derive(Debug, Eq, PartialEq)]
pub enum BindTo {
    IPv4,
    IPv6,
    DualStack,
}

impl std::fmt::Display for BindTo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            BindTo::IPv4 => write!(f, "IPv4"),
            BindTo::IPv6 => write!(f, "IPv6"),
            BindTo::DualStack => write!(f, "Dual Stack"),
        }
    }
}

impl BindTo {
    pub fn ipv4_only(&self) -> bool {
        matches!(self, BindTo::IPv4)
    }

    pub fn ipv6_only(&self) -> bool {
        matches!(self, BindTo::IPv6)
    }
}

#[derive(Debug, Clone)]
pub enum PortOrSocket {
    Port(u16),
    Socket(RawFd),
    SocketPath(PathBuf),
}

impl Config {
    pub fn log(&self) {
        event!(Level::INFO, ?self);
    }
}
