use std::net::IpAddr;
use std::sync::Arc;

use crate::network_interface::NetworkInterface;

#[derive(Eq, Clone)]
pub struct NetworkAddress {
    pub address: IpAddr,
    pub interface: Arc<NetworkInterface>,
}

impl NetworkAddress {
    pub fn new(address: IpAddr, interface: &Arc<NetworkInterface>) -> Self {
        Self {
            address,
            interface: Arc::clone(interface),
        }
    }

    // """ return true if the (interface) address can be used for creating (link-local) multicasting sockets  """
    // # Nah, this check is not optimal but there are no local flags for
    // # addresses, but it should be safe for IPv4 anyways
    // # (https://tools.ietf.org/html/rfc5735#page-3)
    // return ((self._family == socket.AF_INET) and (self._raw_address[0] != 127)
    //         or (self._family == socket.AF_INET6) and (self._raw_address[0:2] == b'\xfe\x80'))
    pub fn is_multicastable(&self) -> bool {
        match self.address {
            IpAddr::V4(ipv4_addr) => !ipv4_addr.is_loopback(),
            IpAddr::V6(ipv6_addr) => ipv6_addr.is_unicast_link_local(),
        }
    }
}

impl std::fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}%{}", self.address, self.interface.name)
    }
}

impl std::cmp::PartialEq for NetworkAddress {
    fn eq(&self, other: &Self) -> bool {
        self.address == other.address && self.interface == other.interface
    }
}
