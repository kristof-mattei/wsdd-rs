use std::net::SocketAddr;
use std::sync::Arc;

use ipnet::IpNet;

use crate::network_address::NetworkAddress;
use crate::network_interface::NetworkInterface;

pub struct UdpAddress {
    _network_address: NetworkAddress,
    // _transport_address: Tuple
    pub transport_address: SocketAddr,
    // _port: int
}

impl UdpAddress {
    pub fn new(
        transport_address: SocketAddr,
        address: IpNet,
        interface: Arc<NetworkInterface>,
    ) -> Self {
        let network_address = NetworkAddress::new(address, interface);

        Self {
            _network_address: network_address,
            transport_address,
        }
    }
}

impl std::cmp::PartialEq for UdpAddress {
    fn eq(&self, other: &Self) -> bool {
        self.transport_address == other.transport_address
    }
}

impl std::fmt::Display for UdpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.transport_address)
    }
}
