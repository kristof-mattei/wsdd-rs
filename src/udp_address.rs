use std::net::SocketAddr;

use crate::{network_address::NetworkAddress, network_interface::NetworkInterface};

#[derive(Eq)]
pub struct UdpAddress {
    pub network_address: NetworkAddress,
    // _transport_address: Tuple
    pub transport_address: SocketAddr,
    // _port: int
}

impl UdpAddress {
    pub fn new(transport_address: SocketAddr, interface: NetworkInterface) -> Self {
        let network_address = NetworkAddress::new(transport_address.ip(), interface);

        Self {
            network_address,
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

// class y(NetworkAddress):

//     def __init__(self, family, transport_address: Tuple, interface: NetworkInterface) -> None:

//         if not (family == socket.AF_INET or family == socket.AF_INET6):
//             raise RuntimeError('Unsupport address address family: {}.'.format(family))

//         self._transport_address = transport_address
//         self._port = transport_address[1]

//         super().__init__(family, transport_address[0], interface)

//     @property
//     def transport_address(self):
//         return self._transport_address

//     @property
//     def port(self):
//         return self._port

//     def __eq__(self, other) -> bool:
//         return self.transport_address == other.transport_address
