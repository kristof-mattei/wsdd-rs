#![expect(dead_code)]
use std::net::IpAddr;
use std::sync::Arc;

use crate::network_interface::NetworkInterface;

#[derive(Eq)]
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

    //     @property
    //     def is_multicastable(self):
    //         # Nah, this check is not optimal but there are no local flags for
    //         # addresses, but it should be safe for IPv4 anyways
    //         # (https://tools.ietf.org/html/rfc5735#page-3)
    //         return ((self._family == socket.AF_INET) and (self._raw_address[0] == 127)
    //                 or (self._family == socket.AF_INET6) and (self._raw_address[0:2] != b'\xfe\x80'))
    fn is_multicastable(&self) -> bool {
        const HEX_FE: u8 = 254;
        const HEX_80: u8 = 128;

        match self.address {
            IpAddr::V4(ipv4_addr) => ipv4_addr.octets()[0] == 127,
            IpAddr::V6(ipv6_addr) => {
                let octets = ipv6_addr.octets();

                !(octets[0] == HEX_FE && octets[1] == HEX_80)
            },
        }
    }

    fn transport_str(&self) -> String {
        match self.address {
            IpAddr::V4(ipv4_addr) => ipv4_addr.to_string(),
            IpAddr::V6(ipv6_addr) => format!("[{}]", ipv6_addr),
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
