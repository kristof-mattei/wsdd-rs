use std::net::IpAddr;
use std::sync::Arc;

use crate::network_interface::NetworkInterface;

#[derive(Eq, Clone)]
pub struct NetworkAddress {
    pub address: IpAddr,
    pub interface: Arc<NetworkInterface>,
}

impl NetworkAddress {
    pub fn new(address: IpAddr, interface: Arc<NetworkInterface>) -> Self {
        Self { address, interface }
    }

    // Can the address can be used for creating (link-local) multicasting sockets?
    // # Nah, this check is not optimal but there are no local flags for
    // # addresses, but it should be safe for IPv4 anyways
    // # (https://tools.ietf.org/html/rfc5735#page-3)
    pub fn is_multicastable(&self) -> bool {
        match self.address {
            IpAddr::V4(ipv4_addr) => {
                // TODO add `https://doc.rust-lang.org/std/net/enum.IpAddr.html#method.is_global` once stabilized
                !ipv4_addr.is_loopback()
            },
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

#[cfg(test)]
mod tests {
    use std::{
        net::{Ipv4Addr, Ipv6Addr},
        sync::Arc,
    };

    use libc::RT_SCOPE_SITE;

    use crate::{network_address::NetworkAddress, network_interface::NetworkInterface};

    #[test]
    fn ipv4_loopback_not_multicastable() {
        let network_address = NetworkAddress::new(
            Ipv4Addr::new(127, 1, 2, 3).into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert!(!network_address.is_multicastable());
    }

    #[test]
    fn ipv4_local_multicastable() {
        let network_address = NetworkAddress::new(
            Ipv4Addr::new(192, 168, 100, 5).into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert!(network_address.is_multicastable());
    }

    #[test]
    fn ipv6_global_not_multicastable() {
        let network_address = NetworkAddress::new(
            Ipv6Addr::new(
                0x2001, 0x0db8, 0x5c41, 0xf105, 0x2cf9, 0xcd58, 0x0b74, 0x0684,
            )
            .into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert!(!network_address.is_multicastable());
    }

    #[test]
    fn ipv6_link_local_multicastable() {
        let network_address = NetworkAddress::new(
            Ipv6Addr::new(
                0xfdd5, 0x8f27, 0x6bc0, 0xf625, 0xcb86, 0xd38b, 0xa939, 0x3c67,
            )
            .into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert!(!network_address.is_multicastable());
    }
}
