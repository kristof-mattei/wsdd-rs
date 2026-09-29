use std::sync::Arc;

use ipnet::IpNet;

use crate::network_interface::NetworkInterface;

#[derive(Clone, Debug)]
pub struct NetworkAddress {
    pub address: IpNet,
    pub interface: Arc<NetworkInterface>,
}

impl NetworkAddress {
    pub fn new(address: IpNet, interface: Arc<NetworkInterface>) -> Self {
        Self { address, interface }
    }

    // Can the address can be used for creating (link-local) multicasting sockets?
    // # Nah, this check is not optimal but there are no local flags for
    // # addresses, but it should be safe for IPv4 anyways
    // # (https://tools.ietf.org/html/rfc5735#page-3)
    pub fn is_multicastable(&self) -> bool {
        match self.address {
            IpNet::V4(ipv4_net) => !ipv4_net.addr().is_loopback(),
            IpNet::V6(ipv6_net) => ipv6_net.addr().is_unicast_link_local(),
        }
    }
}

impl std::fmt::Display for NetworkAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}%{}", self.address, self.interface.name())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::sync::Arc;

    use ipnet::{Ipv4Net, Ipv6Net};
    use libc::RT_SCOPE_SITE;
    use pretty_assertions::assert_eq;

    use crate::network_address::NetworkAddress;
    use crate::network_interface::NetworkInterface;

    #[test]
    fn ipv4_loopback_not_multicastable() {
        let network_address = NetworkAddress::new(
            Ipv4Net::new(Ipv4Addr::new(127, 1, 2, 3), 8).unwrap().into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert!(!network_address.is_multicastable());
    }

    #[test]
    fn ipv4_local_multicastable() {
        let network_address = NetworkAddress::new(
            Ipv4Net::new(Ipv4Addr::new(192, 168, 100, 5), 24)
                .unwrap()
                .into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert!(network_address.is_multicastable());
    }

    #[test]
    fn ipv6_global_not_multicastable() {
        let network_address = NetworkAddress::new(
            Ipv6Net::new(
                Ipv6Addr::new(
                    0x2001, 0x0db8, 0x5c41, 0xf105, 0x2cf9, 0xcd58, 0x0b74, 0x0684,
                ),
                64,
            )
            .unwrap()
            .into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert!(!network_address.is_multicastable());
    }

    #[test]
    fn ipv6_unique_local_not_multicastable() {
        let network_address = NetworkAddress::new(
            Ipv6Net::new(
                Ipv6Addr::new(
                    0xfdd5, 0x8f27, 0x6bc0, 0xf625, 0xcb86, 0xd38b, 0xa939, 0x3c67,
                ),
                16,
            )
            .unwrap()
            .into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert!(!network_address.is_multicastable());
    }

    #[test]
    fn ipv6_link_local_multicastable() {
        let network_address = NetworkAddress::new(
            Ipv6Net::new(
                Ipv6Addr::new(0xfe80, 0, 0, 0, 0x1c2d, 0x3e4f, 0x5a6b, 0x7c8d),
                64,
            )
            .unwrap()
            .into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert!(network_address.is_multicastable());
    }

    #[test]
    fn ipv4_display() {
        let network_address = NetworkAddress::new(
            Ipv4Net::new(Ipv4Addr::new(192, 168, 100, 5), 24)
                .unwrap()
                .into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert_eq!(network_address.to_string(), "192.168.100.5/24%eth0");
    }

    #[test]
    fn ipv6_display() {
        let network_address = NetworkAddress::new(
            Ipv6Net::new(
                Ipv6Addr::new(
                    0x2001, 0x0db8, 0x5c41, 0xf105, 0x2cf9, 0xcd58, 0x0b74, 0x0684,
                ),
                64,
            )
            .unwrap()
            .into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        assert_eq!(
            network_address.to_string(),
            "2001:db8:5c41:f105:2cf9:cd58:b74:684/64%eth0"
        );
    }
}
