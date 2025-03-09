use std::net::IpAddr;

pub struct UrlIpAddr {
    ip_addr: IpAddr,
}

impl std::fmt::Display for UrlIpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.ip_addr {
            IpAddr::V4(ipv4_addr) => write!(f, "{}", ipv4_addr),
            IpAddr::V6(ipv6_addr) => write!(f, "[{}]", ipv6_addr),
        }
    }
}

impl From<IpAddr> for UrlIpAddr {
    fn from(value: IpAddr) -> Self {
        UrlIpAddr { ip_addr: value }
    }
}
