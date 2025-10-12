use std::net::IpAddr;

pub struct UrlIpAddr {
    ip_addr: IpAddr,
}

impl std::fmt::Display for UrlIpAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.ip_addr {
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use pretty_assertions::assert_eq;

    use crate::url_ip_addr::UrlIpAddr;

    #[test]
    fn displays_ipv4() {
        let ip_addr: IpAddr = Ipv4Addr::new(192, 168, 100, 5).into();

        let url_ip_addr: UrlIpAddr = ip_addr.into();

        assert_eq!("192.168.100.5", url_ip_addr.to_string());
    }

    #[test]
    fn displays_ipv6_with_square_brackets() {
        let ip_addr: IpAddr = Ipv6Addr::new(
            0x2001, 0x0db8, 0x5c41, 0xf105, 0x2cf9, 0xcd58, 0x0b74, 0x0684,
        )
        .into();

        let url_ip_addr: UrlIpAddr = ip_addr.into();

        assert_eq!(
            "[2001:db8:5c41:f105:2cf9:cd58:b74:684]",
            url_ip_addr.to_string()
        );
    }
}
