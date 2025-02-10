pub const WSDD_VERSION: &str = "0.8";

// # constants for WSD XML/SOAP parsing
// WSA_URI: str = 'http://schemas.xmlsoap.org/ws/2004/08/addressing'
const WSA_URI: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
// WSD_URI: str = 'http://schemas.xmlsoap.org/ws/2005/04/discovery'
const WSD_URI: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
// WSDP_URI: str = 'http://schemas.xmlsoap.org/ws/2006/02/devprof'
const WSDP_URI: &str = "http://schemas.xmlsoap.org/ws/2006/02/devprof";

// namespaces: Dict[str, str] = {
//     'soap': 'http://www.w3.org/2003/05/soap-envelope',
//     'wsa': WSA_URI,
//     'wsd': WSD_URI,
//     'wsx': 'http://schemas.xmlsoap.org/ws/2004/09/mex',
//     'wsdp': WSDP_URI,
//     'pnpx': 'http://schemas.microsoft.com/windows/pnpx/2005/10',
//     'pub': 'http://schemas.microsoft.com/windows/pub/2005/07'
// }

pub static NAMESPACES: LazyLock<HashMap<&'static str, &'static str>> = LazyLock::new(|| {
    HashMap::from_iter([
        ("soap", "http://www.w3.org/2003/05/soap-envelope"),
        ("wsa", WSA_URI),
        ("wsd", WSD_URI),
        ("wsx", "http://schemas.xmlsoap.org/ws/2004/09/mex"),
        ("wsdp", WSDP_URI),
        ("pnpx", "http://schemas.microsoft.com/windows/pnpx/2005/10"),
        ("pub", "http://schemas.microsoft.com/windows/pub/2005/07"),
    ])
});

// WSD_MAX_KNOWN_MESSAGES: int = 10

// WSD_PROBE: str = WSD_URI + '/Probe'
// WSD_PROBE_MATCH: str = WSD_URI + '/ProbeMatches'
// WSD_RESOLVE: str = WSD_URI + '/Resolve'
// WSD_RESOLVE_MATCH: str = WSD_URI + '/ResolveMatches'
// WSD_HELLO: str = WSD_URI + '/Hello'
// WSD_BYE: str = WSD_URI + '/Bye'
// WSD_GET: str = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get'
// WSD_GET_RESPONSE: str = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse'

// WSD_TYPE_DEVICE: str = 'wsdp:Device'
const WSD_TYPE_DEVICE: &str = "wsdp:Device";
// PUB_COMPUTER: str = 'pub:Computer'
const PUB_COMPUTER: &str = "pub:Computer";
// WSD_TYPE_DEVICE_COMPUTER: str = '{0} {1}'.format(WSD_TYPE_DEVICE, PUB_COMPUTER)
// TODO: fix when format_args!() becomes const
pub const WSD_TYPE_DEVICE_COMPUTER: &str = "wsdp:Device pub:Computer";

use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    num::NonZeroU16,
    sync::LazyLock,
};

// WSD_MCAST_GRP_V4: str = '239.255.255.250'
pub const WSD_MCAST_GRP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
// WSD_MCAST_GRP_V6: str = 'ff02::c'  # link-local
pub const WSD_MCAST_GRP_V6: Ipv6Addr = Ipv6Addr::new(65282, 0, 0, 0, 0, 0, 0, 12);

// WSA_ANON: str = WSA_URI + '/role/anonymous'
pub const WSA_ANON: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";
// WSA_DISCOVERY: str = 'urn:schemas-xmlsoap-org:ws:2005:04:discovery'

// MIME_TYPE_SOAP_XML: str = 'application/soap+xml'

// # protocol assignments (WSD spec/Section 2.4)
// WSD_UDP_PORT: int = 3702
pub const WSD_UDP_PORT: NonZeroU16 = unsafe { NonZeroU16::new_unchecked(3702) };
// WSD_HTTP_PORT: int = 5357
pub const WSD_HTTP_PORT: NonZeroU16 = unsafe { NonZeroU16::new_unchecked(5357) };
// WSD_MAX_LEN: int = 32767

// WSDD_LISTEN_PORT = 5359

// # SOAP/UDP transmission constants
// MULTICAST_UDP_REPEAT: int = 4
// UNICAST_UDP_REPEAT: int = 2
// UDP_MIN_DELAY: int = 50
// UDP_MAX_DELAY: int = 250
// UDP_UPPER_DELAY: int = 500

// # servers must recond in 4 seconds after probe arrives
// PROBE_TIMEOUT: int = 4
// MAX_STARTUP_PROBE_DELAY: int = 3
