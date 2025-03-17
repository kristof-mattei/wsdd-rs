use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;

use const_format::concatcp;

pub const WSDD_VERSION: &str = "0.8";

// # constants for WSD XML/SOAP parsing
// WSA_URI: str = 'http://schemas.xmlsoap.org/ws/2004/08/addressing'
pub const WSA_URI: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
// WSD_URI: str = 'http://schemas.xmlsoap.org/ws/2005/04/discovery'
pub const WSD_URI: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
// WSDP_URI: str = 'http://schemas.xmlsoap.org/ws/2006/02/devprof'
pub const WSDP_URI: &str = "http://schemas.xmlsoap.org/ws/2006/02/devprof";

// namespaces: Dict[str, str] = {
//     'soap': 'http://www.w3.org/2003/05/soap-envelope',
//     'wsa': WSA_URI,
//     'wsd': WSD_URI,
//     'wsx': 'http://schemas.xmlsoap.org/ws/2004/09/mex',
//     'wsdp': WSDP_URI,
//     'pnpx': 'http://schemas.microsoft.com/windows/pnpx/2005/10',
//     'pub': 'http://schemas.microsoft.com/windows/pub/2005/07'
// }

pub const XML_SOAP_NAMESPACE: &str = "http://www.w3.org/2003/05/soap-envelope";
pub const XML_WSA_NAMESPACE: &str = WSA_URI;
pub const XML_WSD_NAMESPACE: &str = WSD_URI;
#[expect(unused)]
pub const XML_WSX_NAMESPACE: &str = "http://schemas.xmlsoap.org/ws/2004/09/mex";
pub const XML_WSDP_NAMESPACE: &str = WSDP_URI;
#[expect(unused)]
pub const XML_PNPX_NAMESPACE: &str = "http://schemas.microsoft.com/windows/pnpx/2005/10";
pub const XML_PUB_NAMESPACE: &str = "http://schemas.microsoft.com/windows/pub/2005/07";

// WSD_MAX_KNOWN_MESSAGES: int = 10

// WSD_PROBE: str = WSD_URI + '/Probe'
pub const WSD_PROBE: &str = concatcp!(WSD_URI, "/Probe");
// WSD_PROBE_MATCH: str = WSD_URI + '/ProbeMatches'
pub const WSD_PROBE_MATCH: &str = concatcp!(WSD_URI, "/ProbeMatches");
// WSD_RESOLVE: str = WSD_URI + '/Resolve'
pub const WSD_RESOLVE: &str = concatcp!(WSD_URI, "/Resolve");
// WSD_RESOLVE_MATCH: str = WSD_URI + '/ResolveMatches'
pub const WSD_RESOLVE_MATCH: &str = concatcp!(WSD_URI, "/ResolveMatches");
// WSD_HELLO: str = WSD_URI + '/Hello'
pub const WSD_HELLO: &str = concatcp!(WSD_URI, "/Hello");
// WSD_BYE: str = WSD_URI + '/Bye'
pub const WSD_BYE: &str = concatcp!(WSD_URI, "/Bye");
// WSD_GET: str = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/Get'
// WSD_GET_RESPONSE: str = 'http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse'

// WSD_TYPE_DEVICE: str = 'wsdp:Device'
pub const WSD_TYPE_DEVICE: &str = "wsdp:Device";
// PUB_COMPUTER: str = 'pub:Computer'
const PUB_COMPUTER: &str = "pub:Computer";
// WSD_TYPE_DEVICE_COMPUTER: str = '{0} {1}'.format(WSD_TYPE_DEVICE, PUB_COMPUTER)
// TODO: fix when format_args!() becomes const
pub const WSD_TYPE_DEVICE_COMPUTER: &str = concatcp!(WSD_TYPE_DEVICE, " ", PUB_COMPUTER);

// WSD_MCAST_GRP_V4: str = '239.255.255.250'
pub const WSD_MCAST_GRP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
// WSD_MCAST_GRP_V6: str = 'ff02::c'  # link-local
pub const WSD_MCAST_GRP_V6: Ipv6Addr = Ipv6Addr::new(65282, 0, 0, 0, 0, 0, 0, 12);

// WSA_ANON: str = WSA_URI + '/role/anonymous'
pub const WSA_ANON: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous";
// WSA_DISCOVERY: str = 'urn:schemas-xmlsoap-org:ws:2005:04:discovery'
pub const WSA_DISCOVERY: &str = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";

// MIME_TYPE_SOAP_XML: str = 'application/soap+xml'

// # protocol assignments (WSD spec/Section 2.4)
// WSD_UDP_PORT: int = 3702
pub const WSD_UDP_PORT: NonZeroU16 = NonZeroU16::new(3702).unwrap();
// WSD_HTTP_PORT: int = 5357
pub const WSD_HTTP_PORT: NonZeroU16 = NonZeroU16::new(5357).unwrap();
// WSD_MAX_LEN: int = 32767
pub const WSD_MAX_LEN: usize = 32767;

// WSDD_LISTEN_PORT = 5359

// # SOAP/UDP transmission constants
// MULTICAST_UDP_REPEAT: int = 4
pub const MULTICAST_UDP_REPEAT: usize = 4;
// UNICAST_UDP_REPEAT: int = 2
pub const UNICAST_UDP_REPEAT: usize = 2;
// UDP_MIN_DELAY: int = 50
pub const UDP_MIN_DELAY: u64 = 50;
// UDP_MAX_DELAY: int = 250
pub const UDP_MAX_DELAY: u64 = 250;
// UDP_UPPER_DELAY: int = 500
pub const UDP_UPPER_DELAY: u64 = 500;

// # servers must respond in 4 seconds after probe arrives
pub const PROBE_TIMEOUT: u128 = 4000;
// MAX_STARTUP_PROBE_DELAY: int = 3
pub const APP_MAX_DELAY: u64 = 500;
