use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::time::Duration;

use const_str::format as const_format;

pub const WSA_URI: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
pub const WSD_URI: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
pub const WSDP_URI: &str = "http://schemas.xmlsoap.org/ws/2006/02/devprof";

pub const XML_SOAP_NAMESPACE: &str = "http://www.w3.org/2003/05/soap-envelope";
pub const XML_WSA_NAMESPACE: &str = WSA_URI;
pub const XML_WSD_NAMESPACE: &str = WSD_URI;
pub const XML_WSX_NAMESPACE: &str = "http://schemas.xmlsoap.org/ws/2004/09/mex";
pub const XML_WSDP_NAMESPACE: &str = WSDP_URI;
pub const XML_PNPX_NAMESPACE: &str = "http://schemas.microsoft.com/windows/pnpx/2005/10";
pub const XML_PUB_NAMESPACE: &str = "http://schemas.microsoft.com/windows/pub/2005/07";

pub const WSD_MAX_KNOWN_MESSAGES: usize = 10;

pub const WSD_PROBE: &str = const_format!("{}{}", WSD_URI, "/Probe");
pub const WSD_PROBE_MATCH: &str = const_format!("{}{}", WSD_URI, "/ProbeMatches");
pub const WSD_RESOLVE: &str = const_format!("{}{}", WSD_URI, "/Resolve");
pub const WSD_RESOLVE_MATCH: &str = const_format!("{}{}", WSD_URI, "/ResolveMatches");
pub const WSD_HELLO: &str = const_format!("{}{}", WSD_URI, "/Hello");
pub const WSD_BYE: &str = const_format!("{}{}", WSD_URI, "/Bye");
pub const WSD_GET: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";
pub const WSD_GET_RESPONSE: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse";

pub const WSDP_THIS_DEVICE: &str = "ThisDevice";
pub const WSDP_THIS_DEVICE_DIALECT: &str = const_format!("{}/{}", WSDP_URI, WSDP_THIS_DEVICE);
pub const WSDP_THIS_MODEL: &str = "ThisModel";
pub const WSDP_THIS_MODEL_DIALECT: &str = const_format!("{}/{}", WSDP_URI, WSDP_THIS_MODEL);
pub const WSDP_RELATIONSHIP: &str = "Relationship";
pub const WSDP_RELATIONSHIP_DIALECT: &str = const_format!("{}/{}", WSDP_URI, WSDP_RELATIONSHIP);
pub const WSDP_RELATIONSHIP_HOST: &str = "host";
pub const WSDP_RELATIONSHIP_TYPE_HOST: &str =
    const_format!("{}/{}", WSDP_URI, WSDP_RELATIONSHIP_HOST);

pub const WSDP_TYPE_DEVICE: &str = "wsdp:Device";
pub const PUB_COMPUTER: &str = "pub:Computer";
pub const WSDP_TYPE_DEVICE_COMPUTER: &str = const_format!("{} {}", WSDP_TYPE_DEVICE, PUB_COMPUTER);

pub const WSD_MCAST_GRP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
pub const WSD_MCAST_GRP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xc);

pub const WSA_ANON: &str = const_format!("{}{}", WSA_URI, "/role/anonymous");

pub const WSA_DISCOVERY: &str = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";

pub const MIME_TYPE_SOAP_XML: &str = "application/soap+xml";

// See documentation/ws-discovery.pdf, 2.4 Protocol Assignments
pub const WSD_UDP_PORT: NonZeroU16 = NonZeroU16::new(3702).unwrap();
pub const WSD_HTTP_PORT: NonZeroU16 = NonZeroU16::new(5357).unwrap();

#[expect(
    clippy::decimal_literal_representation,
    reason = "Copied from original source code"
)]
pub const WSD_MAX_LEN: usize = 32767;

// SOAP/UDP transmission constants
// See Appendix I (non-normative) – Example retransmission in documentation/soap-over-udp.pdf
pub const MULTICAST_UDP_REPEAT: usize = 4;
pub const UNICAST_UDP_REPEAT: usize = 2;
pub const UDP_MIN_DELAY: Duration = Duration::from_millis(50);
pub const UDP_MAX_DELAY: Duration = Duration::from_millis(250);
pub const UDP_UPPER_DELAY: Duration = Duration::from_millis(500);

// See documentation/ws-discovery.pdf, 2.4 Protocol Assignments, Table 4
pub const APP_MAX_DELAY: Duration = Duration::from_millis(500);

// See documentation/ws-discovery.pdf, 7. Security Model, Table 8
pub const MATCH_TIMEOUT: Duration = APP_MAX_DELAY.saturating_add(Duration::from_millis(100));

// A sane default for the size of text inside an XML element
pub const STRING_DEFAULT_CAPACITY: usize = 128;
