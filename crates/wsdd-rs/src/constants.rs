use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU16;
use std::time::Duration;

use const_str::format as const_format;

use crate::soap::PrefixedName;

pub(crate) const WSA_URI: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
pub(crate) const WSD_URI: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
pub(crate) const WSDP_URI: &str = "http://schemas.xmlsoap.org/ws/2006/02/devprof";

pub(crate) const XML_SOAP_NAMESPACE: &str = "http://www.w3.org/2003/05/soap-envelope";
pub(crate) const XML_WSA_NAMESPACE: &str = WSA_URI;
pub(crate) const XML_WSD_NAMESPACE: &str = WSD_URI;
pub(crate) const XML_WSX_NAMESPACE: &str = "http://schemas.xmlsoap.org/ws/2004/09/mex";
pub(crate) const XML_WSDP_NAMESPACE: &str = WSDP_URI;
pub(crate) const XML_PNPX_NAMESPACE: &str = "http://schemas.microsoft.com/windows/pnpx/2005/10";
pub(crate) const XML_PUB_NAMESPACE: &str = "http://schemas.microsoft.com/windows/pub/2005/07";

pub(crate) const WSD_MAX_KNOWN_MESSAGES: usize = 10;

pub(crate) const WSD_PROBE: &str = const_format!("{}{}", WSD_URI, "/Probe");
pub(crate) const WSD_PROBE_MATCH: &str = const_format!("{}{}", WSD_URI, "/ProbeMatches");
pub(crate) const WSD_RESOLVE: &str = const_format!("{}{}", WSD_URI, "/Resolve");
pub(crate) const WSD_RESOLVE_MATCH: &str = const_format!("{}{}", WSD_URI, "/ResolveMatches");
pub(crate) const WSD_HELLO: &str = const_format!("{}{}", WSD_URI, "/Hello");
pub(crate) const WSD_BYE: &str = const_format!("{}{}", WSD_URI, "/Bye");
pub(crate) const WSD_GET: &str = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get";
pub(crate) const WSD_GET_RESPONSE: &str =
    "http://schemas.xmlsoap.org/ws/2004/09/transfer/GetResponse";

pub(crate) const WSDP_THIS_DEVICE: &str = "ThisDevice";
pub(crate) const WSDP_THIS_DEVICE_DIALECT: &str =
    const_format!("{}/{}", WSDP_URI, WSDP_THIS_DEVICE);
pub(crate) const WSDP_THIS_MODEL: &str = "ThisModel";
pub(crate) const WSDP_THIS_MODEL_DIALECT: &str = const_format!("{}/{}", WSDP_URI, WSDP_THIS_MODEL);
pub(crate) const WSDP_RELATIONSHIP: &str = "Relationship";
pub(crate) const WSDP_RELATIONSHIP_DIALECT: &str =
    const_format!("{}/{}", WSDP_URI, WSDP_RELATIONSHIP);
pub(crate) const WSDP_RELATIONSHIP_HOST: &str = "host";
pub(crate) const WSDP_RELATIONSHIP_TYPE_HOST: &str =
    const_format!("{}/{}", WSDP_URI, WSDP_RELATIONSHIP_HOST);

pub(crate) const WSDP_DEVICE: PrefixedName = PrefixedName {
    prefix: "wsdp",
    namespace: XML_WSDP_NAMESPACE,
    local_name: "Device",
};

pub(crate) const PUB_COMPUTER: PrefixedName = PrefixedName {
    prefix: "pub",
    namespace: XML_PUB_NAMESPACE,
    local_name: "Computer",
};

/// The Types of this Target Service, see documentation/ws-discovery.pdf, Section 4.1.
pub(crate) const ADVERTISED_TYPES: [PrefixedName; 2] = [WSDP_DEVICE, PUB_COMPUTER];

pub(crate) const WSD_MCAST_GRP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
pub(crate) const WSD_MCAST_GRP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xc);

pub(crate) const WSA_ANON: &str = const_format!("{}{}", WSA_URI, "/role/anonymous");

pub(crate) const WSA_DISCOVERY: &str = "urn:schemas-xmlsoap-org:ws:2005:04:discovery";

pub(crate) const MIME_TYPE_SOAP_XML: &str = "application/soap+xml";

// See documentation/ws-discovery.pdf, 2.4 Protocol Assignments
pub(crate) const WSD_UDP_PORT: NonZeroU16 = NonZeroU16::new(3702).unwrap();
pub(crate) const WSD_HTTP_PORT: NonZeroU16 = NonZeroU16::new(5357).unwrap();

#[expect(
    clippy::decimal_literal_representation,
    reason = "Copied from original source code"
)]
pub(crate) const WSD_MAX_LEN: usize = 32767;

// SOAP/UDP transmission constants
// See Appendix I (non-normative) – Example retransmission in documentation/soap-over-udp.pdf
pub(crate) const MULTICAST_UDP_REPEAT: usize = 4;
pub(crate) const UNICAST_UDP_REPEAT: usize = 2;
pub(crate) const UDP_MIN_DELAY: Duration = Duration::from_millis(50);
pub(crate) const UDP_MAX_DELAY: Duration = Duration::from_millis(250);
pub(crate) const UDP_UPPER_DELAY: Duration = Duration::from_millis(500);

// See documentation/ws-discovery.pdf, 2.4 Protocol Assignments, Table 4
pub(crate) const APP_MAX_DELAY: Duration = Duration::from_millis(500);

// See documentation/ws-discovery.pdf, 7. Security Model, Table 8
pub(crate) const MATCH_TIMEOUT: Duration = APP_MAX_DELAY.saturating_add(Duration::from_millis(100));

// A sane default for the size of text inside an XML element
pub(crate) const STRING_DEFAULT_CAPACITY: usize = 128;
