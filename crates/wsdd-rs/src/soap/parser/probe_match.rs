use std::io::Read;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::soap::parser::generic::extract_endpoint_metadata;
use crate::wsd::device::DeviceUri;
use crate::xml::{Wrapper, find_child};

type ParsedProbeMatchResult = Result<ProbeMatch, BodyParsingError>;

pub struct ProbeMatch {
    pub endpoint: DeviceUri,
    pub raw_xaddrs: Option<Box<str>>,
}

/// This takes in a reader that is stopped at the body tag.
///
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
pub fn parse_probe_match<R>(reader: &mut Wrapper<R>) -> ParsedProbeMatchResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "ProbeMatches")?;
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "ProbeMatch")?;

    let (endpoint, raw_xaddrs) = extract_endpoint_metadata(reader)?;

    Ok(ProbeMatch {
        endpoint,
        raw_xaddrs,
    })
}
