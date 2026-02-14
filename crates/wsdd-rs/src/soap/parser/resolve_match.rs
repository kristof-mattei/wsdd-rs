use std::io::Read;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::soap::parser::generic::extract_endpoint_metadata;
use crate::wsd::device::DeviceUri;
use crate::xml::{Wrapper, find_child};

type ParsedResolveMatchResult = Result<ResolveMatch, BodyParsingError>;

pub struct ResolveMatch {
    pub endpoint: DeviceUri,
    pub raw_xaddrs: Option<Box<str>>,
}

/// This takes in a reader that is stopped at the body tag.
///
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
pub fn parse_resolve_match<R>(reader: &mut Wrapper<R>) -> ParsedResolveMatchResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "ResolveMatches")?;
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "ResolveMatch")?;

    let (endpoint, raw_xaddrs) = extract_endpoint_metadata(reader)?;

    Ok(ResolveMatch {
        endpoint,
        raw_xaddrs,
    })
}
