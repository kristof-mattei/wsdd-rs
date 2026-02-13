use std::io::Read;

use crate::constants;
use crate::soap::parser::generic::extract_endpoint_metadata;
use crate::wsd::device::DeviceUri;
use crate::xml::{GenericParsingError, Wrapper, find_child};

type ParsedHelloResult = Result<Hello, GenericParsingError>;

pub struct Hello {
    pub endpoint: DeviceUri,
    pub raw_xaddrs: Option<Box<str>>,
}

/// This takes in a reader that is stopped at the body tag.
///
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
pub fn parse_hello<R>(reader: &mut Wrapper<R>) -> ParsedHelloResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "Hello")?;

    let (endpoint, raw_xaddrs) = extract_endpoint_metadata(reader)?;

    Ok(Hello {
        endpoint,
        raw_xaddrs,
    })
}
