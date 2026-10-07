use std::io::Read;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::soap::parser::app_sequence::AppSequence;
use crate::soap::parser::generic::{
    EndpointMetadata, extract_endpoint_metadata, require_metadata_version, require_valid_types,
};
use crate::wsd::device::DeviceUri;
use crate::xml::{XmlReader, find_child};

type ParsedHelloResult = Result<Hello, BodyParsingError>;

pub struct Hello {
    pub app_sequence: AppSequence,
    pub endpoint: DeviceUri,
    pub raw_xaddrs: Option<Box<str>>,
    pub metadata_version: u64,
}

/// This takes in a reader that is stopped at the body tag.
///
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
pub fn parse_hello<R>(reader: &mut XmlReader<R>, app_sequence: AppSequence) -> ParsedHelloResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "Hello")?;

    let EndpointMetadata {
        endpoint,
        raw_xaddrs,
        metadata_version,
        invalid_types,
    } = extract_endpoint_metadata(reader)?;

    let metadata_version = require_metadata_version(metadata_version)?;

    require_valid_types(invalid_types)?;

    Ok(Hello {
        app_sequence,
        endpoint,
        raw_xaddrs: raw_xaddrs.into_text(),
        metadata_version,
    })
}
