use std::io::Read;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::soap::parser::app_sequence::AppSequence;
use crate::soap::parser::generic::{EndpointMetadata, extract_endpoint_metadata};
use crate::wsd::device::DeviceUri;
use crate::xml::{XmlReader, find_child};

type ParsedByeResult = Result<Bye, BodyParsingError>;

pub struct Bye {
    pub app_sequence: AppSequence,
    pub endpoint: DeviceUri,
}

/// This takes in a reader that is stopped at the body tag.
///
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
pub fn parse_bye<R>(reader: &mut XmlReader<R>, app_sequence: AppSequence) -> ParsedByeResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "Bye")?;

    let EndpointMetadata { endpoint, .. } = extract_endpoint_metadata(reader)?;

    Ok(Bye {
        app_sequence,
        endpoint,
    })
}
