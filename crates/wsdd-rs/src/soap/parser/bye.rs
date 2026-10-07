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

    let EndpointMetadata {
        endpoint,
        metadata_version,
        ..
    } = extract_endpoint_metadata(reader)?;

    // optional in `ByeType` (documentation/ws-discovery.pdf, Appendix II), but a present one must be valid
    if let Some(Err(text)) = metadata_version {
        return Err(BodyParsingError::InvalidMetadataVersion(text));
    }

    Ok(Bye {
        app_sequence,
        endpoint,
    })
}
