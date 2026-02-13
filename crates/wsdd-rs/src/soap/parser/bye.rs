use std::io::Read;

use crate::constants;
use crate::soap::parser::generic::extract_endpoint_metadata;
use crate::wsd::device::DeviceUri;
use crate::xml::{GenericParsingError, Wrapper, find_child};

type ParsedByeResult = Result<Bye, GenericParsingError>;

pub struct Bye {
    pub endpoint: DeviceUri,
}

/// This takes in a reader that is stopped at the body tag.
///
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
pub fn parse_bye<R>(reader: &mut Wrapper<R>) -> ParsedByeResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "Bye")?;

    let (endpoint, _) = extract_endpoint_metadata(reader)?;

    Ok(Bye { endpoint })
}
