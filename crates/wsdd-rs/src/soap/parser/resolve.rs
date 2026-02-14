use std::io::Read;

use tracing::{Level, event};
use uuid::fmt::Urn;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::soap::parser::generic::extract_endpoint_reference_address;
use crate::xml::{Wrapper, find_child};

type ParsedResolveResult = Result<Resolve, BodyParsingError>;

pub struct Resolve {
    pub addr_urn: Urn,
}

/// This takes in a reader that is stopped at the body tag.
///
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
pub fn parse_resolve<R>(reader: &mut Wrapper<R>) -> ParsedResolveResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "Resolve")?;
    find_child(
        reader,
        Some(constants::XML_WSA_NAMESPACE),
        "EndpointReference",
    )?;

    let raw_addr = extract_endpoint_reference_address(reader)?;

    match raw_addr.parse::<Urn>() {
        Ok(addr_urn) => Ok(Resolve { addr_urn }),
        Err(error) => {
            event!(
                Level::DEBUG,
                addr = %raw_addr,
                "invalid resolve request: address is not a valid urn"
            );

            Err(BodyParsingError::InvalidUrnUuid(error))
        },
    }
}
