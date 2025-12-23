use thiserror::Error;
use tracing::{Level, event};
use uuid::Uuid;
use uuid::fmt::Urn;
use xml::reader::XmlEvent;

use crate::constants::{XML_WSA_NAMESPACE, XML_WSD_NAMESPACE};
use crate::xml::{TextReadError, Wrapper, read_text};

type ParsedResolveResult = Result<(), ResolveParsingError>;

#[derive(Error, Debug)]
pub enum ResolveParsingError {
    #[error("Error reading text")]
    TextReadError(#[from] TextReadError),
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
    #[error("Missing ./Resolve in body")]
    MissingResolveElement,
    #[error("invalid resolve request: missing endpoint address")]
    MissingEndpoint,
    #[error("invalid resolve request: address does not match own one")]
    AddressDoesntMatch,
    #[error("invalid resolve request: address is not a valid urn")]
    EndpointNotAValidUrn,
}

/// Expects a reader inside of the `Resolve` tag
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`)
fn parse_resolve(reader: &mut Wrapper<'_>, target_uuid: Uuid) -> ParsedResolveResult {
    let mut addr = None;

    let mut resolve_depth = 0_usize;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                resolve_depth += 1;

                if resolve_depth == 1
                    && name.namespace_ref() == Some(XML_WSA_NAMESPACE)
                    && name.local_name == "EndpointReference"
                {
                    let mut endpoint_reference_depth = 0_usize;

                    loop {
                        match reader.next()? {
                            XmlEvent::StartElement { name, .. } => {
                                endpoint_reference_depth += 1;

                                if endpoint_reference_depth == 1
                                    && name.namespace_ref() == Some(XML_WSA_NAMESPACE)
                                    && name.local_name == "Address"
                                {
                                    addr = read_text(reader)?;

                                    break;
                                }
                            },
                            XmlEvent::EndElement { .. } => {
                                if endpoint_reference_depth == 0 {
                                    // we've exited the EndpointReference Block
                                    break;
                                }

                                endpoint_reference_depth -= 1;
                            },
                            XmlEvent::CData(_)
                            | XmlEvent::Characters(_)
                            | XmlEvent::Comment(_)
                            | XmlEvent::Doctype { .. }
                            | XmlEvent::EndDocument
                            | XmlEvent::ProcessingInstruction { .. }
                            | XmlEvent::StartDocument { .. }
                            | XmlEvent::Whitespace(_) => {
                                // these events are squelched by the parser config, or they're valid, but we ignore them
                                // or they just won't occur
                            },
                        }
                    }
                }
            },
            XmlEvent::EndElement { .. } => {
                if resolve_depth == 0 {
                    // we've exited the Resolve
                    break;
                }

                resolve_depth -= 1;
            },
            XmlEvent::EndDocument => {
                break;
            },
            XmlEvent::CData(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::StartDocument { .. }
            | XmlEvent::Whitespace(_) => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
        }
    }

    let Some(addr) = addr else {
        event!(
            Level::DEBUG,
            "invalid resolve request: missing endpoint address"
        );

        // TODO error
        return Err(ResolveParsingError::MissingEndpoint);
    };

    let Ok(addr_urn) = addr.parse::<Urn>() else {
        event!(
            Level::DEBUG,
            addr = &*addr,
            "invalid resolve request: address is not a valid urn"
        );

        return Err(ResolveParsingError::EndpointNotAValidUrn);
    };

    if addr_urn != target_uuid.urn() {
        event!(
            Level::DEBUG,
            addr = &*addr,
            expected = %target_uuid.urn(),
            "invalid resolve request: address does not match own one"
        );

        return Err(ResolveParsingError::AddressDoesntMatch);
    }

    Ok(())
}

/// This takes in a reader that is stopped at the body tag.
pub fn parse_resolve_body(reader: &mut Wrapper<'_>, target_uuid: Uuid) -> ParsedResolveResult {
    let mut depth = 0_usize;
    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                depth += 1;

                if depth == 1
                    && name.namespace_ref() == Some(XML_WSD_NAMESPACE)
                    && name.local_name == "Resolve"
                {
                    return parse_resolve(reader, target_uuid);
                }
            },
            XmlEvent::EndElement { .. } => {
                if depth == 0 {
                    return Err(ResolveParsingError::MissingResolveElement);
                }

                depth -= 1;
            },
            XmlEvent::EndDocument => {
                break;
            },
            XmlEvent::CData(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::StartDocument { .. }
            | XmlEvent::Whitespace(_) => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
        }
    }

    // TODO error
    Err(ResolveParsingError::MissingResolveElement)
}
