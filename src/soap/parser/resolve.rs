use std::io::BufReader;

use thiserror::Error;
use tracing::{Level, event};
use uuid::Uuid;
use xml::EventReader;
use xml::reader::XmlEvent;

use crate::constants::{XML_WSA_NAMESPACE, XML_WSD_NAMESPACE};
use crate::xml::{TextReadError, read_text};

type ParsedResolve = Result<(), ResolveParsingError>;

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
}

fn parse_resolve(reader: &mut EventReader<BufReader<&[u8]>>, target_uuid: Uuid) -> ParsedResolve {
    let mut addr = None;

    let mut resolve_depth = 0;
    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                resolve_depth += 1;

                if resolve_depth == 1
                    && name.namespace_ref() == Some(XML_WSA_NAMESPACE)
                    && name.local_name == "EndpointReference"
                {
                    let mut endpoint_reference_depth = 0;

                    loop {
                        match reader.next()? {
                            XmlEvent::StartElement { name, .. } => {
                                endpoint_reference_depth += 1;

                                if endpoint_reference_depth == 1
                                    && name.namespace_ref() == Some(XML_WSA_NAMESPACE)
                                    && name.local_name == "Address"
                                {
                                    addr = read_text(reader, name.borrow())?;

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
                            XmlEvent::StartDocument { .. }
                            | XmlEvent::EndDocument
                            | XmlEvent::ProcessingInstruction { .. }
                            | XmlEvent::CData(_)
                            | XmlEvent::Comment(_)
                            | XmlEvent::Characters(_)
                            | XmlEvent::Whitespace(_)
                            | XmlEvent::Doctype { .. } => (),
                        }
                    }
                }
            },
            XmlEvent::EndElement { .. } => {
                if resolve_depth == 0 {
                    // we've exited the EndpointReference Block
                    break;
                }
                resolve_depth -= 1;
            },
            XmlEvent::EndDocument => {
                break;
            },
            XmlEvent::StartDocument { .. }
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::CData(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Whitespace(_)
            | XmlEvent::Doctype { .. } => (),
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

    if addr.trim() != target_uuid.urn().to_string() {
        event!(
            Level::DEBUG,
            addr = &*addr,
            expected = target_uuid.urn().to_string(),
            "invalid resolve request: address does not match own one"
        );

        return Err(ResolveParsingError::AddressDoesntMatch);
    }

    Ok(())
}

/// This takes in a reader that is stopped at the body tag.
pub fn parse_resolve_body(
    reader: &mut EventReader<BufReader<&[u8]>>,
    target_uuid: Uuid,
) -> ParsedResolve {
    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if name.namespace_ref() == Some(XML_WSD_NAMESPACE) && name.local_name == "Resolve" {
                    return parse_resolve(reader, target_uuid);
                }
            },
            XmlEvent::EndDocument => {
                break;
            },
            XmlEvent::StartDocument { .. }
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::EndElement { .. }
            | XmlEvent::CData(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Whitespace(_)
            | XmlEvent::Doctype { .. } => (),
        }
    }

    // TODO error
    Err(ResolveParsingError::MissingResolveElement)
}
