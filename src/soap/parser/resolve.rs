use quick_xml::events::Event;
use quick_xml::name::ResolveResult::Bound;
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::reader::NsReader;
use thiserror::Error;
use tracing::{Level, event};
use uuid::Uuid;

use crate::constants::{XML_WSA_NAMESPACE, XML_WSD_NAMESPACE};
type ParsedResolve = Result<(), ResolveParsingError>;

#[derive(Error, Debug)]
pub enum ResolveParsingError {
    #[error("Error parsing XML")]
    XmlError(#[from] quick_xml::errors::Error),
    #[error("Missing ./Resolve in body")]
    MissingProbeElement,
    #[error("invalid resolve request: missing endpoint address")]
    MissingEndpoint,
    #[error("invalid resolve request: address does not match own one")]
    AddressDoesntMatch,
}

fn parse_resolve<'raw>(reader: &mut NsReader<&'raw [u8]>, target_uuid: Uuid) -> ParsedResolve {
    let mut addr = None;

    let mut resolve_depth = 0;
    loop {
        match reader.read_resolved_event()? {
            (ns, Event::Start(e)) => {
                resolve_depth += 1;

                if resolve_depth == 1
                    && ns == ResolveResult::Bound(Namespace(const { XML_WSA_NAMESPACE.as_bytes() }))
                    && e.name().local_name().as_ref() == b"EndpointReference"
                {
                    let mut endpoint_reference_depth = 0;

                    loop {
                        match reader.read_resolved_event()? {
                            (Bound(Namespace(ns)), Event::Start(e)) => {
                                endpoint_reference_depth += 1;

                                if endpoint_reference_depth == 1
                                    && ns == XML_WSA_NAMESPACE.as_bytes()
                                    && e.name().local_name().as_ref() == b"Address"
                                {
                                    addr = Some(reader.read_text(e.to_end().name())?);

                                    break;
                                }
                            },
                            (_, Event::Start(_)) => {
                                endpoint_reference_depth += 1;
                            },
                            (_, Event::End(_)) => {
                                if endpoint_reference_depth == 0 {
                                    // we've exited the EndpointReference Block
                                    break;
                                }
                                endpoint_reference_depth -= 1;
                            },
                            _ => (),
                        }
                    }
                }
            },
            (_, Event::End(_)) => {
                if resolve_depth == 0 {
                    // we've exited the EndpointReference Block
                    break;
                }
                resolve_depth -= 1;
            },
            (_, Event::Eof) => {
                break;
            },
            _ => (),
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
pub fn parse_resolve_body<'raw>(
    reader: &mut NsReader<&'raw [u8]>,
    target_uuid: Uuid,
) -> ParsedResolve {
    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == XML_WSD_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"Resolve"
                {
                    return parse_resolve(reader, target_uuid);
                }
            },
            (_, Event::Eof) => {
                break;
            },
            _ => (),
        }
    }

    // TODO error
    Err(ResolveParsingError::MissingProbeElement)
}
