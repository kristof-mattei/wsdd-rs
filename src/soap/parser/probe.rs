use thiserror::Error;
use tracing::{Level, event};
use xml::reader::XmlEvent;

use crate::constants::{PUB_COMPUTER, WSDP_TYPE_DEVICE, XML_WSD_NAMESPACE};
use crate::xml::{TextReadError, Wrapper, read_text};

type ParsedProbeResult = Result<bool, ProbeParsingError>;

#[derive(Error, Debug)]
pub enum ProbeParsingError {
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
    #[error("Error reading text")]
    TextReadError(#[from] TextReadError),
    #[error("Missing types")]
    MissingTypes,
    #[error("Missing ./Probe in body")]
    MissingProbeElement,
}

/// Expects a reader inside of the `Probe` tag
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`)
fn parse_probe(reader: &mut Wrapper<'_>) -> ParsedProbeResult {
    let mut types = None;

    let mut depth = 0_usize;
    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                depth += 1;

                if depth == 1 && name.namespace_ref() == Some(XML_WSD_NAMESPACE) {
                    match &*name.local_name {
                        "Scopes" => {
                            let text = read_text(reader)?;

                            let raw_scopes = text.unwrap_or_default();

                            event!(
                                Level::DEBUG,
                                scopes = &raw_scopes,
                                "ignoring unsupported scopes in probe request"
                            );

                            // read_text consumed the closing `Scopes`
                            depth -= 1;
                        },
                        "Types" => {
                            types = read_text(reader)?;

                            break;
                        },
                        _ => {},
                    }
                }
            },
            XmlEvent::EndElement { .. } => {
                if depth == 0 {
                    // we've exited the Probe
                    break;
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

    let Some(types) = types else {
        event!(
            Level::DEBUG,
            "Probe message lacks wsd:Types element. Ignored."
        );

        return Err(ProbeParsingError::MissingTypes);
    };

    // TODO make the types we support a HashSet stored once
    if !types
        .split_whitespace()
        .any(|requested_type| requested_type == WSDP_TYPE_DEVICE || requested_type == PUB_COMPUTER)
    {
        event!(
            Level::DEBUG,
            types = &*types,
            "client requests types we don't offer"
        );

        return Ok(false);
    }

    Ok(true)
}

/// This takes in a reader that is stopped at the body tag.
pub fn parse_probe_body(reader: &mut Wrapper<'_>) -> ParsedProbeResult {
    let mut depth = 0_usize;
    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                depth += 1;

                if depth == 1
                    && name.namespace_ref() == Some(XML_WSD_NAMESPACE)
                    && name.local_name == "Probe"
                {
                    return parse_probe(reader);
                }
            },
            XmlEvent::EndElement { .. } => {
                if depth == 0 {
                    return Err(ProbeParsingError::MissingProbeElement);
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

    Err(ProbeParsingError::MissingProbeElement)
}
