use thiserror::Error;
use tracing::{Level, event};
use xml::reader::XmlEvent;

use crate::constants::{XML_PUB_NAMESPACE, XML_WSD_NAMESPACE, XML_WSDP_NAMESPACE};
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
    let mut types_and_namespace = None;

    let mut depth = 0_usize;
    loop {
        match reader.next()? {
            XmlEvent::StartElement {
                name, namespace, ..
            } => {
                depth += 1;

                if depth == 1 && name.namespace_ref() == Some(XML_WSD_NAMESPACE) {
                    match &*name.local_name {
                        "Scopes" => {
                            let text = read_text(reader)?;

                            let raw_scopes = text.unwrap_or_default();

                            event!(
                                Level::DEBUG,
                                scopes = %raw_scopes,
                                "Ignoring unsupported scopes in probe request"
                            );

                            // read_text consumed the closing `Scopes`
                            depth -= 1;
                        },
                        "Types" => {
                            types_and_namespace = read_text(reader)?.map(|text| (text, namespace));

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

    let Some((types, namespace)) = types_and_namespace else {
        event!(
            Level::DEBUG,
            "Probe message lacks wsd:Types element. Ignored."
        );

        return Err(ProbeParsingError::MissingTypes);
    };

    let requested_type_match = {
        let mut requested_type_match = false;

        for r#type in types.split_whitespace() {
            // split
            let Some((prefix, name)) = r#type.split_once(':') else {
                continue;
            };

            match name {
                "Device" => {
                    if namespace.get(prefix) == Some(XML_WSDP_NAMESPACE) {
                        requested_type_match = true;
                        break;
                    }
                },

                "Computer" => {
                    if namespace.get(prefix) == Some(XML_PUB_NAMESPACE) {
                        requested_type_match = true;
                        break;
                    }
                },
                _ => {
                    continue;
                },
            }
        }

        requested_type_match
    };

    if !requested_type_match {
        event!(
            Level::DEBUG,
            %types,
            "client requests types we don't offer"
        );

        return Ok(false);
    }

    Ok(true)
}

/// This takes in a reader that is stopped at the body tag.
///
/// Returns
/// * `Ok(true)`: when we offer the `wsd:Types` requested
/// * `Ok(false)`: when we do not offer the `wsd:Types` requested
/// * `Err(_)`: Anything went wrong trying to parse the XML
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
