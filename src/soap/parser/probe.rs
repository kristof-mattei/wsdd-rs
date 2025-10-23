use std::io::BufReader;

use thiserror::Error;
use tracing::{Level, event};
use xml::EventReader;
use xml::reader::XmlEvent;

use crate::constants::{WSDP_TYPE_DEVICE, XML_WSD_NAMESPACE};
use crate::xml::{TextReadError, read_text};

type ParsedProbeResult = Result<(), ProbeParsingError>;

#[derive(Error, Debug)]
pub enum ProbeParsingError {
    #[error("Scopes are currently not supported: {0}")]
    ScopesUnsupported(Box<str>),
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
    #[error("Error reading text")]
    TextReadError(#[from] TextReadError),
    #[error("Missing types")]
    MissingTypes,
    #[error("Unknown discovery type for probe: {0}")]
    UnknownTypes(Box<str>),
    #[error("Missing ./Probe in body")]
    MissingProbeElement,
}

fn parse_probe(reader: &mut EventReader<BufReader<&[u8]>>) -> ParsedProbeResult {
    let mut types = None;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if name.namespace_ref() == Some(XML_WSD_NAMESPACE) && name.local_name == "Scopes" {
                    let text = read_text(reader, name.borrow())?;

                    let raw_scopes = text.unwrap_or_default();

                    // TODO: THINK: send fault message (see p. 21 in WSD)
                    // I don't think this is correct?
                    // scopes MAYBE be ommitted...
                    event!(
                        Level::DEBUG,
                        scopes = &raw_scopes,
                        "scopes unsupported, but probed"
                    );

                    return Err(ProbeParsingError::ScopesUnsupported(
                        raw_scopes.into_boxed_str(),
                    ));
                } else if name.namespace_ref() == Some(XML_WSD_NAMESPACE)
                    && name.local_name == "Types"
                {
                    types = read_text(reader, name.borrow())?;
                } else {
                    // Ignore
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

    let Some(types) = types else {
        event!(
            Level::DEBUG,
            "Probe message lacks wsd:Types element. Ignored."
        );

        return Err(ProbeParsingError::MissingTypes);
    };

    // TODO do we want to return the probes and make the host handle the different types
    // As it is the host responsible for defining the response
    if types.trim() != WSDP_TYPE_DEVICE {
        event!(
            Level::DEBUG,
            r#type = &*types,
            "unknown discovery type for probe"
        );

        return Err(ProbeParsingError::UnknownTypes(types.into_boxed_str()));
    }

    Ok(())
}

/// This takes in a reader that is stopped at the body tag.
pub fn parse_probe_body(reader: &mut EventReader<BufReader<&[u8]>>) -> ParsedProbeResult {
    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if name.namespace_ref() == Some(XML_WSD_NAMESPACE) && name.local_name == "Probe" {
                    return parse_probe(reader);
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

    Err(ProbeParsingError::MissingProbeElement)
}
