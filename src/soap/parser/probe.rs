use thiserror::Error;
use tracing::{Level, event};
use xml::reader::XmlEvent;

use crate::constants::{WSDP_TYPE_DEVICE, XML_WSD_NAMESPACE};
use crate::xml::{TextReadError, Wrapper, read_text};

type ParsedProbeResult = Result<(), ProbeParsingError>;

#[derive(Error, Debug)]
pub enum ProbeParsingError {
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
    #[error("Error reading text")]
    TextReadError(#[from] TextReadError),
    #[error("Missing types")]
    MissingTypes,
    #[error("Client probed for type(s) we don't offer: {0}")]
    TypesMismatch(Box<str>),
    #[error("Missing ./Probe in body")]
    MissingProbeElement,
}

fn parse_probe(reader: &mut Wrapper<'_>) -> ParsedProbeResult {
    let mut types = None;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if name.namespace_ref() == Some(XML_WSD_NAMESPACE) && name.local_name == "Scopes" {
                    let text = read_text(reader)?;

                    let raw_scopes = text.unwrap_or_default();

                    event!(
                        Level::DEBUG,
                        scopes = &raw_scopes,
                        "ignoring unsupported scopes in probe request"
                    );
                } else if name.namespace_ref() == Some(XML_WSD_NAMESPACE)
                    && name.local_name == "Types"
                {
                    types = read_text(reader)?;
                } else {
                    // Ignore
                }
            },
            XmlEvent::EndDocument => {
                break;
            },
            XmlEvent::CData(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::EndElement { .. }
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

    // TODO do we want to return the probes and make the host handle the different types
    // As it is the host responsible for defining the response
    if !types
        .split_whitespace()
        .any(|requested_type| requested_type == WSDP_TYPE_DEVICE)
    {
        event!(
            Level::DEBUG,
            types = &*types,
            "client requests types we don't offer"
        );

        return Err(ProbeParsingError::TypesMismatch(types.into_boxed_str()));
    }

    Ok(())
}

/// This takes in a reader that is stopped at the body tag.
pub fn parse_probe_body(reader: &mut Wrapper<'_>) -> ParsedProbeResult {
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
            XmlEvent::CData(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::EndElement { .. }
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
