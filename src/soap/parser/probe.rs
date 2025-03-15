use quick_xml::events::Event;
use quick_xml::name::Namespace;
use quick_xml::name::ResolveResult::Bound;
use quick_xml::reader::NsReader;
use thiserror::Error;
use tracing::{Level, event};

use crate::constants::{WSD_TYPE_DEVICE, XML_WSD_NAMESPACE};

type ParsedProbe = Result<(), ProbeParsingError>;

#[derive(Error, Debug)]
pub enum ProbeParsingError {
    #[error("Scopes are currently not supported: {0}")]
    ScopesUnsupported(String),
    #[error("Error parsing XML")]
    XmlError(#[from] quick_xml::errors::Error),
    #[error("Missing types")]
    MissingTypes,
    #[error("Unknown discovery type for probe: {0}")]
    UnknownTypes(String),
    #[error("Missing ./Probe in body")]
    MissingProbeElement,
}

fn parse_probe<'raw>(reader: &mut NsReader<&'raw [u8]>) -> ParsedProbe {
    let mut types = None;

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == XML_WSD_NAMESPACE.as_bytes() && e.name().local_name().as_ref() == b"Scopes"
                {
                    let raw_scopes = reader.read_text(e.to_end().name())?;

                    // THINK: send fault message (see p. 21 in WSD)
                    // I don't think this is correct?
                    // scopes MAYBE be ommitted...
                    event!(
                        Level::DEBUG,
                        scopes = &*raw_scopes,
                        "scopes unsupported, but probed"
                    );

                    return Err(ProbeParsingError::ScopesUnsupported(
                        raw_scopes.into_owned(),
                    ));
                } else if ns == XML_WSD_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"Types"
                {
                    types = Some(reader.read_text(e.to_end().name())?);
                }
            },
            (_, Event::Eof) => {
                break;
            },
            _ => (),
        }
    }

    let Some(types) = types else {
        event!(
            Level::DEBUG,
            "Probe message lacks wsd:Types element. Ignored."
        );

        return Err(ProbeParsingError::MissingTypes);
    };

    if types.trim() != WSD_TYPE_DEVICE {
        event!(
            Level::DEBUG,
            r#type = &*types,
            "unknown discovery type for probe"
        );

        return Err(ProbeParsingError::UnknownTypes(types.into_owned()));
    }

    Ok(())
}

/// This takes in a reader that is stopped at the body tag.
pub fn parse_probe_body<'raw>(reader: &mut NsReader<&'raw [u8]>) -> ParsedProbe {
    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == XML_WSD_NAMESPACE.as_bytes() && e.name().local_name().as_ref() == b"Probe"
                {
                    return parse_probe(reader);
                }
            },
            (_, Event::Eof) => {
                break;
            },
            _ => (),
        }
    }

    Err(ProbeParsingError::MissingProbeElement)
}
