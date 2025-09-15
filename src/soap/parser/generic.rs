use std::borrow::Cow;
use std::str::FromStr as _;

use quick_xml::NsReader;
use quick_xml::events::Event;
use quick_xml::name::Namespace;
use quick_xml::name::ResolveResult::Bound;
use thiserror::Error;
use tracing::{Level, event};
use uuid::Uuid;
use uuid::fmt::Urn;

use crate::constants::{XML_WSA_NAMESPACE, XML_WSD_NAMESPACE};

#[derive(Error, Debug)]
pub enum GenericParsingError<'e> {
    #[error("Error parsing XML")]
    XmlError(#[from] quick_xml::errors::Error),
    #[error("Missing ./{0} in body")]
    MissingElement(&'e str),
    #[error("Invalid element order")]
    InvalidElementOrder,
    #[error("Invalid UUID")]
    InvalidUuid(#[from] uuid::Error),
}

pub fn extract_endpoint_reference_address<'raw, 'error>(
    reader: &mut NsReader<&'raw [u8]>,
) -> Result<Cow<'raw, str>, GenericParsingError<'error>> {
    let mut address = None;

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == XML_WSA_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"Address"
                {
                    address = Some(reader.read_text(e.to_end().name())?);
                }
            },
            (Bound(Namespace(ns)), Event::End(e)) => {
                if ns == XML_WSA_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"EndpointReference"
                {
                    break;
                }
            },
            _ => (),
        }
    }

    let Some(address) = address else {
        event!(
            Level::DEBUG,
            "Missing wsa:EndpointReference/wsa:Address element. Ignored."
        );

        return Err(GenericParsingError::MissingElement(
            "wsa:EndpointReference/wsa:Address",
        ));
    };

    Ok(address)
}

pub fn extract_endpoint_metadata<'raw, 'error>(
    reader: &mut NsReader<&'raw [u8]>,
) -> Result<(Uuid, Option<Cow<'raw, str>>), GenericParsingError<'error>> {
    let mut endpoint = None;
    let mut xaddrs = None;

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == XML_WSA_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"EndpointReference"
                {
                    if endpoint.is_some() || xaddrs.is_some() {
                        return Err(GenericParsingError::InvalidElementOrder);
                    }
                    endpoint = Some(extract_endpoint_reference_address(reader)?);
                } else if ns == XML_WSD_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"XAddrs"
                {
                    if endpoint.is_none() || xaddrs.is_some() {
                        return Err(GenericParsingError::InvalidElementOrder);
                    }
                    xaddrs = Some(reader.read_text(e.to_end().name())?);

                    // stop for another function to continue reading
                    break;
                } else {
                    // Ignore
                }
            },
            (_, Event::Eof) => {
                break;
            },
            _ => (),
        }
    }

    let Some(endpoint) = endpoint else {
        event!(
            Level::DEBUG,
            "Missing wsa:EndpointReference element. Ignored."
        );

        return Err(GenericParsingError::MissingElement("wsa:EndpointReference"));
    };

    let endpoint = Urn::from_str(&endpoint)?.into_uuid();

    Ok((endpoint, xaddrs))
}

pub fn parse_generic_body<'path>(
    reader: &mut NsReader<&[u8]>,
    path: &'path str,
) -> Result<(), GenericParsingError<'path>> {
    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == XML_WSD_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == path.as_bytes()
                {
                    return Ok(());
                }
            },
            (_, Event::Eof) => {
                break;
            },
            _ => (),
        }
    }

    Err(GenericParsingError::MissingElement(path))
}

pub fn parse_generic_body_paths<'path>(
    reader: &mut NsReader<&[u8]>,
    paths: &[&'path str],
) -> Result<(), GenericParsingError<'path>> {
    let [first, ref rest @ ..] = *paths else {
        return Ok(());
    };

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == XML_WSD_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == first.as_bytes()
                {
                    return parse_generic_body_paths(reader, rest);
                }
            },
            (_, Event::Eof) => {
                break;
            },
            _ => (),
        }
    }

    Err(GenericParsingError::MissingElement(first))
}
