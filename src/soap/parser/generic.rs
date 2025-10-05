use std::borrow::Cow;
use std::str::FromStr as _;

use quick_xml::NsReader;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::Namespace;
use quick_xml::name::ResolveResult::Bound;
use thiserror::Error;
use tracing::{Level, event};
use uuid::Uuid;
use uuid::fmt::Urn;

use crate::constants::{XML_WSA_NAMESPACE, XML_WSD_NAMESPACE};

#[derive(Error, Debug)]
pub enum GenericParsingError<'p> {
    #[error("Error parsing XML")]
    XmlError(#[from] quick_xml::errors::Error),
    #[error("Missing ./{0} in body")]
    MissingElement(Cow<'p, str>),
    #[error("Missing closing ./{0} in body")]
    MissingClosingElement(Cow<'p, str>),
    #[error("Invalid element order")]
    InvalidElementOrder,
    #[error("Invalid UUID")]
    InvalidUuid(#[from] uuid::Error),
}

pub fn extract_endpoint_reference_address<'raw>(
    reader: &mut NsReader<&'raw [u8]>,
) -> Result<Cow<'raw, str>, GenericParsingError<'static>> {
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
            "wsa:EndpointReference/wsa:Address".into(),
        ));
    };

    Ok(address)
}

pub fn extract_endpoint_metadata<'raw>(
    reader: &mut NsReader<&'raw [u8]>,
) -> Result<(Uuid, Option<Cow<'raw, str>>), GenericParsingError<'static>> {
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

        return Err(GenericParsingError::MissingElement(
            "wsa:EndpointReference".into(),
        ));
    };

    let endpoint = Urn::from_str(&endpoint)?.into_uuid();

    Ok((endpoint, xaddrs))
}

/// TODO expand to make sure what we search for is at the right depth
pub fn parse_generic_body<'full_path, 'namespace, 'path, 'reader>(
    reader: &'reader mut NsReader<&[u8]>,
    namespace: &'namespace str,
    path: &'path str,
) -> Result<(BytesStart<'reader>, usize), GenericParsingError<'full_path>>
where
    'full_path: 'path + 'namespace,
{
    let mut depth = 0_usize;

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(element)) => {
                depth += 1;

                if ns == namespace.as_bytes()
                    && element.name().local_name().as_ref() == path.as_bytes()
                {
                    return Ok((element, depth));
                }
            },
            (_, Event::Eof) => {
                break;
            },
            _ => {},
        }
    }

    Err(GenericParsingError::MissingElement(
        format!("{}:{}", namespace, path).into(),
    ))
}

pub fn parse_generic_body_paths<'full_path, 'namespace, 'path>(
    reader: &mut NsReader<&[u8]>,
    paths: &[(&'namespace str, &'path str)],
) -> Result<usize, GenericParsingError<'full_path>>
where
    'full_path: 'path + 'namespace,
{
    parse_generic_body_paths_recursive(reader, paths, 0)
}

fn parse_generic_body_paths_recursive<'full_path, 'namespace, 'path>(
    reader: &mut NsReader<&[u8]>,
    paths: &[(&'namespace str, &'path str)],
    mut depth: usize,
) -> Result<usize, GenericParsingError<'full_path>>
where
    'full_path: 'path + 'namespace,
{
    let [(namespace, path), ref rest @ ..] = *paths else {
        return Ok(depth);
    };

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                depth += 1;

                if ns == namespace.as_bytes() && e.name().local_name().as_ref() == path.as_bytes() {
                    return parse_generic_body_paths_recursive(reader, rest, depth);
                }
            },
            (Bound(Namespace(_)), Event::Empty(_)) => {
                depth -= 1;
            },
            (_, Event::Eof) => {
                break;
            },
            _ => (),
        }
    }

    Err(GenericParsingError::MissingElement(
        format!("{}:{}", namespace, path).into(),
    ))
}
