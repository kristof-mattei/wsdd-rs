use std::borrow::Cow;
use std::io::BufReader;
use std::str::FromStr as _;

use thiserror::Error;
use tracing::{Level, event};
use uuid::Uuid;
use uuid::fmt::Urn;
use xml::EventReader;
use xml::attribute::OwnedAttribute;
use xml::name::OwnedName;
use xml::reader::XmlEvent;

use crate::constants::{XML_WSA_NAMESPACE, XML_WSD_NAMESPACE};
use crate::xml::{TextReadError, read_text};

#[derive(Error, Debug)]
pub enum GenericParsingError<'p> {
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
    #[error("Error reading text")]
    TextReadError(#[from] TextReadError),
    #[error("Missing ./{0} in body")]
    MissingElement(Cow<'p, str>),
    #[error("Missing closing ./{0} in body")]
    MissingClosingElement(Cow<'p, str>),
    #[error("Invalid element order")]
    InvalidElementOrder,
    #[error("Invalid UUID")]
    InvalidUuid(#[from] uuid::Error),
}

pub fn extract_endpoint_reference_address(
    reader: &mut EventReader<BufReader<&[u8]>>,
) -> Result<Box<str>, GenericParsingError<'static>> {
    let mut address = None;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if name.namespace_ref() == Some(XML_WSA_NAMESPACE) && name.local_name == "Address" {
                    address = read_text(reader, name.borrow())?;
                }
            },
            XmlEvent::EndElement { name, .. } => {
                if name.namespace_ref() == Some(XML_WSA_NAMESPACE)
                    && name.local_name == "EndpointReference"
                {
                    break;
                }
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

    let Some(address) = address else {
        event!(
            Level::DEBUG,
            "Missing wsa:EndpointReference/wsa:Address element. Ignored."
        );

        return Err(GenericParsingError::MissingElement(
            "wsa:EndpointReference/wsa:Address".into(),
        ));
    };

    Ok(address.into_boxed_str())
}

pub fn extract_endpoint_metadata(
    reader: &mut EventReader<BufReader<&[u8]>>,
) -> Result<(Uuid, Option<Box<str>>), GenericParsingError<'static>> {
    let mut endpoint = None;
    let mut xaddrs = None;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if name.namespace_ref() == Some(XML_WSA_NAMESPACE)
                    && name.local_name == "EndpointReference"
                {
                    if endpoint.is_some() || xaddrs.is_some() {
                        return Err(GenericParsingError::InvalidElementOrder);
                    }
                    endpoint = Some(extract_endpoint_reference_address(reader)?);
                } else if name.namespace_ref() == Some(XML_WSD_NAMESPACE)
                    && name.local_name == "XAddrs"
                {
                    if endpoint.is_none() || xaddrs.is_some() {
                        return Err(GenericParsingError::InvalidElementOrder);
                    }
                    xaddrs = read_text(reader, name.borrow())?;

                    // stop for another function to continue reading
                    break;
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

    Ok((endpoint, xaddrs.map(String::into_boxed_str)))
}

/// TODO expand to make sure what we search for is at the right depth
pub fn parse_generic_body<'full_path, 'namespace, 'path, 'reader>(
    reader: &'reader mut EventReader<BufReader<&[u8]>>,
    namespace: &'namespace str,
    path: &'path str,
) -> Result<(OwnedName, Vec<OwnedAttribute>, usize), GenericParsingError<'full_path>>
where
    'full_path: 'path + 'namespace,
{
    let mut depth = 0_usize;

    loop {
        match reader.next()? {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                depth += 1;

                if name.namespace_ref() == Some(namespace) && name.local_name == path {
                    return Ok((name, attributes, depth));
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
            | XmlEvent::Doctype { .. } => {},
        }
    }

    Err(GenericParsingError::MissingElement(
        format!("{}:{}", namespace, path).into(),
    ))
}

type ParseGenericPath<'full_path> = Result<
    (Option<OwnedName>, Option<Vec<OwnedAttribute>>, usize),
    GenericParsingError<'full_path>,
>;

pub fn parse_generic_body_paths<'full_path, 'namespace, 'path>(
    reader: &mut EventReader<BufReader<&[u8]>>,
    paths: &[(&'namespace str, &'path str)],
) -> ParseGenericPath<'full_path>
where
    'full_path: 'path + 'namespace,
{
    parse_generic_body_paths_recursive(reader, paths, None, None, 0)
}

fn parse_generic_body_paths_recursive<'full_path, 'namespace, 'path>(
    reader: &mut EventReader<BufReader<&[u8]>>,
    paths: &[(&'namespace str, &'path str)],
    name: Option<OwnedName>,
    attributes: Option<Vec<OwnedAttribute>>,
    mut depth: usize,
) -> ParseGenericPath<'full_path>
where
    'full_path: 'path + 'namespace,
{
    let [(namespace, path), ref rest @ ..] = *paths else {
        return Ok((name, attributes, depth));
    };

    loop {
        match reader.next()? {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                depth += 1;

                if name.namespace_ref() == Some(namespace) && name.local_name == path {
                    return parse_generic_body_paths_recursive(
                        reader,
                        rest,
                        Some(name),
                        Some(attributes),
                        depth,
                    );
                }
            },
            XmlEvent::EndElement { .. } => {
                depth -= 1;
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

    Err(GenericParsingError::MissingElement(
        format!("{}:{}", namespace, path).into(),
    ))
}
