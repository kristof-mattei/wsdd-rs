use std::borrow::ToOwned;
use std::io::BufReader;

use thiserror::Error;
use xml::EventReader;
use xml::attribute::OwnedAttribute;
use xml::name::{Name, OwnedName};
use xml::reader::XmlEvent;

#[derive(Debug, Error)]
pub enum TextReadError {
    #[error("Found non-text-contents: `{0:?}`")]
    NonTextContents(XmlEvent),
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
    #[error("Invalid open/close element order")]
    InvalidDepth(isize),
    #[error("Missing end `{0}` element")]
    MissingEndElement(Box<str>),
}

/// Reads all text from current position in `reader` until closing tag of `element_name`
///
/// Expects that reader has just read the opening tag and nothing further.
///
/// Errors:
/// * When it encounters anything other than text, comments or closing tag of `element_name`
/// * When the closing tag is not on the same depth as the opening tag
pub fn read_text(
    reader: &mut EventReader<BufReader<&[u8]>>,
    element_name: Name<'_>,
) -> Result<Option<String>, TextReadError> {
    let mut text: Option<String> = None;

    // We're in an opening element
    let mut depth: isize = 1;

    loop {
        match reader.next()? {
            XmlEvent::Comment(_) => {},
            XmlEvent::Whitespace(s) | XmlEvent::Characters(s) => {
                if let Some(text) = text.as_mut() {
                    text.push_str(&s);
                } else {
                    text = Some(s);
                }
            },

            XmlEvent::StartElement {
                name: _name,
                attributes: _attributes,
                namespace: _namespace,
            } => {
                depth += 1;
            },
            XmlEvent::EndElement { name } => {
                depth -= 1;

                if name.borrow() == element_name {
                    if depth != 0 {
                        return Err(TextReadError::InvalidDepth(depth));
                    }

                    return Ok(text.map(|original| {
                        let trimmed = original.trim();

                        if trimmed.len() == original.len() {
                            original
                        } else {
                            trimmed.to_owned()
                        }
                    }));
                }
            },

            XmlEvent::EndDocument => {
                break;
            },
            event @ (XmlEvent::StartDocument { .. }
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::CData(_)
            | XmlEvent::Doctype { .. }) => {
                return Err(TextReadError::NonTextContents(event));
            },
        }
    }

    Err(TextReadError::MissingEndElement(
        element_name.to_string().into_boxed_str(),
    ))
}

#[derive(Error, Debug)]
pub enum GenericParsingError {
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
    #[error("Error reading text")]
    TextReadError(#[from] TextReadError),
    #[error("Missing `{0}`")]
    MissingElement(Box<str>),
    #[error("Missing end `{0}` element")]
    MissingEndElement(Box<str>),
    #[error("Invalid element order")]
    InvalidElementOrder,
    #[error("Invalid UUID")]
    InvalidUuid(#[from] uuid::Error),
    #[error("Invalid open/close element order")]
    InvalidDepth(usize),
}

/// TODO expand to make sure what we search for is at the right depth
pub fn parse_generic_body(
    reader: &mut EventReader<BufReader<&[u8]>>,
    namespace: Option<&str>,
    path: &str,
) -> Result<(OwnedName, Vec<OwnedAttribute>, usize), GenericParsingError> {
    let mut depth = 0_usize;

    loop {
        match reader.next()? {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                depth += 1;

                if name.namespace_ref() == namespace && name.local_name == path {
                    return Ok((name, attributes, depth));
                }
            },
            XmlEvent::EndElement { .. } => {
                if depth == 0 {
                    return Err(GenericParsingError::MissingElement(
                        format!(
                            "{}{}{}",
                            namespace.unwrap_or_default(),
                            namespace.map(|_| ":").unwrap_or_default(),
                            path
                        )
                        .into_boxed_str(),
                    ));
                }

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
            | XmlEvent::Doctype { .. } => {},
        }
    }

    Err(GenericParsingError::MissingElement(
        format!(
            "{}{}{}",
            namespace.unwrap_or_default(),
            namespace.map(|_| ":").unwrap_or_default(),
            path
        )
        .into_boxed_str(),
    ))
}

type ParseGenericBodyPathResult =
    Result<(Option<OwnedName>, Option<Vec<OwnedAttribute>>, usize), GenericParsingError>;

pub fn parse_generic_body_paths(
    reader: &mut EventReader<BufReader<&[u8]>>,
    paths: &[(&str, &str)],
) -> ParseGenericBodyPathResult {
    parse_generic_body_paths_recursive(reader, paths, None, None, 0)
}

fn parse_generic_body_paths_recursive(
    reader: &mut EventReader<BufReader<&[u8]>>,
    paths: &[(&str, &str)],
    name: Option<OwnedName>,
    attributes: Option<Vec<OwnedAttribute>>,
    mut depth: usize,
) -> ParseGenericBodyPathResult {
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
        format!("{}:{}", namespace, path).into_boxed_str(),
    ))
}
