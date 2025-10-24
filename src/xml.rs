use std::borrow::Cow;
use std::io::BufReader;

use thiserror::Error;
use xml::EventReader;
use xml::attribute::OwnedAttribute;
use xml::name::{Name, OwnedName};
use xml::reader::XmlEvent;

#[derive(Debug, Error)]
pub enum TextReadError {
    #[error("Found non-text-contents: {0:?}")]
    NonTextContents(XmlEvent),
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
    #[error("Invalid open/close element order")]
    InvalidDepth(isize),
}

/// Reads all text from current position in `reader` until closing tag of `element_name`
///
/// Errors:
/// * When it encounters anything other than text, comments or closing tag of `element_name`
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

                if depth < 0 {
                    return Err(TextReadError::InvalidDepth(depth));
                }

                if name.borrow() == element_name {
                    break;
                }
            },
            event @ (XmlEvent::StartDocument { .. }
            | XmlEvent::EndDocument
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::CData(_)
            | XmlEvent::Doctype { .. }) => {
                return Err(TextReadError::NonTextContents(event));
            },
        }
    }

    if depth != 0 {
        return Err(TextReadError::InvalidDepth(depth));
    }

    let trimmed = text.as_ref().map(|t| t.trim());

    if trimmed == text.as_deref() {
        Ok(text)
    } else {
        Ok(trimmed.map(std::borrow::ToOwned::to_owned))
    }
}

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

type ParseGenericBodyPathResult<'full_path> = Result<
    (Option<OwnedName>, Option<Vec<OwnedAttribute>>, usize),
    GenericParsingError<'full_path>,
>;

pub fn parse_generic_body_paths<'full_path, 'namespace, 'path>(
    reader: &mut EventReader<BufReader<&[u8]>>,
    paths: &[(&'namespace str, &'path str)],
) -> ParseGenericBodyPathResult<'full_path>
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
) -> ParseGenericBodyPathResult<'full_path>
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
