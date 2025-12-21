use std::io::{BufReader, Read};

use thiserror::Error;
use tracing::{Level, event};
use xml::EventReader;
use xml::attribute::OwnedAttribute;
use xml::name::OwnedName;
use xml::reader::XmlEvent;

#[derive(Debug, Error)]
pub enum TextReadError {
    #[error("Found non-text-contents: `{0:?}`")]
    NonTextContents(XmlEvent),
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
}

pub struct Wrapper<'r> {
    next: Option<std::result::Result<XmlEvent, xml::reader::Error>>,
    reader: EventReader<BufReader<&'r [u8]>>,
}

impl<'r> Wrapper<'r> {
    pub fn new(reader: EventReader<BufReader<&'r [u8]>>) -> Wrapper<'r> {
        Self { next: None, reader }
    }

    pub fn next(&mut self) -> std::result::Result<XmlEvent, xml::reader::Error> {
        if let Some(next) = self.next.take() {
            next
        } else {
            self.reader.next()
        }
    }

    #[expect(unused, reason = "WIP")]
    pub fn peek(&mut self) -> std::result::Result<&XmlEvent, &xml::reader::Error> {
        self.next.get_or_insert_with(|| self.reader.next()).as_ref()
    }
}

pub trait Next {
    fn next(&mut self) -> std::result::Result<XmlEvent, xml::reader::Error>;
}

impl<R: Read> Next for xml::reader::EventReader<R> {
    fn next(&mut self) -> std::result::Result<XmlEvent, xml::reader::Error> {
        self.next()
    }
}

impl Next for Wrapper<'_> {
    fn next(&mut self) -> std::result::Result<XmlEvent, xml::reader::Error> {
        self.next()
    }
}

/// Reads all text from current position in `reader` until closing tag of the current element
///
/// Expects that reader has just read the opening tag and nothing further.
///
/// Errors:
/// * When it encounters anything other than text, comments, cdata or closing tag of the opening tag
/// * When the closing tag is not on the same depth as the opening tag
pub fn read_text(reader: &mut Wrapper<'_>) -> Result<Option<String>, TextReadError> {
    let mut text: String = String::with_capacity(128);

    loop {
        match reader.next()? {
            XmlEvent::CData(s) | XmlEvent::Characters(s) | XmlEvent::Whitespace(s) => {
                text.push_str(&s);
            },
            XmlEvent::EndElement { .. } => {
                // since we don't descend into other elements we don't need to worry here
                // if this element is on 'our' level
                // we don't even need to check if the EndElement is 'ours' as any other EndElement
                // other than ours either precedes a StartElement (caught by us), or is invalid (caught by the parser)
                let trimmed = text.trim();

                if trimmed.is_empty() {
                    return Ok(None);
                }

                if trimmed.len() == text.len() {
                    return Ok(Some(text));
                } else {
                    return Ok(Some(trimmed.to_owned()));
                }
            },
            element @ XmlEvent::StartElement { .. } => {
                // no start elements allowed in our text nodes
                return Err(TextReadError::NonTextContents(element));
            },
            XmlEvent::Comment(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::EndDocument
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::StartDocument { .. } => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
        }
    }
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

pub fn find_child(
    reader: &mut Wrapper<'_>,
    namespace: Option<&str>,
    path: &str,
) -> Result<(OwnedName, Vec<OwnedAttribute>), GenericParsingError> {
    let mut depth = 0_usize;

    loop {
        match reader.next()? {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                depth += 1;

                if name.namespace_ref() == namespace && name.local_name == path {
                    if depth != 1 {
                        event!(
                            Level::TRACE,
                            depth,
                            ?name,
                            "Element found, but at wrong depth (expected depth to be 1)"
                        );

                        continue;
                    }

                    return Ok((name, attributes));
                }
            },
            XmlEvent::EndElement { name } => {
                if depth == 0 {
                    let missing_element = format!(
                        "{}{}{}",
                        namespace.unwrap_or_default(),
                        namespace.map(|_| ":").unwrap_or_default(),
                        path,
                    );

                    event!(
                        Level::ERROR,
                        now_in = %name,
                        missing_element = missing_element,
                        "Could not find element"
                    );

                    return Err(GenericParsingError::MissingElement(
                        missing_element.into_boxed_str(),
                    ));
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

pub fn parse_generic_body_paths<N>(
    reader: &mut N,
    paths: &[(Option<&str>, &str)],
) -> ParseGenericBodyPathResult
where
    N: Next,
{
    parse_generic_body_paths_recursive(reader, paths, None, None, 0)
}

fn parse_generic_body_paths_recursive<N>(
    reader: &mut N,
    paths: &[(Option<&str>, &str)],
    name: Option<OwnedName>,
    attributes: Option<Vec<OwnedAttribute>>,
    mut depth: usize,
) -> ParseGenericBodyPathResult
where
    N: Next,
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

                if name.namespace_ref() == namespace && name.local_name == path {
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
                if depth == 0 {
                    let missing_element = format!(
                        "{}{}{}",
                        namespace.unwrap_or_default(),
                        namespace.map(|_| ":").unwrap_or_default(),
                        path,
                    );

                    event!(
                        Level::ERROR,
                        now_in = ?name,
                        missing_element = missing_element,
                        "Could not find element"
                    );

                    return Err(GenericParsingError::MissingElement(
                        missing_element.into_boxed_str(),
                    ));
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

    let missing_element = format!(
        "{}{}{}",
        namespace.unwrap_or_default(),
        namespace.map(|_| ":").unwrap_or_default(),
        path,
    );

    Err(GenericParsingError::MissingElement(
        missing_element.into_boxed_str(),
    ))
}

// pub fn find_first_element(
//     reader: &mut Wrapper,
//     namespace: Option<&str>,
//     path: &str,
// ) -> Result<(OwnedName, Vec<OwnedAttribute>, usize), GenericParsingError> {
//     let mut depth = 0_usize;

//     loop {
//         match reader.next()? {
//             XmlEvent::StartElement {
//                 name, attributes, ..
//             } => {
//                 depth += 1;

//                 if name.namespace_ref() == namespace && name.local_name == path {
//                     return Ok((name, attributes, depth));
//                 }
//             },
//             XmlEvent::EndElement { name } => {
//                 if depth == 0 {
//                     let missing_element = format!(
//                         "{}{}{}",
//                         namespace.unwrap_or_default(),
//                         namespace.map(|_| ":").unwrap_or_default(),
//                         path,
//                     );

//                     event!(
//                         Level::TRACE,
//                         now_in = %name,
//                         missing_element = missing_element,
//                         "Could not find element"
//                     );

//                     return Err(GenericParsingError::MissingElement(
//                         missing_element.into_boxed_str(),
//                     ));
//                 }

//                 depth -= 1;
//             },
//             XmlEvent::EndDocument => {
//                 break;
//             },
//             XmlEvent::StartDocument { .. }
//             | XmlEvent::ProcessingInstruction { .. }
//             | XmlEvent::CData(_)
//             | XmlEvent::Comment(_)
//             | XmlEvent::Characters(_)
//             | XmlEvent::Whitespace(_)
//             | XmlEvent::Doctype { .. } => {},
//         }
//     }

//     Err(GenericParsingError::MissingElement(
//         format!(
//             "{}{}{}",
//             namespace.unwrap_or_default(),
//             namespace.map(|_| ":").unwrap_or_default(),
//             path
//         )
//         .into_boxed_str(),
//     ))
// }

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_eq;

    use crate::xml::{BufReader, EventReader, GenericParsingError, parse_generic_body_paths};

    #[test]
    fn parse_generic_body_paths_reports_missing_third_level_element() {
        let xml = include_bytes!("./test/three-levels.xml");

        let mut reader = EventReader::new(BufReader::new(xml.as_ref()));

        let err = parse_generic_body_paths(
            &mut reader,
            &[
                (Some("urn:level1"), "Envelope"),
                (None, "Body"),
                (Some("urn:level3"), "Resolve"),
            ],
        )
        .expect_err("expected missing third-level element");

        match err {
            GenericParsingError::MissingElement(name) => {
                assert_eq!(&*name, "urn:level3:Resolve");
            },
            GenericParsingError::XmlError(_)
            | GenericParsingError::TextReadError(_)
            | GenericParsingError::MissingEndElement(_)
            | GenericParsingError::InvalidElementOrder
            | GenericParsingError::InvalidUuid(_)
            | GenericParsingError::InvalidDepth(_) => panic!(),
        }
    }
}
