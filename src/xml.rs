use std::io::BufReader;

use thiserror::Error;
use tracing::{Level, event};
use xml::EventReader;
use xml::attribute::OwnedAttribute;
use xml::name::{Name, OwnedName};
use xml::reader::XmlEvent;

use crate::constants::STRING_DEFAULT_CAPACITY;

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

/// Reads all text from current position in `reader` until closing tag of the current element
///
/// Expects that reader has just read an opening tag and nothing further.
///
/// Errors:
/// * When it encounters anything other than character data (including normalized whitespace and CDATA)
pub fn read_text(reader: &mut Wrapper<'_>) -> Result<Option<String>, TextReadError> {
    let mut text: String = String::with_capacity(STRING_DEFAULT_CAPACITY);

    loop {
        match reader.next()? {
            XmlEvent::CData(s) | XmlEvent::Characters(s) | XmlEvent::Whitespace(s) => {
                if !text.is_empty() || !s.trim().is_empty() {
                    // leading whitespace is ignored, might as well never store it
                    text.push_str(&s);
                }
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
    Result<(Option<(OwnedName, Vec<OwnedAttribute>)>, usize), GenericParsingError>;

pub fn parse_generic_body_paths(
    reader: &mut Wrapper,
    paths: &[(Option<&str>, &str)],
) -> ParseGenericBodyPathResult {
    parse_generic_body_paths_recursive(reader, paths, None, 0)
}

fn parse_generic_body_paths_recursive(
    reader: &mut Wrapper,
    paths: &[(Option<&str>, &str)],
    name_attributes: Option<(OwnedName, Vec<OwnedAttribute>)>,
    start_depth: usize,
) -> ParseGenericBodyPathResult {
    let [(namespace, path), ref rest @ ..] = *paths else {
        return Ok((name_attributes, start_depth));
    };

    let mut current_depth: usize = start_depth;

    loop {
        match reader.next()? {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                current_depth += 1;

                if start_depth + 1 == current_depth
                    && name.namespace_ref() == namespace
                    && name.local_name == path
                {
                    return parse_generic_body_paths_recursive(
                        reader,
                        rest,
                        Some((name, attributes)),
                        current_depth,
                    );
                }
            },
            XmlEvent::EndElement { name } => {
                if start_depth == current_depth {
                    let missing_element = Name {
                        local_name: path,
                        namespace,
                        prefix: None,
                    };

                    event!(
                        Level::ERROR,
                        now_in = ?name,
                        missing_element = %missing_element,
                        "Could not find element"
                    );

                    return Err(GenericParsingError::MissingElement(
                        missing_element.to_string().into_boxed_str(),
                    ));
                }

                current_depth -= 1;
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

    let name = Name {
        local_name: path,
        namespace,
        prefix: None,
    };

    Err(GenericParsingError::MissingElement(
        name.to_string().into_boxed_str(),
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
    use pretty_assertions::assert_matches;
    use xml::ParserConfig;
    use xml::attribute::OwnedAttribute;
    use xml::name::OwnedName;

    use crate::xml::{BufReader, GenericParsingError, Wrapper, parse_generic_body_paths};

    #[test]
    fn parse_generic_body_missing_element() {
        let xml = include_bytes!("./test/three-levels.xml");

        let mut reader = {
            let reader = ParserConfig::new()
                .cdata_to_characters(true)
                .ignore_comments(true)
                .trim_whitespace(true)
                .whitespace_to_characters(true)
                .create_reader(BufReader::new(xml.as_ref()));

            Wrapper::new(reader)
        };

        let result = parse_generic_body_paths(
            &mut reader,
            &[
                (None, "Level1"),
                (None, "Level2"),
                (Some("urn:level3_ns"), "Level3"),
            ],
        );

        assert_matches!(result, Err(GenericParsingError::MissingElement(name)) if &*name== "{urn:level3_ns}Level3");
    }

    #[test]
    fn parse_generic_body_invalid_depth() {
        let xml = include_bytes!("./test/four-levels.xml");

        let mut reader = {
            let reader = ParserConfig::new()
                .cdata_to_characters(true)
                .ignore_comments(true)
                .trim_whitespace(true)
                .whitespace_to_characters(true)
                .create_reader(BufReader::new(xml.as_ref()));

            Wrapper::new(reader)
        };

        {
            let _unused: Result<xml::reader::XmlEvent, xml::reader::Error> = reader.next();
            let _unused: Result<xml::reader::XmlEvent, xml::reader::Error> = reader.next();
            let _unused: Result<xml::reader::XmlEvent, xml::reader::Error> = reader.next();
        }

        let result = parse_generic_body_paths(
            &mut reader,
            &[
                (Some("urn:level3_ns"), "Level3"),
                (None, "Level4"),
                (Some("urn:level5_ns"), "Level5"),
            ],
        );

        assert_matches!(result, Err(GenericParsingError::MissingElement(name)) if &*name== "{urn:level5_ns}Level5");
    }

    #[test]
    fn repro_depth_underflow() {
        let xml = include_str!("./test/depth-underflow.xml");

        let mut reader = {
            let reader = ParserConfig::new()
                .cdata_to_characters(true)
                .ignore_comments(true)
                .trim_whitespace(true)
                .whitespace_to_characters(true)
                .create_reader(BufReader::new(xml.as_ref()));

            Wrapper::new(reader)
        };

        let result = parse_generic_body_paths(&mut reader, &[(None, "Envelope"), (None, "Body")]);

        let attribute = OwnedAttribute::new(OwnedName::local("attribute"), "this-one");
        assert_matches!(result, Ok((Some((_, attributes)), _)) if attributes.contains(&attribute));
    }
}
