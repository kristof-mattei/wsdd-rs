use std::io::Read;

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

pub struct Wrapper<R>
where
    R: Read,
{
    next: Option<std::result::Result<XmlEvent, xml::reader::Error>>,
    reader: EventReader<R>,
}

impl<R> Wrapper<R>
where
    R: Read,
{
    pub fn new(reader: EventReader<R>) -> Wrapper<R> {
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
pub fn read_text<R>(reader: &mut Wrapper<R>) -> Result<Option<String>, TextReadError>
where
    R: Read,
{
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
    UrnUuidError(#[from] uuid::Error),
    #[error("Invalid open/close element order")]
    InvalidDepth(usize),
}

type FindDescendantResult = Result<(OwnedName, Vec<OwnedAttribute>), GenericParsingError>;

pub fn find_descendant<R>(
    reader: &mut Wrapper<R>,
    namespace: Option<&str>,
    path: &str,
) -> FindDescendantResult
where
    R: Read,
{
    let start_depth = 0;
    let mut depth: usize = start_depth;

    loop {
        match reader.next()? {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                depth += 1;

                if start_depth + 1 == depth
                    && name.namespace_ref() == namespace
                    && name.local_name == path
                {
                    return Ok((name, attributes));
                }
            },
            XmlEvent::EndElement { name } => {
                if start_depth == depth {
                    let missing_element = Name {
                        local_name: path,
                        namespace,
                        prefix: None,
                    };

                    event!(
                        Level::TRACE,
                        now_in = %name,
                        missing_element = %missing_element,
                        "Could not find element"
                    );

                    return Err(GenericParsingError::MissingElement(
                        missing_element.to_string().into_boxed_str(),
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

    let name = Name {
        local_name: path,
        namespace,
        prefix: None,
    };

    Err(GenericParsingError::MissingElement(
        name.to_string().into_boxed_str(),
    ))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_matches;
    use xml::ParserConfig;
    use xml::attribute::OwnedAttribute;
    use xml::name::OwnedName;

    use crate::xml::{GenericParsingError, Wrapper, find_descendant};

    #[test]
    fn parse_generic_body_missing_element() {
        let xml = include_str!("./test/xml/three-levels.xml");

        let mut reader = {
            let reader = ParserConfig::new()
                .cdata_to_characters(true)
                .ignore_comments(true)
                .trim_whitespace(true)
                .whitespace_to_characters(true)
                .create_reader(xml.as_bytes());

            Wrapper::new(reader)
        };

        let _result = find_descendant(&mut reader, None, "Level1").unwrap();
        let _result = find_descendant(&mut reader, None, "Level2").unwrap();
        let result = find_descendant(&mut reader, Some("urn:level3_ns"), "Level3");

        assert_matches!(result, Err(GenericParsingError::MissingElement(name)) if &*name == "{urn:level3_ns}Level3");
    }

    #[test]
    fn parse_generic_body_depth_mismatch_returns_missing_element() {
        let xml = include_str!("./test/xml/four-levels.xml");

        let mut reader = {
            let reader = ParserConfig::new()
                .cdata_to_characters(true)
                .ignore_comments(true)
                .trim_whitespace(true)
                .whitespace_to_characters(true)
                .create_reader(xml.as_bytes());

            Wrapper::new(reader)
        };

        {
            let _unused: Result<xml::reader::XmlEvent, xml::reader::Error> = reader.next();
            let _unused: Result<xml::reader::XmlEvent, xml::reader::Error> = reader.next();
            let _unused: Result<xml::reader::XmlEvent, xml::reader::Error> = reader.next();
        }

        let _result = find_descendant(&mut reader, Some("urn:level3_ns"), "Level3");
        let _result = find_descendant(&mut reader, None, "Level4");
        let result = find_descendant(&mut reader, Some("urn:level5_ns"), "Level5");

        assert_matches!(result, Err(GenericParsingError::MissingElement(name)) if &*name == "{urn:level5_ns}Level5");
    }

    #[test]
    fn parse_generic_body_paths_nested_non_matching_elements() {
        let xml = include_str!("./test/xml/nested-non-matching-elements.xml");

        let mut reader = {
            let reader = ParserConfig::new()
                .cdata_to_characters(true)
                .ignore_comments(true)
                .trim_whitespace(true)
                .whitespace_to_characters(true)
                .create_reader(xml.as_bytes());

            Wrapper::new(reader)
        };

        let _result = find_descendant(&mut reader, Some("urn:first"), "Envelope");
        let result = find_descendant(&mut reader, Some("urn:first"), "Body");

        let attribute = OwnedAttribute::new(OwnedName::local("attribute"), "this-one");
        assert_matches!(result, Ok((_, attributes)) if attributes.contains(&attribute));
    }

    #[test]
    fn parse_generic_body_paths_requires_direct_child_match() {
        let xml = include_str!("./test/xml/requires-direct-child-match.xml");

        let mut reader = {
            let reader = ParserConfig::new()
                .cdata_to_characters(true)
                .ignore_comments(true)
                .trim_whitespace(true)
                .whitespace_to_characters(true)
                .create_reader(xml.as_bytes());

            Wrapper::new(reader)
        };

        let _result = find_descendant(&mut reader, Some("urn:first"), "Envelope");
        let result = find_descendant(&mut reader, Some("urn:first"), "Body");

        assert_matches!(result, Err(GenericParsingError::MissingElement(name)) if &*name == "{urn:first}Body");
    }

    #[test]
    fn parse_generic_body_paths_siblings() {
        let xml = include_str!("./test/xml/siblings.xml");

        let mut reader = {
            let reader = ParserConfig::new()
                .cdata_to_characters(true)
                .ignore_comments(true)
                .trim_whitespace(true)
                .whitespace_to_characters(true)
                .create_reader(xml.as_bytes());

            Wrapper::new(reader)
        };

        let _result = find_descendant(&mut reader, Some("urn:first"), "Envelope");
        let result = find_descendant(&mut reader, Some("urn:first"), "Body");

        let attribute = OwnedAttribute::new(OwnedName::local("attribute"), "this-one");
        assert_matches!(result, Ok((_, attributes)) if attributes.contains(&attribute));
    }

    #[test]
    fn repro_depth_underflow() {
        let xml = include_str!("./test/xml/depth-underflow.xml");

        let mut reader = {
            let reader = ParserConfig::new()
                .cdata_to_characters(true)
                .ignore_comments(true)
                .trim_whitespace(true)
                .whitespace_to_characters(true)
                .create_reader(xml.as_bytes());

            Wrapper::new(reader)
        };

        // descent into the reader
        // before this bugfix, when starting at a certain depth
        // when an element wasn't found it would go beyond that depth
        // and since depth is usize, it would underflow
        {
            let _unused = reader.next();
            let _unused = reader.next();
        }

        let result = find_descendant(&mut reader, None, "NotFound");

        assert_matches!(result, Err(GenericParsingError::MissingElement(name)) if &*name == "NotFound");
    }
}
