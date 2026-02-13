use std::io::Read;

use thiserror::Error;
use tracing::{Level, event};
use xml::EventReader;
use xml::attribute::OwnedAttribute;
use xml::name::{Name, OwnedName};
use xml::reader::XmlEvent;

use crate::constants;

#[derive(Debug, Error)]
pub enum TextReadError {
    #[error("Found non-text-contents: {0:?}")]
    NonTextContents(Box<XmlEvent>),
    #[error("Error parsing XML: {0}")]
    XmlError(#[from] xml::reader::Error),
}

pub struct Wrapper<R>
where
    R: Read,
{
    depth: usize,
    next: Option<std::result::Result<XmlEvent, xml::reader::Error>>,
    reader: EventReader<R>,
}

impl<R> Wrapper<R>
where
    R: Read,
{
    pub fn new(reader: EventReader<R>) -> Wrapper<R> {
        Self {
            depth: 0,
            next: None,
            reader,
        }
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    pub fn next(&mut self) -> std::result::Result<XmlEvent, xml::reader::Error> {
        let event = match self.next.take() {
            Some(next) => next,
            None => self.reader.next(),
        };

        if let Ok(ref event) = event {
            #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
            match *event {
                XmlEvent::StartElement { .. } => {
                    self.depth += 1;
                },
                XmlEvent::EndElement { .. } => {
                    self.depth -= 1;
                },
                _ => {},
            }
        }

        event
    }

    #[expect(unused, reason = "WIP")]
    pub fn peek(&mut self) -> std::result::Result<&XmlEvent, &xml::reader::Error> {
        self.next.get_or_insert_with(|| self.reader.next()).as_ref()
    }
}

/// Reads all text from current position in `reader` until closing tag of the current element.
///
/// Expects that reader has just read an opening tag and nothing further.
///
/// Errors:
/// * When it encounters anything other than character data (including normalized white space and CDATA)
pub fn read_text<R>(reader: &mut Wrapper<R>) -> Result<Option<String>, TextReadError>
where
    R: Read,
{
    let mut text: String = String::with_capacity(constants::STRING_DEFAULT_CAPACITY);

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
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
            element @ (XmlEvent::StartElement { .. } | XmlEvent::EndDocument) => {
                // no start elements or premature end-of-document allowed in our text nodes
                return Err(TextReadError::NonTextContents(Box::new(element)));
            },
            _ => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
        }
    }
}

#[derive(Debug, Error)]
pub enum XmlError {
    #[error("Error parsing XML: {0}")]
    ReaderError(#[from] xml::reader::Error),
    #[error("Error reading text: {0}")]
    TextReadError(#[from] TextReadError),
    #[error("Unexpected event: {0:?}")]
    UnexpectedEvent(Box<XmlEvent>),
    #[error("Missing element: {0}")]
    MissingElement(Box<str>),
}

type FindDescendantResult = Result<(OwnedName, Vec<OwnedAttribute>), XmlError>;

pub fn find_child<R>(
    reader: &mut Wrapper<R>,
    namespace: Option<&str>,
    path: &str,
) -> FindDescendantResult
where
    R: Read,
{
    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement {
                name, attributes, ..
            } => {
                if reader.depth() == entry_depth + 1
                    && name.namespace_ref() == namespace
                    && name.local_name == path
                {
                    return Ok((name, attributes));
                }
            },
            XmlEvent::EndElement { name } => {
                if reader.depth() < entry_depth {
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

                    return Err(XmlError::MissingElement(
                        missing_element.to_string().into_boxed_str(),
                    ));
                }
            },
            XmlEvent::EndDocument => {
                break;
            },
            _ => {
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

    Err(XmlError::MissingElement(name.to_string().into_boxed_str()))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::assert_matches;
    use xml::ParserConfig;
    use xml::attribute::OwnedAttribute;
    use xml::name::OwnedName;

    use crate::xml::{Wrapper, XmlError, find_child};

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

        let _result = find_child(&mut reader, None, "Level1").unwrap();
        let _result = find_child(&mut reader, None, "Level2").unwrap();
        let result = find_child(&mut reader, Some("urn:level3_ns"), "Level3");

        assert_matches!(result, Err(XmlError::MissingElement(name)) if &*name == "{urn:level3_ns}Level3");
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

        let _result = find_child(&mut reader, Some("urn:level3_ns"), "Level3");
        let _result = find_child(&mut reader, None, "Level4");
        let result = find_child(&mut reader, Some("urn:level5_ns"), "Level5");

        assert_matches!(result, Err(XmlError::MissingElement(name)) if &*name == "{urn:level5_ns}Level5");
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

        let _result = find_child(&mut reader, Some("urn:first"), "Envelope");
        let result = find_child(&mut reader, Some("urn:first"), "Body");

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

        let _result = find_child(&mut reader, Some("urn:first"), "Envelope");
        let result = find_child(&mut reader, Some("urn:first"), "Body");

        assert_matches!(result, Err(XmlError::MissingElement(name)) if &*name == "{urn:first}Body");
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

        let _result = find_child(&mut reader, Some("urn:first"), "Envelope");
        let result = find_child(&mut reader, Some("urn:first"), "Body");

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

        let result = find_child(&mut reader, None, "NotFound");

        assert_matches!(result, Err(XmlError::MissingElement(name)) if &*name == "NotFound");
    }
}
