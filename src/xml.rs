use std::io::BufReader;

use thiserror::Error;
use xml::EventReader;
use xml::name::OwnedName;
use xml::reader::XmlEvent;

#[derive(Debug, Error)]
pub enum TextReadError {
    #[error("Found non-text-contents: {0:?}")]
    NonTextContents(XmlEvent),
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
}

/// Reads all text from current position in `reader` until closing tag of `element_name`
///
/// Errors:
/// * When it encounters anything other than text, comments or closing tag of `element_name`
pub fn read_text(
    reader: &mut EventReader<BufReader<&[u8]>>,
    element_name: &OwnedName,
) -> Result<Option<String>, TextReadError> {
    let mut text: Option<String> = None;

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
            XmlEvent::EndElement { name } => {
                if &name == element_name {
                    break;
                }
            },
            event @ (XmlEvent::StartDocument { .. }
            | XmlEvent::EndDocument
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::StartElement { .. }
            | XmlEvent::CData(_)
            | XmlEvent::Doctype { .. }) => {
                return Err(TextReadError::NonTextContents(event));
            },
        }
    }

    let trimmed = text.as_ref().map(|t| t.trim());

    if trimmed == text.as_deref() {
        Ok(text)
    } else {
        Ok(trimmed.map(std::borrow::ToOwned::to_owned))
    }
}
