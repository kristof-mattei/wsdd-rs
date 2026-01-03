use std::io::Read;

use tracing::{Level, event};
use xml::reader::XmlEvent;

use crate::constants::{XML_WSA_NAMESPACE, XML_WSD_NAMESPACE};
use crate::wsd::device::DeviceUri;
use crate::xml::{GenericParsingError, Wrapper, read_text};

pub fn extract_endpoint_reference_address<R>(
    reader: &mut Wrapper<R>,
) -> Result<Box<str>, GenericParsingError>
where
    R: Read,
{
    let mut address = None;

    let mut depth = 0_usize;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                depth += 1;

                if depth == 1
                    && name.namespace_ref() == Some(XML_WSA_NAMESPACE)
                    && name.local_name == "Address"
                {
                    address = read_text(reader)?;

                    // read_text closes the element
                    depth -= 1;
                }
            },
            XmlEvent::EndElement { .. } => {
                if depth == 0 {
                    // we've exited the element that we entered on
                    break;
                }

                depth -= 1;
            },
            XmlEvent::CData(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::EndDocument
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::StartDocument { .. }
            | XmlEvent::Whitespace(_) => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
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

pub fn extract_endpoint_metadata<R>(
    reader: &mut Wrapper<R>,
) -> Result<(DeviceUri, Option<Box<str>>), GenericParsingError>
where
    R: Read,
{
    let mut endpoint = None;
    let mut xaddrs = None;

    let mut depth = 0_usize;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                depth += 1;

                if depth == 1 {
                    match (name.namespace_ref(), &*name.local_name) {
                        (Some(XML_WSA_NAMESPACE), "EndpointReference") => {
                            if endpoint.is_some() || xaddrs.is_some() {
                                return Err(GenericParsingError::InvalidElementOrder);
                            }
                            endpoint = Some(extract_endpoint_reference_address(reader)?);

                            // `extract_endpoint_reference_address` stops when it has consumed the closing tag
                            depth -= 1;
                        },
                        (Some(XML_WSD_NAMESPACE), "XAddrs") => {
                            if endpoint.is_none() || xaddrs.is_some() {
                                return Err(GenericParsingError::InvalidElementOrder);
                            }

                            xaddrs = read_text(reader)?;

                            // stop for another function to continue reading
                            break;
                        },
                        _ => {
                            // Ignore
                        },
                    }
                }
            },
            XmlEvent::EndElement { .. } => {
                if depth == 0 {
                    // we've exited the element that we entered on
                    break;
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

    let Some(endpoint) = endpoint else {
        event!(
            Level::DEBUG,
            "Missing wsa:EndpointReference element. Ignored."
        );

        return Err(GenericParsingError::MissingElement(
            "wsa:EndpointReference".into(),
        ));
    };

    Ok((DeviceUri::new(endpoint), xaddrs.map(String::into_boxed_str)))
}
