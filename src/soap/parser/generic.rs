use tracing::{Level, event};
use xml::reader::XmlEvent;

use crate::constants::{XML_WSA_NAMESPACE, XML_WSD_NAMESPACE};
use crate::wsd::device::DeviceUri;
use crate::xml::{GenericParsingError, Wrapper, read_text};

pub fn extract_endpoint_reference_address(
    reader: &mut Wrapper<'_>,
) -> Result<Box<str>, GenericParsingError> {
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

pub fn extract_endpoint_metadata(
    reader: &mut Wrapper<'_>,
) -> Result<(DeviceUri, Option<Box<str>>), GenericParsingError> {
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
            XmlEvent::CData(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::EndElement { .. }
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
