use std::io::BufReader;

use tracing::{Level, event};
use xml::EventReader;
use xml::reader::XmlEvent;

use crate::constants::{XML_WSA_NAMESPACE, XML_WSD_NAMESPACE};
use crate::wsd::device::DeviceUri;
use crate::xml::{GenericParsingError, read_text};

pub fn extract_endpoint_reference_address(
    reader: &mut EventReader<BufReader<&[u8]>>,
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

    Ok((DeviceUri::new(endpoint), xaddrs.map(String::into_boxed_str)))
}
