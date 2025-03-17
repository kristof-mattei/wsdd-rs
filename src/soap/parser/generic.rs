use std::borrow::Cow;

use quick_xml::NsReader;
use quick_xml::events::Event;
use quick_xml::name::Namespace;
use quick_xml::name::ResolveResult::Bound;
use thiserror::Error;
use tracing::{Level, event};

use crate::constants::{XML_WSA_NAMESPACE, XML_WSD_NAMESPACE};

#[derive(Error, Debug)]
pub enum GenericParsingError<'e> {
    #[error("Error parsing XML")]
    XmlError(#[from] quick_xml::errors::Error),
    #[error("Missing ./{0} in body")]
    MissingElement(&'e str),
    #[error("Invalid element order")]
    InvalidElementOrder,
}

pub fn extract_endpoint_reference_address<'reader, 'raw, 'error>(
    reader: &'reader mut NsReader<&'raw [u8]>,
) -> Result<Cow<'raw, str>, GenericParsingError<'error>> {
    let mut address = None;

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == XML_WSA_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"Address"
                {
                    address = Some(reader.read_text(e.to_end().name())?);
                }
            },
            (Bound(Namespace(ns)), Event::End(e)) => {
                if ns == XML_WSA_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"EndpointReference"
                {
                    break;
                }
            },
            _ => (),
        }
    }

    let Some(address) = address else {
        event!(
            Level::DEBUG,
            "wsa:Hello message lacks wsa:EndpointReference/wsa:Address element. Ignored."
        );

        return Err(GenericParsingError::MissingElement(
            "wsa:EndpointReference/wsa:Address",
        ));
    };

    Ok(address)
}

pub fn extract_endpoint_metadata<'reader, 'raw, 'error>(
    reader: &'reader mut NsReader<&'raw [u8]>,
) -> Result<(Cow<'raw, str>, Option<Cow<'raw, str>>), GenericParsingError<'error>> {
    //         addr_path = 'wsa:EndpointReference/wsa:Address'

    //         endpoint = body.findtext(prefix + addr_path, namespaces=namespaces)
    //         xaddrs = body.findtext(prefix + 'wsd:XAddrs', namespaces=namespaces)

    //         return endpoint, xaddrs

    let mut endpoint = None;
    let mut xaddrs = None;

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == XML_WSA_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"EndpointReference"
                {
                    if endpoint.is_some() || xaddrs.is_some() {
                        return Err(GenericParsingError::InvalidElementOrder);
                    }
                    endpoint = Some(extract_endpoint_reference_address(reader)?);
                } else if ns == XML_WSD_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"XAddrs"
                {
                    if endpoint.is_none() || xaddrs.is_some() {
                        return Err(GenericParsingError::InvalidElementOrder);
                    }
                    xaddrs = Some(reader.read_text(e.to_end().name())?);

                    // stop for another function to continue reading
                    break;
                }
            },
            (_, Event::Eof) => {
                break;
            },
            _ => (),
        }
    }

    let Some(endpoint) = endpoint else {
        event!(
            Level::DEBUG,
            "wsa:Hello message lacks wsa:EndpointReference/wsa:Address element. Ignored."
        );

        return Err(GenericParsingError::MissingElement(
            "wsa:EndpointReference/wsa:Address",
        ));
    };

    Ok((endpoint, xaddrs))
}

pub fn parse_generic_body<'reader, 'path, 'raw>(
    reader: &'reader mut NsReader<&'raw [u8]>,
    path: &'path str,
) -> Result<(), GenericParsingError<'path>> {
    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == XML_WSD_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == path.as_bytes()
                {
                    return Ok(());
                }
            },
            (_, Event::Eof) => {
                break;
            },
            _ => (),
        }
    }

    Err(GenericParsingError::MissingElement(path))
}
