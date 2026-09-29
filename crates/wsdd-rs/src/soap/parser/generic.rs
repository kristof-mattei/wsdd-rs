use std::io::Read;

use tracing::{Level, event};
use xml::name::OwnedName;
use xml::reader::XmlEvent;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::wsd::device::DeviceUri;
use crate::xml::{XmlError, XmlReader, read_text};

pub fn extract_endpoint_reference_address<R>(
    reader: &mut XmlReader<R>,
) -> Result<Box<str>, BodyParsingError>
where
    R: Read,
{
    let mut address = None;

    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement { name, .. }
                if reader.depth() == entry_depth + 1
                    && name.namespace_ref() == Some(constants::XML_WSA_NAMESPACE)
                    && name.local_name == "Address" =>
            {
                address = read_text(reader)?;
            },
            XmlEvent::EndElement { .. } if reader.depth() < entry_depth => {
                // we've exited the element that we entered on
                break;
            },
            element @ XmlEvent::EndDocument => {
                return Err(XmlError::UnexpectedEvent(Box::new(element)).into());
            },
            _ => {
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

        return Err(XmlError::MissingElement("wsa:EndpointReference/wsa:Address".into()).into());
    };

    Ok(address.into_boxed_str())
}

/// Parses an `xs:unsignedInt` into a `u64`, see `config.rs::AppSequence` for why 64 bits.
pub fn parse_unsigned_int(value: &str) -> Option<u64> {
    value.trim().parse().ok()
}

/// The children of `wsd:Hello`, `wsd:Bye`, `wsd:ProbeMatch` and `wsd:ResolveMatch` in their shared sequence order (WS-Discovery, Appendix II).
#[derive(Clone, Copy, PartialEq, PartialOrd)]
enum EndpointMetadataChild {
    EndpointReference,
    Types,
    Scopes,
    XAddrs,
    MetadataVersion,
    Extension,
}

impl EndpointMetadataChild {
    /// `None` for a child outside the sequence: an unknown `wsd:` element or one without a namespace.
    fn from_name(name: &OwnedName) -> Option<Self> {
        match name.namespace_ref() {
            Some(constants::XML_WSA_NAMESPACE) if name.local_name == "EndpointReference" => {
                Some(Self::EndpointReference)
            },
            Some(constants::XML_WSD_NAMESPACE) => match &*name.local_name {
                "Types" => Some(Self::Types),
                "Scopes" => Some(Self::Scopes),
                "XAddrs" => Some(Self::XAddrs),
                "MetadataVersion" => Some(Self::MetadataVersion),
                _ => None,
            },
            Some(_) => Some(Self::Extension),
            None => None,
        }
    }
}

pub fn extract_endpoint_metadata<R>(
    reader: &mut XmlReader<R>,
) -> Result<(DeviceUri, Option<Box<str>>), BodyParsingError>
where
    R: Read,
{
    let mut endpoint = None;
    let mut xaddrs = None;
    let mut last_child = None;

    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement { name, .. } if reader.depth() == entry_depth + 1 => {
                let Some(child) = EndpointMetadataChild::from_name(&name) else {
                    // not part of the sequence, ignored
                    continue;
                };

                // extension elements repeat, every other child appears at most once
                if child != EndpointMetadataChild::Extension && last_child >= Some(child) {
                    return Err(BodyParsingError::InvalidElementOrder);
                }

                last_child = Some(child);

                match child {
                    EndpointMetadataChild::EndpointReference => {
                        endpoint = Some(extract_endpoint_reference_address(reader)?);
                    },
                    EndpointMetadataChild::XAddrs => {
                        xaddrs = read_text(reader)?;
                    },
                    EndpointMetadataChild::Types
                    | EndpointMetadataChild::Scopes
                    | EndpointMetadataChild::MetadataVersion
                    | EndpointMetadataChild::Extension => {},
                }
            },
            XmlEvent::EndElement { .. } if reader.depth() < entry_depth => {
                // we've exited the element that we entered on
                break;
            },
            element @ XmlEvent::EndDocument => {
                return Err(XmlError::UnexpectedEvent(Box::new(element)).into());
            },
            _ => {
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

        return Err(XmlError::MissingElement("wsa:EndpointReference".into()).into());
    };

    Ok((DeviceUri::new(endpoint), xaddrs.map(String::into_boxed_str)))
}

#[cfg(test)]
mod tests {
    use pretty_assertions::{assert_eq, assert_matches};
    use xml::ParserConfig;

    use crate::constants;
    use crate::soap::parser::BodyParsingError;
    use crate::soap::parser::generic::extract_endpoint_metadata;
    use crate::wsd::device::DeviceUri;
    use crate::xml::{XmlReader, find_child};

    const ENDPOINT_REFERENCE: &str = "<wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference>";
    const TYPES: &str = "<wsd:Types>wsdp:Device</wsd:Types>";
    const SCOPES: &str = "<wsd:Scopes>http://example.com/scope</wsd:Scopes>";
    const XADDRS: &str = "<wsd:XAddrs>http://192.168.100.5:5357/</wsd:XAddrs>";
    const METADATA_VERSION: &str = "<wsd:MetadataVersion>1</wsd:MetadataVersion>";
    const EXTENSION: &str = r#"<ext:Extension xmlns:ext="urn:ext" />"#;

    fn parse(children: &[&str]) -> Result<(DeviceUri, Option<Box<str>>), BodyParsingError> {
        let xml = format!(
            r#"<wsd:Hello xmlns:wsa="{}" xmlns:wsd="{}">{}</wsd:Hello>"#,
            constants::XML_WSA_NAMESPACE,
            constants::XML_WSD_NAMESPACE,
            children.concat()
        );

        let mut reader = XmlReader::new(
            ParserConfig::new()
                .cdata_to_characters(true)
                .ignore_comments(true)
                .trim_whitespace(true)
                .whitespace_to_characters(true)
                .create_reader(xml.as_bytes()),
        );

        find_child(&mut reader, Some(constants::XML_WSD_NAMESPACE), "Hello")?;

        extract_endpoint_metadata(&mut reader)
    }

    #[test]
    fn parses_full_sequence() {
        let (endpoint, xaddrs) = parse(&[
            ENDPOINT_REFERENCE,
            TYPES,
            SCOPES,
            XADDRS,
            METADATA_VERSION,
            EXTENSION,
            EXTENSION,
        ])
        .unwrap();

        assert_eq!(&*endpoint, "urn:uuid:00000000-0000-0000-0000-000000000001");
        assert_eq!(xaddrs.as_deref(), Some("http://192.168.100.5:5357/"));
    }

    #[test]
    fn parses_minimal_sequence() {
        let (_, xaddrs) = parse(&[ENDPOINT_REFERENCE, METADATA_VERSION]).unwrap();

        assert_eq!(xaddrs, None);
    }

    #[test]
    fn rejects_second_endpoint_reference() {
        let result = parse(&[ENDPOINT_REFERENCE, ENDPOINT_REFERENCE]);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_endpoint_reference_after_types() {
        let result = parse(&[TYPES, ENDPOINT_REFERENCE]);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_endpoint_reference_after_xaddrs() {
        let result = parse(&[XADDRS, ENDPOINT_REFERENCE]);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_types_after_scopes() {
        let result = parse(&[ENDPOINT_REFERENCE, SCOPES, TYPES]);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_second_xaddrs() {
        let result = parse(&[ENDPOINT_REFERENCE, XADDRS, XADDRS]);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_xaddrs_after_metadata_version() {
        let result = parse(&[ENDPOINT_REFERENCE, METADATA_VERSION, XADDRS]);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_metadata_version_after_extension() {
        let result = parse(&[ENDPOINT_REFERENCE, EXTENSION, METADATA_VERSION]);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }
}
