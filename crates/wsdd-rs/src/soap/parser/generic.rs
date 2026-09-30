use std::io::Read;

use tracing::{Level, event};
use xml::common::{is_name_char, is_name_start_char, is_whitespace_char};
use xml::name::OwnedName;
use xml::namespace::{NS_EMPTY_URI, NS_NO_PREFIX, Namespace};
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
/// Its lexical space is decimal digits only, and its `whiteSpace` facet strips only #x20, #x9, #xA and #xD around them, see documentation/xmlschema-2.pdf, 3.3.22.1 and 4.3.6.
pub fn parse_unsigned_int(value: &str) -> Option<u64> {
    let digits = value.trim_matches([' ', '\t', '\n', '\r']);

    if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    digits.parse().ok()
}

/// Splits an `xs:list` value at XML white space, see documentation/xmlschema-2.pdf, 4.3.6.
pub fn list_items(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(is_whitespace_char)
        .filter(|item| !item.is_empty())
}

/// Resolves an `xs:QName` to its namespace and local name, see documentation/xmlschema-2.pdf, 3.2.18.
pub fn resolve_qname<'a>(raw: &'a str, namespaces: &'a Namespace) -> Option<(&'a str, &'a str)> {
    match raw.split_once(':') {
        None => is_ncname(raw).then(|| (namespaces.get(NS_NO_PREFIX).unwrap_or(NS_EMPTY_URI), raw)),
        Some((prefix, local_name)) => {
            if !is_ncname(prefix) || !is_ncname(local_name) {
                return None;
            }

            namespaces
                .get(prefix)
                .map(|namespace| (namespace, local_name))
        },
    }
}

/// An XML name without a colon.
fn is_ncname(value: &str) -> bool {
    let mut chars = value.chars();

    chars
        .next()
        .is_some_and(|first| first != ':' && is_name_start_char(first))
        && chars.all(|c| c != ':' && is_name_char(c))
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

pub struct EndpointMetadata {
    pub endpoint: DeviceUri,
    pub raw_xaddrs: Option<Box<str>>,
    /// `None` when absent, `Err` holds the text of a value that is not an `xs:unsignedInt`.
    pub metadata_version: Option<Result<u64, Box<str>>>,
    /// A `wsd:Types` text with an unresolvable entry.
    pub invalid_types: Option<Box<str>>,
}

pub fn require_valid_types(invalid_types: Option<Box<str>>) -> Result<(), BodyParsingError> {
    match invalid_types {
        Some(raw_types) => Err(BodyParsingError::InvalidTypes(raw_types)),
        None => Ok(()),
    }
}

/// Hello, `ProbeMatch` and `ResolveMatch` require a valid `MetadataVersion`, only Bye makes it optional, see documentation/ws-discovery.pdf, Appendix II.
pub fn require_metadata_version(
    metadata_version: Option<Result<u64, Box<str>>>,
) -> Result<(), BodyParsingError> {
    match metadata_version {
        None => Err(XmlError::MissingElement("wsd:MetadataVersion".into()).into()),
        Some(Err(text)) => Err(BodyParsingError::InvalidMetadataVersion(text)),
        Some(Ok(_)) => Ok(()),
    }
}

pub fn extract_endpoint_metadata<R>(
    reader: &mut XmlReader<R>,
) -> Result<EndpointMetadata, BodyParsingError>
where
    R: Read,
{
    let mut endpoint = None;
    let mut xaddrs = None;
    let mut metadata_version = None;
    let mut invalid_types = None;
    let mut last_child = None;

    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement {
                name, namespace, ..
            } if reader.depth() == entry_depth + 1 => {
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
                    EndpointMetadataChild::MetadataVersion => {
                        let text = read_text(reader)?.unwrap_or_default();

                        metadata_version =
                            Some(parse_unsigned_int(&text).ok_or_else(|| text.into_boxed_str()));
                    },
                    EndpointMetadataChild::Types => {
                        let raw_types = read_text(reader)?.unwrap_or_default();

                        if list_items(&raw_types)
                            .any(|raw_type| resolve_qname(raw_type, &namespace).is_none())
                        {
                            invalid_types = Some(raw_types.into_boxed_str());
                        }
                    },
                    EndpointMetadataChild::Scopes | EndpointMetadataChild::Extension => {},
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

    Ok(EndpointMetadata {
        endpoint: DeviceUri::new(endpoint),
        raw_xaddrs: xaddrs.map(String::into_boxed_str),
        metadata_version,
        invalid_types,
    })
}

#[cfg(test)]
mod tests {
    use pretty_assertions::{assert_eq, assert_matches};
    use xml::ParserConfig;
    use xml::namespace::Namespace;

    use crate::constants;
    use crate::soap::parser::BodyParsingError;
    use crate::soap::parser::generic::{
        EndpointMetadata, extract_endpoint_metadata, list_items, parse_unsigned_int,
        require_metadata_version, require_valid_types, resolve_qname,
    };
    use crate::xml::{XmlError, XmlReader, find_child};

    const ENDPOINT_REFERENCE: &str = "<wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference>";
    const TYPES: &str = "<wsd:Types>wsdp:Device</wsd:Types>";
    const SCOPES: &str = "<wsd:Scopes>http://example.com/scope</wsd:Scopes>";
    const XADDRS: &str = "<wsd:XAddrs>http://192.168.100.5:5357/</wsd:XAddrs>";
    const METADATA_VERSION: &str = "<wsd:MetadataVersion>1</wsd:MetadataVersion>";
    const EXTENSION: &str = r#"<ext:Extension xmlns:ext="urn:ext" />"#;

    fn parse(children: &[&str]) -> Result<EndpointMetadata, BodyParsingError> {
        let xml = format!(
            r#"<wsd:Hello xmlns:wsa="{}" xmlns:wsd="{}" xmlns:wsdp="{}">{}</wsd:Hello>"#,
            constants::XML_WSA_NAMESPACE,
            constants::XML_WSD_NAMESPACE,
            constants::XML_WSDP_NAMESPACE,
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
        let EndpointMetadata {
            endpoint,
            raw_xaddrs,
            metadata_version,
            invalid_types,
        } = parse(&[
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
        assert_eq!(raw_xaddrs.as_deref(), Some("http://192.168.100.5:5357/"));
        assert_eq!(metadata_version, Some(Ok(1)));
        assert_eq!(invalid_types, None);
    }

    #[test]
    fn reads_types_with_an_unresolvable_entry() {
        let EndpointMetadata { invalid_types, .. } = parse(&[
            ENDPOINT_REFERENCE,
            "<wsd:Types>wsdp:Device nope:Device other:Device</wsd:Types>",
        ])
        .unwrap();

        assert_eq!(
            invalid_types.as_deref(),
            Some("wsdp:Device nope:Device other:Device")
        );
    }

    #[test]
    fn requires_valid_types() {
        assert_matches!(require_valid_types(None), Ok(()));
        assert_matches!(
            require_valid_types(Some(Box::from("nope:Device"))),
            Err(BodyParsingError::InvalidTypes(ref raw_types)) if &**raw_types == "nope:Device"
        );
    }

    fn namespaces() -> Namespace {
        let mut namespaces = Namespace::empty();
        namespaces.put("wsdp", constants::XML_WSDP_NAMESPACE);
        namespaces.put("x", "urn:x");

        namespaces
    }

    #[test]
    fn resolves_prefixed_qname() {
        let namespaces = namespaces();

        assert_eq!(
            resolve_qname("wsdp:Device", &namespaces),
            Some((constants::XML_WSDP_NAMESPACE, "Device"))
        );
        assert_eq!(
            resolve_qname("x:D\u{e9}vice", &namespaces),
            Some(("urn:x", "D\u{e9}vice"))
        );
    }

    #[test]
    fn resolves_unprefixed_qname_in_the_default_namespace() {
        let mut namespaces = namespaces();
        namespaces.put("", constants::XML_WSDP_NAMESPACE);

        assert_eq!(
            resolve_qname("Device", &namespaces),
            Some((constants::XML_WSDP_NAMESPACE, "Device"))
        );
    }

    #[test]
    fn resolves_unprefixed_qname_without_a_default_namespace() {
        assert_eq!(resolve_qname("Device", &namespaces()), Some(("", "Device")));
    }

    #[test]
    fn rejects_qname_with_undeclared_prefix() {
        assert_eq!(resolve_qname("nope:Device", &namespaces()), None);
    }

    #[test]
    fn rejects_values_that_are_not_qnames() {
        let namespaces = namespaces();

        for raw in [
            "wsdp:Device:x",
            ":Device",
            "wsdp:",
            "1bad",
            "wsdp:1bad",
            "wsdp :Device",
        ] {
            assert_eq!(resolve_qname(raw, &namespaces), None, "{}", raw);
        }
    }

    #[test]
    fn splits_list_items_at_xml_white_space_only() {
        assert_eq!(
            list_items(" a\u{a0}b\tc\r\nd ").collect::<Vec<_>>(),
            ["a\u{a0}b", "c", "d"]
        );
    }

    #[test]
    fn parses_minimal_sequence() {
        let EndpointMetadata {
            raw_xaddrs,
            metadata_version,
            ..
        } = parse(&[ENDPOINT_REFERENCE, METADATA_VERSION]).unwrap();

        assert_eq!(raw_xaddrs, None);
        assert_eq!(metadata_version, Some(Ok(1)));
    }

    #[test]
    fn parses_metadata_version_above_unsigned_int() {
        let EndpointMetadata {
            metadata_version, ..
        } = parse(&[
            ENDPOINT_REFERENCE,
            "<wsd:MetadataVersion>4294967296</wsd:MetadataVersion>",
        ])
        .unwrap();

        assert_eq!(metadata_version, Some(Ok(u64::from(u32::MAX) + 1)));
    }

    #[test]
    fn parses_without_metadata_version() {
        let EndpointMetadata {
            metadata_version, ..
        } = parse(&[ENDPOINT_REFERENCE]).unwrap();

        assert_eq!(metadata_version, None);
    }

    #[test]
    fn reads_malformed_metadata_version_as_error() {
        let EndpointMetadata {
            metadata_version, ..
        } = parse(&[
            ENDPOINT_REFERENCE,
            "<wsd:MetadataVersion>two</wsd:MetadataVersion>",
        ])
        .unwrap();

        assert_eq!(metadata_version, Some(Err(Box::from("two"))));
    }

    #[test]
    fn reads_empty_metadata_version_as_error() {
        let EndpointMetadata {
            metadata_version, ..
        } = parse(&[ENDPOINT_REFERENCE, "<wsd:MetadataVersion />"]).unwrap();

        assert_eq!(metadata_version, Some(Err(Box::from(""))));
    }

    #[test]
    fn requires_metadata_version() {
        assert_matches!(require_metadata_version(Some(Ok(1))), Ok(()));
        assert_matches!(
            require_metadata_version(None),
            Err(BodyParsingError::Xml(XmlError::MissingElement(ref name))) if &**name == "wsd:MetadataVersion"
        );
    }

    #[test]
    fn requires_valid_metadata_version() {
        assert_matches!(
            require_metadata_version(Some(Err(Box::from("two")))),
            Err(BodyParsingError::InvalidMetadataVersion(ref text)) if &**text == "two"
        );
    }

    #[test]
    fn parses_unsigned_int_between_xml_white_space() {
        assert_eq!(parse_unsigned_int(" \t\n\r007 \t\n\r"), Some(7));
    }

    #[test]
    fn rejects_signed_unsigned_int() {
        assert_eq!(parse_unsigned_int("+2"), None);
        assert_eq!(parse_unsigned_int("-0"), None);
    }

    #[test]
    fn rejects_unsigned_int_between_other_white_space() {
        assert_eq!(parse_unsigned_int("\u{a0}2"), None);
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
