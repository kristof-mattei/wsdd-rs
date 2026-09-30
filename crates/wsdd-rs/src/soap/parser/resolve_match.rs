use std::io::Read;

use xml::reader::XmlEvent;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::soap::parser::generic::{
    EndpointMetadata, extract_endpoint_metadata, require_metadata_version, require_valid_types,
};
use crate::wsd::device::DeviceUri;
use crate::xml::{XmlError, XmlReader, find_child};

type ParsedResolveMatchesResult = Result<ResolveMatches, BodyParsingError>;

pub struct ResolveMatches {
    pub resolve_match: Option<ResolveMatch>,
}

pub struct ResolveMatch {
    pub endpoint: DeviceUri,
    pub raw_xaddrs: Option<Box<str>>,
}

/// This takes in a reader that is stopped at the body tag.
///
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
pub fn parse_resolve_matches<R>(reader: &mut XmlReader<R>) -> ParsedResolveMatchesResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "ResolveMatches")?;

    let mut resolve_match = None;
    // `ResolveMatchesType` is an optional `ResolveMatch`, then extension elements (WS-Discovery, Appendix II)
    let mut extension_seen = false;

    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement { name, .. } if reader.depth() == entry_depth + 1 => {
                match name.namespace_ref() {
                    Some(constants::XML_WSD_NAMESPACE) if name.local_name == "ResolveMatch" => {
                        if resolve_match.is_some() || extension_seen {
                            return Err(BodyParsingError::InvalidElementOrder);
                        }

                        let EndpointMetadata {
                            endpoint,
                            raw_xaddrs,
                            metadata_version,
                            invalid_types,
                        } = extract_endpoint_metadata(reader)?;

                        require_metadata_version(metadata_version)?;
                        require_valid_types(invalid_types)?;

                        resolve_match = Some(ResolveMatch {
                            endpoint,
                            raw_xaddrs,
                        });
                    },
                    Some(constants::XML_WSD_NAMESPACE) | None => {
                        // not part of `ResolveMatchesType`, ignored
                    },
                    Some(_) => {
                        extension_seen = true;
                    },
                }
            },
            XmlEvent::EndElement { .. } if reader.depth() < entry_depth => {
                // we've exited the ResolveMatches
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

    Ok(ResolveMatches { resolve_match })
}

#[cfg(test)]
mod tests {
    use pretty_assertions::{assert_eq, assert_matches};
    use xml::ParserConfig;

    use crate::constants;
    use crate::soap::parser::BodyParsingError;
    use crate::soap::parser::resolve_match::{ResolveMatches, parse_resolve_matches};
    use crate::xml::{XmlError, XmlReader};

    const EXTENSION: &str = r#"<ext:Extension xmlns:ext="urn:ext" />"#;
    const RESOLVE_MATCH: &str = "<wsd:ResolveMatch><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:XAddrs>http://192.168.100.5:5357/</wsd:XAddrs><wsd:MetadataVersion>1</wsd:MetadataVersion></wsd:ResolveMatch>";

    fn parse(children: &[&str]) -> Result<ResolveMatches, BodyParsingError> {
        let xml = format!(
            r#"<wsd:ResolveMatches xmlns:wsa="{}" xmlns:wsd="{}">{}</wsd:ResolveMatches>"#,
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

        parse_resolve_matches(&mut reader)
    }

    #[test]
    fn parses_resolve_matches_without_match() {
        let resolve_matches = parse(&[]).unwrap();

        assert!(resolve_matches.resolve_match.is_none());
    }

    #[test]
    fn parses_resolve_match() {
        let resolve_matches = parse(&[RESOLVE_MATCH]).unwrap();

        let resolve_match = resolve_matches.resolve_match.unwrap();

        assert_eq!(
            &*resolve_match.endpoint,
            "urn:uuid:00000000-0000-0000-0000-000000000001"
        );
        assert_eq!(
            resolve_match.raw_xaddrs.as_deref(),
            Some("http://192.168.100.5:5357/")
        );
    }

    #[test]
    fn parses_extension_after_resolve_match() {
        let resolve_matches = parse(&[RESOLVE_MATCH, EXTENSION]).unwrap();

        assert!(resolve_matches.resolve_match.is_some());
    }

    #[test]
    fn rejects_second_resolve_match() {
        let result = parse(&[RESOLVE_MATCH, RESOLVE_MATCH]);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_resolve_match_after_extension() {
        let result = parse(&[EXTENSION, RESOLVE_MATCH]);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_resolve_match_without_metadata_version() {
        let result = parse(&[
            "<wsd:ResolveMatch><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:XAddrs>http://192.168.100.5:5357/</wsd:XAddrs></wsd:ResolveMatch>",
        ]);

        assert_matches!(
            result.map(|_| ()),
            Err(BodyParsingError::Xml(XmlError::MissingElement(_)))
        );
    }

    #[test]
    fn rejects_resolve_match_with_undeclared_type_prefix() {
        let result = parse(&[
            "<wsd:ResolveMatch><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:Types>nope:Device</wsd:Types><wsd:XAddrs>http://192.168.100.5:5357/</wsd:XAddrs><wsd:MetadataVersion>1</wsd:MetadataVersion></wsd:ResolveMatch>",
        ]);

        assert_matches!(
            result.map(|_| ()),
            Err(BodyParsingError::InvalidTypes(ref raw_types)) if &**raw_types == "nope:Device"
        );
    }
}
