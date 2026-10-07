use std::io::Read;

use xml::reader::XmlEvent;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::soap::parser::app_sequence::AppSequence;
use crate::soap::parser::generic::{
    EndpointMetadata, extract_endpoint_metadata, require_metadata_version, require_valid_types,
};
use crate::wsd::device::DeviceUri;
use crate::xml::{XmlError, XmlReader, find_child};

type ParsedProbeMatchesResult = Result<ProbeMatches, BodyParsingError>;

pub struct ProbeMatches {
    pub app_sequence: AppSequence,
    pub matches: Vec<ProbeMatch>,
}

pub struct ProbeMatch {
    pub endpoint: DeviceUri,
    pub raw_xaddrs: Option<Box<str>>,
    pub metadata_version: u64,
}

/// This takes in a reader that is stopped at the body tag.
///
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
pub fn parse_probe_matches<R>(
    reader: &mut XmlReader<R>,
    app_sequence: AppSequence,
) -> ParsedProbeMatchesResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "ProbeMatches")?;

    let mut matches = Vec::new();
    // `ProbeMatchesType` is any number of `ProbeMatch`, then extension elements (WS-Discovery, Appendix II)
    let mut extension_seen = false;

    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement { name, .. } if reader.depth() == entry_depth + 1 => {
                match name.namespace_ref() {
                    Some(constants::XML_WSD_NAMESPACE) if name.local_name == "ProbeMatch" => {
                        if extension_seen {
                            return Err(BodyParsingError::InvalidElementOrder);
                        }

                        let EndpointMetadata {
                            endpoint,
                            raw_xaddrs,
                            metadata_version,
                            invalid_types,
                        } = extract_endpoint_metadata(reader)?;

                        let metadata_version = require_metadata_version(metadata_version)?;

                        require_valid_types(invalid_types)?;

                        matches.push(ProbeMatch {
                            endpoint,
                            raw_xaddrs: raw_xaddrs.into_text(),
                            metadata_version,
                        });
                    },
                    Some(constants::XML_WSD_NAMESPACE) | None => {
                        // not part of `ProbeMatchesType`, ignored
                    },
                    Some(_) => {
                        extension_seen = true;
                    },
                }
            },
            XmlEvent::EndElement { .. } if reader.depth() < entry_depth => {
                // we've exited the ProbeMatches
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

    Ok(ProbeMatches {
        app_sequence,
        matches,
    })
}

#[cfg(test)]
mod tests {
    use pretty_assertions::{assert_eq, assert_matches};
    use xml::ParserConfig;

    use crate::constants;
    use crate::soap::parser::BodyParsingError;
    use crate::soap::parser::app_sequence::AppSequence;
    use crate::soap::parser::probe_match::{ProbeMatches, parse_probe_matches};
    use crate::xml::{XmlError, XmlReader};

    const EXTENSION: &str = r#"<ext:Extension xmlns:ext="urn:ext" />"#;

    fn probe_match(address: &str) -> String {
        format!(
            "<wsd:ProbeMatch><wsa:EndpointReference><wsa:Address>{}</wsa:Address></wsa:EndpointReference><wsd:MetadataVersion>1</wsd:MetadataVersion></wsd:ProbeMatch>",
            address
        )
    }

    fn parse(children: &[&str]) -> Result<ProbeMatches, BodyParsingError> {
        let xml = format!(
            r#"<wsd:ProbeMatches xmlns:wsa="{}" xmlns:wsd="{}">{}</wsd:ProbeMatches>"#,
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

        parse_probe_matches(&mut reader, AppSequence::new(1, None, 0))
    }

    #[test]
    fn parses_probe_matches_without_matches() {
        let probe_matches = parse(&[]).unwrap();

        assert!(probe_matches.matches.is_empty());
    }

    #[test]
    fn parses_every_probe_match() {
        let probe_matches = parse(&[
            &probe_match("urn:uuid:00000000-0000-0000-0000-000000000001"),
            &probe_match("urn:uuid:00000000-0000-0000-0000-000000000002"),
        ])
        .unwrap();

        let endpoints = probe_matches
            .matches
            .iter()
            .map(|probe_match| &*probe_match.endpoint)
            .collect::<Vec<_>>();

        assert_eq!(
            endpoints,
            [
                "urn:uuid:00000000-0000-0000-0000-000000000001",
                "urn:uuid:00000000-0000-0000-0000-000000000002"
            ]
        );
    }

    #[test]
    fn parses_extension_after_probe_matches() {
        let probe_matches = parse(&[
            &probe_match("urn:uuid:00000000-0000-0000-0000-000000000001"),
            EXTENSION,
        ])
        .unwrap();

        assert_eq!(probe_matches.matches.len(), 1);
    }

    #[test]
    fn parses_probe_match_with_empty_xaddrs() {
        let probe_matches = parse(&[
            "<wsd:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:XAddrs /><wsd:MetadataVersion>1</wsd:MetadataVersion></wsd:ProbeMatch>",
        ])
        .unwrap();

        assert_eq!(probe_matches.matches[0].raw_xaddrs, None);
    }

    #[test]
    fn rejects_probe_match_after_extension() {
        let result = parse(&[
            EXTENSION,
            &probe_match("urn:uuid:00000000-0000-0000-0000-000000000001"),
        ]);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_probe_match_without_metadata_version() {
        let result = parse(&[
            "<wsd:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference></wsd:ProbeMatch>",
        ]);

        assert_matches!(
            result.map(|_| ()),
            Err(BodyParsingError::Xml(XmlError::MissingElement(_)))
        );
    }

    #[test]
    fn rejects_probe_match_with_undeclared_type_prefix() {
        let result = parse(&[
            "<wsd:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:Types>nope:Device</wsd:Types><wsd:MetadataVersion>1</wsd:MetadataVersion></wsd:ProbeMatch>",
        ]);

        assert_matches!(
            result.map(|_| ()),
            Err(BodyParsingError::InvalidTypes(ref raw_types)) if &**raw_types == "nope:Device"
        );
    }
}
