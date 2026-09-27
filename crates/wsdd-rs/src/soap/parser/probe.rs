use std::io::Read;

use hashbrown::HashSet;
use tracing::{Level, event};
use xml::namespace::{NS_EMPTY_URI, NS_NO_PREFIX, Namespace};
use xml::reader::XmlEvent;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::xml::{XmlError, XmlReader, find_child, read_text};

type ParsedProbeResult = Result<Probe, BodyParsingError>;

/// Namespace and local name.
type QName = (Box<str>, Box<str>);

pub struct Probe {
    /// `None` when the Probe has no `wsd:Types`, which implies any Type (WS-Discovery, Section 5.2).
    pub types: Option<HashSet<QName>>,
}

/// The children of `wsd:Probe` in `ProbeType` sequence order (WS-Discovery, Appendix II).
#[derive(PartialEq, PartialOrd)]
enum ProbeChild {
    Types,
    Scopes,
    Extension,
}

/// This takes in a reader that is stopped at the body tag.
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
///
/// # Returns
///
/// * `Ok(Probe {})`: when we were able to successfully decode the XML as a `Probe`
/// * `Err(_)`: Anything went wrong trying to parse the XML
pub fn parse_probe<R>(reader: &mut XmlReader<R>) -> ParsedProbeResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "Probe")?;

    let mut types = None;
    let mut last_child = None;

    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement {
                name, namespace, ..
            } if reader.depth() == entry_depth + 1 => {
                match (name.namespace_ref(), &*name.local_name) {
                    (Some(constants::XML_WSD_NAMESPACE), "Types") => {
                        if last_child >= Some(ProbeChild::Types) {
                            return Err(BodyParsingError::InvalidElementOrder);
                        }

                        last_child = Some(ProbeChild::Types);

                        let raw_types = read_text(reader)?.unwrap_or_default();

                        types = Some(parse_types(&raw_types, &namespace)?);
                    },
                    (Some(constants::XML_WSD_NAMESPACE), "Scopes") => {
                        if last_child >= Some(ProbeChild::Scopes) {
                            return Err(BodyParsingError::InvalidElementOrder);
                        }

                        last_child = Some(ProbeChild::Scopes);

                        let text = read_text(reader)?;
                        let raw_scopes = text.unwrap_or_default();

                        event!(
                            Level::DEBUG,
                            scopes = %raw_scopes,
                            "Ignoring unsupported scopes in probe request"
                        );
                    },
                    (Some(constants::XML_WSD_NAMESPACE) | None, _) => {
                        // not part of `ProbeType`, ignored
                    },
                    (Some(_), _) => {
                        last_child = Some(ProbeChild::Extension);
                    },
                }
            },
            XmlEvent::EndElement { .. } if reader.depth() < entry_depth => {
                // we've exited the Probe
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

    if types.is_none() {
        event!(Level::DEBUG, "Probe message lacks wsd:Types element.");
    }

    Ok(Probe { types })
}

/// Resolves the `xs:QName` list of `wsd:Types` against the namespaces in scope of the element.
fn parse_types(
    raw_types: &str,
    namespaces: &Namespace,
) -> Result<HashSet<QName>, BodyParsingError> {
    raw_types
        .split_whitespace()
        .map(|raw_type| {
            let resolved = match raw_type.split_once(':') {
                None => Some((
                    namespaces.get(NS_NO_PREFIX).unwrap_or(NS_EMPTY_URI),
                    raw_type,
                )),
                Some(("", _) | (_, "")) => None,
                Some((prefix, local_name)) => namespaces
                    .get(prefix)
                    .map(|namespace| (namespace, local_name)),
            };

            let Some((namespace, local_name)) = resolved else {
                return Err(BodyParsingError::InvalidQName(Box::from(raw_type)));
            };

            Ok((Box::from(namespace), Box::from(local_name)))
        })
        .collect()
}

impl Probe {
    /// WS-Discovery, Section 5.1, for Types. Scopes are not matched.
    pub fn matches(&self) -> bool {
        self.types.as_ref().is_none_or(|types| {
            types.iter().all(|&(ref namespace, ref name)| {
                matches!(
                    (&**namespace, &**name),
                    (constants::XML_WSDP_NAMESPACE, "Device")
                        | (constants::XML_PUB_NAMESPACE, "Computer")
                )
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use hashbrown::HashSet;
    use pretty_assertions::{assert_eq, assert_matches};
    use xml::ParserConfig;
    use xml::reader::XmlEvent;

    use crate::constants;
    use crate::soap::parser::BodyParsingError;
    use crate::soap::parser::probe::{Probe, parse_probe};
    use crate::xml::XmlReader;

    fn build_probe(types: &[(&str, &str)]) -> Probe {
        Probe {
            types: Some(
                types
                    .iter()
                    .map(|&(namespace, name)| (Box::from(namespace), Box::from(name)))
                    .collect::<HashSet<_>>(),
            ),
        }
    }

    fn make_reader(xml: &str) -> XmlReader<&[u8]> {
        let reader = ParserConfig::new()
            .cdata_to_characters(true)
            .ignore_comments(true)
            .trim_whitespace(true)
            .whitespace_to_characters(true)
            .create_reader(xml.as_bytes());

        XmlReader::new(reader)
    }

    fn probe_xml(children: &str) -> String {
        format!(
            r#"<wsd:Probe xmlns:wsd="{}" xmlns:wsdp="{}">{}</wsd:Probe>"#,
            constants::XML_WSD_NAMESPACE,
            constants::XML_WSDP_NAMESPACE,
            children
        )
    }

    fn parse(children: &str) -> Result<Probe, BodyParsingError> {
        parse_probe(&mut make_reader(&probe_xml(children)))
    }

    #[test]
    fn no_types_matches() {
        let probe = Probe { types: None };

        assert!(probe.matches());
    }

    #[test]
    fn empty_types_matches() {
        let probe = build_probe(&[]);

        assert!(probe.matches());
    }

    #[test]
    fn both_types_matches() {
        let probe = build_probe(&[
            (constants::XML_WSDP_NAMESPACE, "Device"),
            (constants::XML_PUB_NAMESPACE, "Computer"),
        ]);

        assert!(probe.matches());
    }

    #[test]
    fn wsdp_device_alone_matches() {
        let probe = build_probe(&[(constants::XML_WSDP_NAMESPACE, "Device")]);

        assert!(probe.matches());
    }

    #[test]
    fn pub_computer_alone_matches() {
        let probe = build_probe(&[(constants::XML_PUB_NAMESPACE, "Computer")]);

        assert!(probe.matches());
    }

    #[test]
    fn offered_and_unoffered_types_do_not_match() {
        let probe = build_probe(&[
            (constants::XML_WSDP_NAMESPACE, "Device"),
            ("urn:other", "Printer"),
        ]);

        assert!(!probe.matches());
    }

    #[test]
    fn right_namespace_wrong_name_does_not_match() {
        let probe = build_probe(&[(constants::XML_WSDP_NAMESPACE, "Printer")]);

        assert!(!probe.matches());
    }

    #[test]
    fn right_name_wrong_namespace_does_not_match() {
        let probe = build_probe(&[("urn:wrong", "Device")]);

        assert!(!probe.matches());
    }

    #[test]
    fn all_wrong_does_not_match() {
        let probe = build_probe(&[("urn:wrong", "Wrong")]);

        assert!(!probe.matches());
    }

    #[test]
    fn parses_missing_types() {
        let probe = parse("").unwrap();

        assert!(probe.types.is_none());
    }

    #[test]
    fn parses_empty_types() {
        let probe = parse("<wsd:Types />").unwrap();

        assert_eq!(probe.types, Some(HashSet::new()));
    }

    #[test]
    fn parses_prefixed_type() {
        let probe = parse("<wsd:Types>wsdp:Device</wsd:Types>").unwrap();

        assert_eq!(
            probe.types,
            Some(HashSet::from([(
                Box::from(constants::XML_WSDP_NAMESPACE),
                Box::from("Device")
            )]))
        );
    }

    #[test]
    fn parses_unprefixed_type_in_default_namespace() {
        let probe = parse(&format!(
            r#"<wsd:Types xmlns="{}">Device</wsd:Types>"#,
            constants::XML_WSDP_NAMESPACE
        ))
        .unwrap();

        assert_eq!(
            probe.types,
            Some(HashSet::from([(
                Box::from(constants::XML_WSDP_NAMESPACE),
                Box::from("Device")
            )]))
        );
    }

    #[test]
    fn parses_unprefixed_type_without_default_namespace() {
        let probe = parse("<wsd:Types>Device</wsd:Types>").unwrap();

        assert_eq!(
            probe.types,
            Some(HashSet::from([(Box::from(""), Box::from("Device"))]))
        );
    }

    #[test]
    fn rejects_type_with_undeclared_prefix() {
        let result = parse("<wsd:Types>wsdp:Device undeclared:Printer</wsd:Types>");

        assert_matches!(result.err(), Some(BodyParsingError::InvalidQName(raw_type)) if &*raw_type == "undeclared:Printer");
    }

    #[test]
    fn rejects_type_with_empty_prefix() {
        let result = parse("<wsd:Types>:Device</wsd:Types>");

        assert_matches!(result.err(), Some(BodyParsingError::InvalidQName(raw_type)) if &*raw_type == ":Device");
    }

    #[test]
    fn rejects_type_with_empty_local_name() {
        let result = parse("<wsd:Types>wsdp:</wsd:Types>");

        assert_matches!(result.err(), Some(BodyParsingError::InvalidQName(raw_type)) if &*raw_type == "wsdp:");
    }

    #[test]
    fn consumes_scopes_after_types() {
        let xml = probe_xml(
            "<wsd:Types>wsdp:Device</wsd:Types><wsd:Scopes>http://example.com/scope</wsd:Scopes>",
        );
        let mut reader = make_reader(&xml);

        let probe = parse_probe(&mut reader).unwrap();

        assert!(probe.types.is_some());
        assert_matches!(reader.next(), Ok(XmlEvent::EndDocument));
    }

    #[test]
    fn parses_extension_after_scopes() {
        let probe = parse(
            r#"<wsd:Types>wsdp:Device</wsd:Types><wsd:Scopes>http://example.com/scope</wsd:Scopes><ext:Extension xmlns:ext="urn:ext" />"#,
        )
        .unwrap();

        assert!(probe.types.is_some());
    }

    #[test]
    fn rejects_second_types() {
        let result = parse("<wsd:Types>wsdp:Printer</wsd:Types><wsd:Types>wsdp:Device</wsd:Types>");

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_second_scopes() {
        let result = parse(
            "<wsd:Scopes>http://example.com/a</wsd:Scopes><wsd:Scopes>http://example.com/b</wsd:Scopes>",
        );

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_types_after_scopes() {
        let result = parse(
            "<wsd:Scopes>http://example.com/scope</wsd:Scopes><wsd:Types>wsdp:Device</wsd:Types>",
        );

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_types_after_extension() {
        let result =
            parse(r#"<ext:Extension xmlns:ext="urn:ext" /><wsd:Types>wsdp:Device</wsd:Types>"#);

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }

    #[test]
    fn rejects_scopes_after_extension() {
        let result = parse(
            r#"<ext:Extension xmlns:ext="urn:ext" /><wsd:Scopes>http://example.com/scope</wsd:Scopes>"#,
        );

        assert_matches!(result.err(), Some(BodyParsingError::InvalidElementOrder));
    }
}
