use std::io::Read;

use hashbrown::HashSet;
use tracing::{Level, event};
use xml::name::OwnedName;
use xml::namespace::Namespace;
use xml::reader::XmlEvent;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::soap::parser::generic::{list_items, resolve_qname};
use crate::xml::{XmlError, XmlReader, find_child, read_text};

/// Namespace and local name.
type QName = (Box<str>, Box<str>);

pub(crate) struct Probe {
    /// `None` means any Type, the implied value of an omitted `wsd:Types`, see documentation/ws-discovery.pdf, 5.2.
    pub types: Option<HashSet<QName>>,
    pub scopes: ProbeScopes,
}

/// The `wsd:Scopes` of a Probe.
#[derive(Debug)]
pub(crate) enum ProbeScopes {
    /// An absent `MatchBy`, an empty one, or one in `MATCH_BY_RULES`.
    SupportedMatchBy(ScopeList),
    /// A `MatchBy` outside `MATCH_BY_RULES`.
    UnsupportedMatchBy,
}

/// The scope list of a `wsd:Scopes`.
#[derive(Debug)]
pub(crate) enum ScopeList {
    /// An absent `wsd:Scopes`, or an empty one.
    Any,
    /// At least one scope.
    Listed,
}

/// The `MatchBy` URIs of documentation/ws-discovery.pdf, 5.1, without their matching rules, see `Probe::matches`.
const MATCH_BY_RULES: [&str; 4] = [
    "http://schemas.xmlsoap.org/ws/2005/04/discovery/rfc2396",
    "http://schemas.xmlsoap.org/ws/2005/04/discovery/uuid",
    "http://schemas.xmlsoap.org/ws/2005/04/discovery/ldap",
    "http://schemas.xmlsoap.org/ws/2005/04/discovery/strcmp0",
];

/// The children of `wsd:Probe` in `ProbeType` sequence order, see documentation/ws-discovery.pdf, Appendix II.
#[derive(Clone, Copy, PartialEq, PartialOrd)]
enum ProbeChild {
    Types,
    Scopes,
    Extension,
}

impl ProbeChild {
    /// `None` for a child outside the sequence: an unknown `wsd:` element or one without a namespace.
    fn from_name(name: &OwnedName) -> Option<Self> {
        match name.namespace_ref() {
            Some(constants::XML_WSD_NAMESPACE) => match &*name.local_name {
                "Types" => Some(Self::Types),
                "Scopes" => Some(Self::Scopes),
                _ => None,
            },
            Some(_) => Some(Self::Extension),
            None => None,
        }
    }
}

/// This takes in a reader that is stopped at the body tag.
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
///
/// # Returns
///
/// * `Ok(Probe {})`: when we were able to successfully decode the XML as a `Probe`
/// * `Err(_)`: Anything went wrong trying to parse the XML
pub(crate) fn parse_probe<R>(reader: &mut XmlReader<R>) -> Result<Probe, BodyParsingError>
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "Probe")?;

    let mut types = None;
    let mut scopes = ProbeScopes::SupportedMatchBy(ScopeList::Any);
    let mut last_child = None;

    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement {
                name,
                attributes,
                namespace,
            } if reader.depth() == entry_depth + 1 => {
                let Some(child) = ProbeChild::from_name(&name) else {
                    // not part of `ProbeType`, ignored
                    continue;
                };

                // extension elements repeat, every other child appears at most once
                if child != ProbeChild::Extension && last_child >= Some(child) {
                    return Err(BodyParsingError::InvalidElementOrder);
                }

                last_child = Some(child);

                match child {
                    ProbeChild::Types => {
                        let raw_types = read_text(reader)?.unwrap_or_default();

                        types = Some(parse_types(&raw_types, &namespace)?);
                    },
                    ProbeChild::Scopes => {
                        let match_by = attributes
                            .iter()
                            .find(|attribute| {
                                attribute.name.namespace.is_none()
                                    && attribute.name.local_name == "MatchBy"
                            })
                            .map(|attribute| &*attribute.value);

                        scopes = parse_scopes(match_by, &read_text(reader)?.unwrap_or_default());
                    },
                    ProbeChild::Extension => {},
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

    Ok(Probe { types, scopes })
}

fn parse_scopes(match_by: Option<&str>, raw_scopes: &str) -> ProbeScopes {
    match match_by {
        // documentation/ws-discovery.pdf, 5.2, implies `rfc2396` for an omitted `MatchBy`
        // an empty `MatchBy` is treated as omitted, because WSDAPI treats it that way too
        None | Some("") => {},
        // documentation/ws-discovery.pdf, 5.1, does not define how `MatchBy` URIs are compared
        // `MatchBy` is compared exactly, because WSDAPI compares it exactly too
        Some(match_by) if MATCH_BY_RULES.contains(&match_by) => {},
        Some(match_by) => {
            event!(Level::DEBUG, match_by, "Probe with an unsupported MatchBy");

            return ProbeScopes::UnsupportedMatchBy;
        },
    }

    let scope_list = if list_items(raw_scopes).next().is_some() {
        event!(Level::DEBUG, scopes = raw_scopes, "Probe lists scopes");

        ScopeList::Listed
    } else {
        ScopeList::Any
    };

    ProbeScopes::SupportedMatchBy(scope_list)
}

/// Resolves the `xs:QName` list of `wsd:Types` against the namespaces in scope of the element.
fn parse_types(
    raw_types: &str,
    namespaces: &Namespace,
) -> Result<HashSet<QName>, BodyParsingError> {
    list_items(raw_types)
        .map(|raw_type| {
            resolve_qname(raw_type, namespaces)
                .map(|(namespace, local_name)| (Box::from(namespace), Box::from(local_name)))
        })
        .collect::<Option<_>>()
        .ok_or_else(|| BodyParsingError::InvalidTypes(Box::from(raw_types)))
}

impl Probe {
    /// Implements the Type matching of documentation/ws-discovery.pdf, 5.1.
    /// Implements its Scope matching in part, because WSDAPI matches Scopes this way for a Target Service with omitted Scopes:
    /// - returns `false` for any listed scope, the implied `.../discovery/adhoc` scope of 4.1 included.
    /// - returns `false` for an unsupported `MatchBy`. 5.1 requires a match for an empty scope list.
    pub(crate) fn matches(&self) -> bool {
        let scopes_match = match self.scopes {
            ProbeScopes::SupportedMatchBy(ScopeList::Any) => true,
            ProbeScopes::SupportedMatchBy(ScopeList::Listed) | ProbeScopes::UnsupportedMatchBy => {
                false
            },
        };

        scopes_match
            && self.types.as_ref().is_none_or(|types| {
                types.iter().all(|&(ref namespace, ref name)| {
                    constants::ADVERTISED_TYPES.iter().any(|advertised| {
                        advertised.namespace == &**namespace && advertised.local_name == &**name
                    })
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
    use crate::soap::parser::probe::{MATCH_BY_RULES, Probe, ProbeScopes, ScopeList, parse_probe};
    use crate::xml::XmlReader;

    fn build_probe(types: &[(&str, &str)]) -> Probe {
        Probe {
            types: Some(
                types
                    .iter()
                    .map(|&(namespace, name)| (Box::from(namespace), Box::from(name)))
                    .collect::<HashSet<_>>(),
            ),
            scopes: ProbeScopes::SupportedMatchBy(ScopeList::Any),
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
        let probe = Probe {
            types: None,
            scopes: ProbeScopes::SupportedMatchBy(ScopeList::Any),
        };

        assert!(probe.matches());
    }

    #[test]
    fn listed_scopes_do_not_match() {
        let probe = Probe {
            types: None,
            scopes: ProbeScopes::SupportedMatchBy(ScopeList::Listed),
        };

        assert!(!probe.matches());
    }

    #[test]
    fn unsupported_match_by_does_not_match() {
        let probe = Probe {
            types: None,
            scopes: ProbeScopes::UnsupportedMatchBy,
        };

        assert!(!probe.matches());
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

        assert_matches!(result.err(), Some(BodyParsingError::InvalidTypes(raw_types)) if &*raw_types == "wsdp:Device undeclared:Printer");
    }

    #[test]
    fn rejects_type_with_empty_prefix() {
        let result = parse("<wsd:Types>:Device</wsd:Types>");

        assert_matches!(result.err(), Some(BodyParsingError::InvalidTypes(raw_types)) if &*raw_types == ":Device");
    }

    #[test]
    fn rejects_type_with_empty_local_name() {
        let result = parse("<wsd:Types>wsdp:</wsd:Types>");

        assert_matches!(result.err(), Some(BodyParsingError::InvalidTypes(raw_types)) if &*raw_types == "wsdp:");
    }

    #[test]
    fn rejects_type_with_two_colons() {
        let result = parse("<wsd:Types>wsdp:Device:x</wsd:Types>");

        assert_matches!(result.err(), Some(BodyParsingError::InvalidTypes(raw_types)) if &*raw_types == "wsdp:Device:x");
    }

    #[test]
    fn parses_missing_scopes() {
        let probe = parse("").unwrap();

        assert_matches!(probe.scopes, ProbeScopes::SupportedMatchBy(ScopeList::Any));
    }

    #[test]
    fn parses_empty_scopes() {
        let probe = parse("<wsd:Scopes />").unwrap();

        assert_matches!(probe.scopes, ProbeScopes::SupportedMatchBy(ScopeList::Any));
    }

    #[test]
    fn parses_whitespace_scopes() {
        let probe = parse("<wsd:Scopes> </wsd:Scopes>").unwrap();

        assert_matches!(probe.scopes, ProbeScopes::SupportedMatchBy(ScopeList::Any));
    }

    #[test]
    fn parses_listed_scope() {
        let probe = parse("<wsd:Scopes>urn:x</wsd:Scopes>").unwrap();

        assert_matches!(
            probe.scopes,
            ProbeScopes::SupportedMatchBy(ScopeList::Listed)
        );
    }

    #[test]
    fn parses_adhoc_scope_as_listed() {
        let probe =
            parse("<wsd:Scopes>http://schemas.xmlsoap.org/ws/2005/04/discovery/adhoc</wsd:Scopes>")
                .unwrap();

        assert_matches!(
            probe.scopes,
            ProbeScopes::SupportedMatchBy(ScopeList::Listed)
        );
    }

    #[test]
    fn parses_empty_scopes_with_every_match_by_rule() {
        for match_by in MATCH_BY_RULES {
            let probe = parse(&format!(r#"<wsd:Scopes MatchBy="{}" />"#, match_by)).unwrap();

            assert_matches!(probe.scopes, ProbeScopes::SupportedMatchBy(ScopeList::Any));
        }
    }

    #[test]
    fn parses_empty_match_by_as_absent() {
        let probe = parse(r#"<wsd:Scopes MatchBy="" />"#).unwrap();

        assert_matches!(probe.scopes, ProbeScopes::SupportedMatchBy(ScopeList::Any));
    }

    #[test]
    fn parses_unsupported_match_by() {
        let probe = parse(r#"<wsd:Scopes MatchBy="urn:unknown" />"#).unwrap();

        assert_matches!(probe.scopes, ProbeScopes::UnsupportedMatchBy);
    }

    #[test]
    fn parses_match_by_case_sensitively() {
        let probe = parse(
            r#"<wsd:Scopes MatchBy="HTTP://SCHEMAS.XMLSOAP.ORG/WS/2005/04/DISCOVERY/RFC2396" />"#,
        )
        .unwrap();

        assert_matches!(probe.scopes, ProbeScopes::UnsupportedMatchBy);
    }

    #[test]
    fn parses_unsupported_match_by_before_listed_scopes() {
        let probe = parse(r#"<wsd:Scopes MatchBy="urn:unknown">urn:x</wsd:Scopes>"#).unwrap();

        assert_matches!(probe.scopes, ProbeScopes::UnsupportedMatchBy);
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
