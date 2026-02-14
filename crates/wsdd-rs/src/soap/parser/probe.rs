use std::io::Read;

use hashbrown::HashSet;
use tracing::{Level, event};
use xml::reader::XmlEvent;

use crate::constants;
use crate::soap::parser::BodyParsingError;
use crate::xml::{Wrapper, XmlError, find_child, read_text};

type ParsedProbeResult = Result<Probe, BodyParsingError>;

pub struct Probe {
    pub types: HashSet<(Box<str>, Box<str>)>,
}

/// This takes in a reader that is stopped at the body tag.
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`).
///
/// # Returns
///
/// * `Ok(Probe {})`: when we were able to successfully decode the XML as a `Probe`
/// * `Err(_)`: Anything went wrong trying to parse the XML
pub fn parse_probe<R>(reader: &mut Wrapper<R>) -> ParsedProbeResult
where
    R: Read,
{
    find_child(reader, Some(constants::XML_WSD_NAMESPACE), "Probe")?;

    let mut raw_types_and_namespaces = None;

    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement {
                name, namespace, ..
            } => {
                if reader.depth() == entry_depth + 1
                    && name.namespace_ref() == Some(constants::XML_WSD_NAMESPACE)
                {
                    match &*name.local_name {
                        "Scopes" => {
                            let text = read_text(reader)?;
                            let raw_scopes = text.unwrap_or_default();

                            event!(
                                Level::DEBUG,
                                scopes = %raw_scopes,
                                "Ignoring unsupported scopes in probe request"
                            );
                        },
                        "Types" => {
                            raw_types_and_namespaces =
                                read_text(reader)?.map(|text| (text, namespace));

                            break;
                        },
                        _ => {},
                    }
                }
            },
            XmlEvent::EndElement { .. } => {
                if reader.depth() < entry_depth {
                    // we've exited the Probe
                    break;
                }
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

    let Some((raw_types, namespaces)) = raw_types_and_namespaces else {
        event!(Level::DEBUG, "Probe message lacks wsd:Types element.");

        return Ok(Probe {
            types: HashSet::new(),
        });
    };

    let mut types = HashSet::new();

    for raw_type in raw_types.split_whitespace() {
        // split
        let Some((prefix, name)) = raw_type.split_once(':') else {
            continue;
        };

        let Some(namespace) = namespaces.get(prefix) else {
            continue;
        };

        types.insert((
            namespace.to_owned().into_boxed_str(),
            name.to_owned().into_boxed_str(),
        ));
    }

    Ok(Probe { types })
}

impl Probe {
    pub fn requested_type_match(&self) -> bool {
        self.types.iter().any(|&(ref namespace, ref name)| {
            matches!(
                (&**namespace, &**name),
                (constants::XML_WSDP_NAMESPACE, "Device")
                    | (constants::XML_PUB_NAMESPACE, "Computer")
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use hashbrown::HashSet;

    use crate::constants;
    use crate::soap::parser::probe::Probe;

    fn build_probe(types: &[(&str, &str)]) -> Probe {
        Probe {
            types: types
                .iter()
                .map(|&(namespace, name)| (Box::from(namespace), Box::from(name)))
                .collect::<HashSet<_>>(),
        }
    }

    #[test]
    fn both_types_matches() {
        let probe = build_probe(&[
            (constants::XML_WSDP_NAMESPACE, "Device"),
            (constants::XML_PUB_NAMESPACE, "Computer"),
        ]);

        assert!(probe.requested_type_match());
    }

    #[test]
    fn wsdp_device_alone_matches() {
        let probe = build_probe(&[(constants::XML_WSDP_NAMESPACE, "Device")]);

        assert!(probe.requested_type_match());
    }

    #[test]
    fn pub_computer_alone_matches() {
        let probe = build_probe(&[(constants::XML_PUB_NAMESPACE, "Computer")]);

        assert!(probe.requested_type_match());
    }

    #[test]
    fn right_namespace_wrong_name_does_not_match() {
        let probe = build_probe(&[(constants::XML_WSDP_NAMESPACE, "Printer")]);

        assert!(!probe.requested_type_match());
    }

    #[test]
    fn right_name_wrong_namespace_does_not_match() {
        let probe = build_probe(&[("urn:wrong", "Device")]);

        assert!(!probe.requested_type_match());
    }

    #[test]
    fn all_wrong_does_not_match() {
        let probe = build_probe(&[("urn:wrong", "Wrong")]);

        assert!(!probe.requested_type_match());
    }
}
