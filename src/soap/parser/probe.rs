use std::io::Read;

use hashbrown::HashSet;
use tracing::{Level, event};
use xml::reader::XmlEvent;

use crate::constants;
use crate::xml::{GenericParsingError, Wrapper, find_descendant, read_text};

type ParsedProbeResult = Result<Probe, GenericParsingError>;

pub struct Probe {
    pub types: HashSet<(Box<str>, Box<str>)>,
}

/// This takes in a reader that is stopped at the body tag.
/// This function makes NO claims about the position of the reader
/// should the structure XML be invalid (e.g. missing `Address`)
/// Returns
/// * `Ok(Probe {})`: when we were able to successfully decode the XML as a `Probe`
/// * `Err(_)`: Anything went wrong trying to parse the XML
pub fn parse_probe<R>(reader: &mut Wrapper<R>) -> ParsedProbeResult
where
    R: Read,
{
    find_descendant(reader, Some(constants::XML_WSD_NAMESPACE), "Probe")?;

    let mut raw_types_and_namespaces = None;

    let mut depth = 0_usize;
    loop {
        match reader.next()? {
            XmlEvent::StartElement {
                name, namespace, ..
            } => {
                depth += 1;

                if depth == 1 && name.namespace_ref() == Some(constants::XML_WSD_NAMESPACE) {
                    match &*name.local_name {
                        "Scopes" => {
                            let text = read_text(reader)?;
                            let raw_scopes = text.unwrap_or_default();

                            event!(
                                Level::DEBUG,
                                scopes = %raw_scopes,
                                "Ignoring unsupported scopes in probe request"
                            );

                            // read_text consumed the closing `Scopes`
                            depth -= 1;
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
                if depth == 0 {
                    // we've exited the Probe
                    break;
                }

                depth -= 1;
            },
            XmlEvent::EndDocument => {
                break;
            },
            XmlEvent::CData(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::StartDocument { .. }
            | XmlEvent::Whitespace(_) => {
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
        let mut requested_type_match = false;

        for &(ref namespace, ref name) in &self.types {
            match (&**namespace, &**name) {
                (constants::XML_WSDP_NAMESPACE, "Device")
                | (constants::XML_PUB_NAMESPACE, "Computer") => {
                    requested_type_match = true;
                    break;
                },
                _ => {
                    continue;
                },
            }
        }

        requested_type_match
    }
}
