use std::borrow::ToOwned;
use std::io::BufReader;

use bytes::Bytes;
use color_eyre::eyre;
use hashbrown::{HashMap, HashSet};
use time::OffsetDateTime;
use tracing::{Level, event};
use url::Url;
use xml::EventReader;
use xml::name::Name;
use xml::reader::XmlEvent;

use crate::constants::{
    WSDP_RELATIONSHIP, WSDP_RELATIONSHIP_DIALECT, WSDP_RELATIONSHIP_TYPE_HOST, WSDP_THIS_DEVICE,
    WSDP_THIS_DEVICE_DIALECT, WSDP_THIS_MODEL, WSDP_THIS_MODEL_DIALECT, WSDP_URI,
    XML_PUB_NAMESPACE, XML_WSDP_NAMESPACE, XML_WSX_NAMESPACE,
};
use crate::network_address::NetworkAddress;
use crate::soap::parser;
use crate::xml::{GenericParsingError, parse_generic_body, read_text};

#[derive(Clone, Debug)]
pub struct WSDDiscoveredDevice {
    addresses: HashMap<Box<str>, HashSet<Box<str>>>,
    props: HashMap<Box<str>, Box<str>>,
    display_name: Option<Box<str>>,
    last_seen: OffsetDateTime,
    types: HashSet<Box<str>>,
}

impl WSDDiscoveredDevice {
    pub fn new(
        meta: &Bytes,
        xaddr: &Url,
        network_address: &NetworkAddress,
    ) -> Result<Self, eyre::Report> {
        let mut device = Self {
            addresses: HashMap::new(),
            props: HashMap::new(),
            display_name: None,
            last_seen: OffsetDateTime::UNIX_EPOCH,
            types: HashSet::new(),
        };

        device.update(meta, xaddr, network_address)?;

        Ok(device)
    }

    pub fn addresses(&self) -> &HashMap<Box<str>, HashSet<Box<str>>> {
        &self.addresses
    }

    pub fn props(&self) -> &HashMap<Box<str>, Box<str>> {
        &self.props
    }

    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    pub fn last_seen(&self) -> &OffsetDateTime {
        &self.last_seen
    }

    pub fn types(&self) -> &HashSet<Box<str>> {
        &self.types
    }

    // TODO better error type
    #[expect(clippy::too_many_lines, reason = "WIP")]
    pub fn update(
        &mut self,
        meta: &Bytes,
        xaddr: &Url,
        network_address: &NetworkAddress,
    ) -> Result<(), eyre::Report> {
        let (_header, _has_body, mut reader) = parser::deconstruct_raw(meta)?;

        let (_, _, depth) = parse_generic_body(&mut reader, Some(XML_WSX_NAMESPACE), "Metadata")?;

        if depth != 1 {
            return Err(eyre::Report::msg(
                "`Metadata` not found at depth 1, invalid XML.",
            ));
        }

        // we're now in metadata

        // loop though the reader for each wsx:MetadataSection at depth 1 from where we are now
        loop {
            let (scope, attributes) =
                match parse_generic_body(&mut reader, Some(XML_WSX_NAMESPACE), "MetadataSection") {
                    Ok((element, attributes, _depth)) => {
                        // we'll need to ensure that the depth is always the same
                        (element, attributes)
                    },
                    Err(GenericParsingError::MissingElement(_)) => {
                        // no more `MetadataSections to be found`
                        break;
                    },
                    Err(error) => return Err(error.into()),
                };

            for attribute in attributes {
                if attribute.name.namespace_ref().is_none()
                    && attribute.name.local_name == "Dialect"
                {
                    if attribute.value == WSDP_THIS_DEVICE_DIALECT {
                        // open ThisDevice
                        let (this_device_scope, ..) = parse_generic_body(
                            &mut reader,
                            Some(XML_WSDP_NAMESPACE),
                            WSDP_THIS_DEVICE,
                        )?;

                        let new_props = extract_wsdp_props(
                            &mut reader,
                            XML_WSDP_NAMESPACE,
                            this_device_scope.borrow(),
                        )?;

                        self.props.extend(new_props);
                    } else if attribute.value == WSDP_THIS_MODEL_DIALECT {
                        // open ThisModel
                        let (this_model_scope, ..) = parse_generic_body(
                            &mut reader,
                            Some(XML_WSDP_NAMESPACE),
                            WSDP_THIS_MODEL,
                        )?;

                        let new_props = extract_wsdp_props(
                            &mut reader,
                            XML_WSDP_NAMESPACE,
                            this_model_scope.borrow(),
                        )?;

                        self.props.extend(new_props);
                    } else if attribute.value == WSDP_RELATIONSHIP_DIALECT {
                        let (types, display_name_belongs_to) = extract_host_props(&mut reader)?;

                        self.types = types;

                        if let Some((display_name, belongs_to)) = display_name_belongs_to {
                            self.props.insert("DisplayName".into(), display_name);
                            self.props.insert("BelongsTo".into(), belongs_to);
                        }
                    } else {
                        event!(
                            Level::DEBUG,
                            dialect = &attribute.value,
                            "unknown metadata dialect"
                        );
                        break;
                    }

                    break;
                }
            }

            // read until the closing to ensure we only stop when we hit
            // our closing element at our level (to avoid nested elements closing)
            let mut depth: usize = 1;

            loop {
                match reader.next()? {
                    XmlEvent::StartElement { name, .. } if name.borrow() == scope.borrow() => {
                        depth += 1;
                    },
                    XmlEvent::EndElement { name } if name.borrow() == scope.borrow() => {
                        depth -= 1;

                        if depth == 0 {
                            break;
                        }
                    },
                    XmlEvent::StartDocument { .. }
                    | XmlEvent::EndDocument
                    | XmlEvent::ProcessingInstruction { .. }
                    | XmlEvent::StartElement { .. }
                    | XmlEvent::EndElement { .. }
                    | XmlEvent::CData(_)
                    | XmlEvent::Comment(_)
                    | XmlEvent::Characters(_)
                    | XmlEvent::Whitespace(_)
                    | XmlEvent::Doctype { .. } => {},
                }
            }
        }

        let host = xaddr
            .host_str()
            .ok_or_else(|| eyre::Report::msg("Device's address does not have a host portion"))?
            .to_owned()
            .into_boxed_str();

        //         if interface.name not in self.addresses:
        //             self.addresses[interface.name] = set([addr])
        //         else:
        //             if addr not in self.addresses[interface.name]:
        //                 self.addresses[interface.name].add(addr)
        //             else:
        //                 report = False
        let report =
            if let Some(addresses) = self.addresses.get_mut(&network_address.interface.name) {
                addresses.insert(host)
            } else {
                self.addresses.insert(
                    network_address.interface.name.clone(),
                    HashSet::from_iter([host]),
                );

                true
            };

        self.last_seen = OffsetDateTime::now_utc();

        //         if ('DisplayName' in self.props) and ('BelongsTo' in self.props) and (report):
        if report {
            if let Some((display_name, belongs_to)) = self
                .props
                .get("DisplayName")
                .and_then(|d| self.props.get("BelongsTo").map(|b| (d, b)))
            {
                //             self.display_name = self.props['DisplayName']
                //             logger.info('discovered {} in {} on {}'.format(self.display_name, self.props['BelongsTo'], addr))
                self.display_name = Some(display_name.clone());

                event!(
                    Level::INFO,
                    display_name,
                    belongs_to,
                    addr = %xaddr,
                    "discovered device"
                );
            } else if let Some(friendly_name) = self.props.get("FriendlyName") {
                //         elif ('FriendlyName' in self.props) and (report):
                //             self.display_name = self.props['FriendlyName']
                self.display_name = Some(friendly_name.clone());
                //             logger.info('discovered {} on {}'.format(self.display_name, addr))
                event!(Level::INFO, display_name = friendly_name, addr = %xaddr, "discovered device");
            } else {
                // No way to get a display name
            }
        }

        event!(Level::DEBUG, ?self.props);

        Ok(())
    }
}

fn extract_wsdp_props(
    reader: &mut EventReader<BufReader<&[u8]>>,
    namespace: &str,
    closing: Name<'_>,
) -> Result<HashMap<Box<str>, Box<str>>, GenericParsingError> {
    // we're now in `namespace:path`, depth is already 1
    let mut depth: usize = 1;

    let mut bag = HashMap::<Box<str>, Box<str>>::new();

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                depth += 1;

                if name.namespace_ref() == Some(namespace) {
                    let text = read_text(reader, name.borrow())?;
                    let text = text.unwrap_or_default();

                    // add to bag
                    let tag_name = name.local_name;

                    bag.insert(tag_name.into_boxed_str(), text.into_boxed_str());

                    // `read_text` reads until the closing, so goes up 1 level
                    depth -= 1;
                }
            },
            XmlEvent::EndElement { name, .. } => {
                depth -= 1;

                // this is detection for the closing element of `namespace:path`
                if name.borrow() == closing {
                    if depth != 0 {
                        return Err(GenericParsingError::InvalidDepth(depth));
                    }

                    return Ok(bag);
                }
            },
            XmlEvent::EndDocument => {
                break;
            },
            XmlEvent::StartDocument { .. }
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::CData(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Whitespace(_)
            | XmlEvent::Doctype { .. } => {},
        }
    }

    Err(GenericParsingError::MissingEndElement(
        closing.to_string().into_boxed_str(),
    ))
}

type ExtractHostPropsResult =
    Result<(HashSet<Box<str>>, Option<(Box<str>, Box<str>)>), GenericParsingError>;

//     def extract_host_props(self, root: ElementTree.Element) -> None:
//         self.types = set(root.findtext('wsdp:Types', '', namespaces).split(' '))
//         if PUB_COMPUTER not in self.types:
//             return

//         comp = root.findtext(PUB_COMPUTER, '', namespaces)
//         self.props['DisplayName'], _, self.props['BelongsTo'] = (comp.partition('/'))
fn extract_host_props(reader: &mut EventReader<BufReader<&[u8]>>) -> ExtractHostPropsResult {
    // we are inside of the relationship metadata section, which contains ... RELATIONSHIPS
    // for each relationship, we find the one with Type=Host
    loop {
        let (_element, attributes) =
            match parse_generic_body(reader, Some(XML_WSDP_NAMESPACE), WSDP_RELATIONSHIP) {
                Ok((element, attributes, _depth)) => {
                    // we'll need to ensure that the depth is always the same
                    (element, attributes)
                },
                Err(GenericParsingError::MissingElement(_)) => {
                    // no more `MetadataSections to be found`
                    break;
                },
                Err(error) => return Err(error),
            };

        for attribute in attributes {
            if attribute.name.namespace_ref().is_none() && attribute.name.local_name == "Type" {
                if attribute.value == WSDP_RELATIONSHIP_TYPE_HOST {
                    match parse_generic_body(reader, Some(XML_WSDP_NAMESPACE), "Host") {
                        Ok((_name, _attributes, _depth)) => {
                            let (types, display_name_belongs_to) =
                                read_types_and_pub_computer(reader)?;

                            return Ok((types, display_name_belongs_to));
                        },

                        Err(GenericParsingError::MissingElement(_)) => {
                            // no more `MetadataSections to be found`
                            break;
                        },
                        Err(error) => return Err(error),
                    }
                } else {
                    event!(
                        Level::DEBUG,
                        r#type = &attribute.value,
                        "unknown relationship type"
                    );
                    break;
                };
            }
        }
    }

    Ok((HashSet::new(), None))
}

fn read_types_and_pub_computer(
    reader: &mut EventReader<BufReader<&[u8]>>,
) -> ExtractHostPropsResult {
    let mut types = None;
    let mut computer = None;
    let mut computer_namespace_prefix = None;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if name.namespace_ref() == Some(WSDP_URI) {
                    if &*name.local_name == "Types" {
                        // we're in wsdp:Types
                        types = read_text(reader, name.borrow())?.map(String::into_boxed_str);
                    } else {
                        // Not a match, continue
                    }
                } else if name.namespace_ref() == Some(XML_PUB_NAMESPACE) {
                    if &*name.local_name == "Computer" {
                        computer = read_text(reader, name.borrow())?.map(String::into_boxed_str);

                        // store the actual prefix, as it is not always `pub`
                        computer_namespace_prefix.clone_from(&name.prefix);
                    } else {
                        // Not a match, continue
                    }
                } else {
                    // ...
                }
            },
            XmlEvent::EndElement { name, .. } => {
                if name.namespace_ref() == Some(WSDP_URI) && name.local_name == "Host" {
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

    let types = types
        .unwrap_or_default()
        .split(' ')
        .map(ToOwned::to_owned)
        .map(String::into_boxed_str)
        .collect::<HashSet<_>>();

    if let Some(mut computer_namespace_prefix) = computer_namespace_prefix
        && let Some(computer) = computer
    {
        let actual_pub_computer = {
            computer_namespace_prefix.push_str(":Computer");

            computer_namespace_prefix
        };

        if types.contains(&*actual_pub_computer)
            && let Some((display_name, belongs_to)) = computer.split_once('/')
        {
            return Ok((
                types,
                Some((
                    display_name.to_owned().into_boxed_str(),
                    belongs_to.to_owned().into_boxed_str(),
                )),
            ));
        }
    }

    Ok((types, None))
}
