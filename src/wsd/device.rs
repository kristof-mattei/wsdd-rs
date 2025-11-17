use std::borrow::ToOwned;
use std::ops::Deref;

use color_eyre::eyre;
use hashbrown::{HashMap, HashSet};
use time::OffsetDateTime;
use tracing::{Level, event};
use url::Url;
use xml::name::Name;
use xml::reader::XmlEvent;

use crate::constants::{
    WSDP_RELATIONSHIP, WSDP_RELATIONSHIP_DIALECT, WSDP_RELATIONSHIP_TYPE_HOST, WSDP_THIS_DEVICE,
    WSDP_THIS_DEVICE_DIALECT, WSDP_THIS_MODEL, WSDP_THIS_MODEL_DIALECT, WSDP_URI,
    XML_PUB_NAMESPACE, XML_WSDP_NAMESPACE, XML_WSX_NAMESPACE,
};
use crate::network_address::NetworkAddress;
use crate::soap::parser;
use crate::xml::{GenericParsingError, Wrapper, find_child, read_text};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
/// Represents an opaque Device URI
pub struct DeviceUri(Box<str>);

impl DeviceUri {
    pub fn new(device_uri: Box<str>) -> Self {
        Self(device_uri)
    }
}

impl Deref for DeviceUri {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl AsRef<str> for DeviceUri {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for DeviceUri {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

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
        meta: &[u8],
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
        meta: &[u8],
        xaddr: &Url,
        network_address: &NetworkAddress,
    ) -> Result<(), eyre::Report> {
        let (_header, _has_body, mut reader) = parser::deconstruct_raw(meta)?;

        let (_name, _attributes) = find_child(&mut reader, Some(XML_WSX_NAMESPACE), "Metadata")?;

        // we're now in metadata

        // loop though the reader for each wsx:MetadataSection at depth 1 from where we are now
        loop {
            let (scope, attributes) =
                match find_child(&mut reader, Some(XML_WSX_NAMESPACE), "MetadataSection") {
                    Ok((name, attributes)) => {
                        // we'll need to ensure that the depth is always the same
                        (name, attributes)
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
                        let (this_device_scope, ..) =
                            find_child(&mut reader, Some(XML_WSDP_NAMESPACE), WSDP_THIS_DEVICE)?;

                        let new_props = extract_wsdp_props(
                            &mut reader,
                            XML_WSDP_NAMESPACE,
                            this_device_scope.borrow(),
                        )?;

                        self.props.extend(new_props);
                    } else if attribute.value == WSDP_THIS_MODEL_DIALECT {
                        // open ThisModel
                        let (this_model_scope, ..) =
                            find_child(&mut reader, Some(XML_WSDP_NAMESPACE), WSDP_THIS_MODEL)?;

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

            // Close out on the `wsx:MetadataSection`
            let mut depth: usize = 1;

            loop {
                let event = reader.next()?;

                match event {
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
                    | XmlEvent::ProcessingInstruction { .. }
                    | XmlEvent::StartElement { .. }
                    | XmlEvent::EndElement { .. }
                    | XmlEvent::CData(_)
                    | XmlEvent::Comment(_)
                    | XmlEvent::Characters(_)
                    | XmlEvent::Whitespace(_)
                    | XmlEvent::Doctype { .. } => {},
                    XmlEvent::EndDocument => {
                        event!(Level::ERROR, "Unexpected `EndDocument` found");
                        break;
                    },
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
            if let Some(addresses) = self.addresses.get_mut(network_address.interface.name()) {
                addresses.insert(host)
            } else {
                self.addresses.insert(
                    network_address.interface.name().to_owned().into_boxed_str(),
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
    reader: &mut Wrapper<'_>,
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

fn extract_host_props(reader: &mut Wrapper<'_>) -> ExtractHostPropsResult {
    // we are inside of the relationship metadata section, which contains ... RELATIONSHIPS
    // for each relationship, we find the one with Type=Host
    loop {
        let (_element, attributes) =
            match find_child(reader, Some(XML_WSDP_NAMESPACE), WSDP_RELATIONSHIP) {
                Ok((name, attributes)) => {
                    // we'll need to ensure that the depth is always the same
                    (name, attributes)
                },
                Err(GenericParsingError::MissingElement(_)) => {
                    // no `wsdp:Relationship` to be found`
                    return Ok((HashSet::new(), None));
                },
                Err(error) => return Err(error),
            };

        for attribute in attributes {
            if attribute.name.namespace_ref().is_none() && attribute.name.local_name == "Type" {
                if attribute.value == WSDP_RELATIONSHIP_TYPE_HOST {
                    match find_child(reader, Some(XML_WSDP_NAMESPACE), "Host") {
                        Ok((_name, _attributes)) => {
                            let (types, display_name_belongs_to) =
                                read_types_and_pub_computer(reader)?;

                            // we're now back in `<wsdp:Relationship Type=$WSDP_RELATIONSHIP_TYPE_HOST>`
                            // and we have to go one level up to `<wsx:MetadataSection>`
                            // so we pop the closing element `</wsdp:Relationship Type=$WSDP_RELATIONSHIP_TYPE_HOST>`
                            loop {
                                let event = reader.next()?;

                                let XmlEvent::EndElement { name } = event else {
                                    continue;
                                };

                                if name.borrow().local_name == WSDP_RELATIONSHIP
                                    && name.namespace_ref() == Some(XML_WSDP_NAMESPACE)
                                {
                                    break;
                                }
                            }

                            return Ok((types, display_name_belongs_to));
                        },

                        Err(GenericParsingError::MissingElement(_)) => {
                            // no `Host` to be found, so we have just closed the `WSDP_RELATIONSHIP`
                            // we are now in `<wsx:MetadataSection>`

                            return Ok((HashSet::new(), None));
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
}

fn read_types_and_pub_computer(reader: &mut Wrapper<'_>) -> ExtractHostPropsResult {
    let mut types = None;
    let mut computer = None;
    let mut computer_namespace_prefix = None;

    let mut depth = 0;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                depth += 1;

                if depth == 1 {
                    match (name.namespace_ref(), name.local_name.as_str()) {
                        (Some(WSDP_URI), "Types") => {
                            // we're in wsdp:Types
                            types = read_text(reader, name.borrow())?.map(String::into_boxed_str);

                            // `read_text` stops when it has hit the closing element, so we go back up 1 level
                            depth -= 1;
                        },
                        (Some(XML_PUB_NAMESPACE), "Computer") => {
                            computer =
                                read_text(reader, name.borrow())?.map(String::into_boxed_str);

                            // store the actual prefix, as it is not always `pub`
                            computer_namespace_prefix.clone_from(&name.prefix);

                            // `read_text` stops when it has hit the closing element, so we go back up 1 level
                            depth -= 1;
                        },
                        (Some(_) | None, _) => {
                            // ...
                        },
                    }
                }
                // only interested in elements at 1 level deep
            },
            XmlEvent::EndElement { name, .. } => {
                depth -= 1;

                if name.namespace_ref() == Some(WSDP_URI) && name.local_name == "Host" {
                    break;
                }
            },
            XmlEvent::EndDocument => return Err(GenericParsingError::InvalidElementOrder),
            XmlEvent::StartDocument { .. }
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
