use std::io::Read;
use std::ops::Deref;

use color_eyre::eyre;
use hashbrown::hash_map::EntryRef;
use hashbrown::{HashMap, HashSet};
use time::OffsetDateTime;
use tracing::{Level, event};
use xml::name::Name;
use xml::reader::XmlEvent;

use crate::constants;
use crate::network_address::NetworkAddress;
use crate::soap::parser;
use crate::soap::parser::xaddrs::XAddr;
use crate::xml::{GenericParsingError, Wrapper, find_descendant, read_text};

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
#[repr(transparent)]
/// Represents an opaque Device URI
pub struct DeviceUri(Box<str>);

impl DeviceUri {
    pub fn new<I: Into<Box<str>>>(device_uri: I) -> Self {
        Self(device_uri.into())
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
    device_uri: DeviceUri,
    addresses: HashMap<Box<str>, HashSet<Box<str>>>,
    props: HashMap<Box<str>, Box<str>>,
    display_name: Option<Box<str>>,
    last_seen: OffsetDateTime,
    types: HashSet<Box<str>>,
}

impl WSDDiscoveredDevice {
    pub fn new(
        device_uri: DeviceUri,
        meta: &[u8],
        xaddr: &XAddr,
        network_address: &NetworkAddress,
    ) -> Result<Self, eyre::Report> {
        let mut device = Self {
            device_uri,
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

    pub fn update(
        &mut self,
        meta: &[u8],
        xaddr: &XAddr,
        network_address: &NetworkAddress,
    ) -> Result<(), eyre::Report> {
        self.update_metadata(meta)?;

        let host = xaddr.host_str().to_owned().into_boxed_str();

        let report = match self.addresses.entry_ref(network_address.interface.name()) {
            EntryRef::Occupied(mut occupied_entry) => occupied_entry.get_mut().insert(host),
            EntryRef::Vacant(vacant_entry_ref) => {
                vacant_entry_ref.insert(HashSet::from_iter([host]));

                true
            },
        };

        self.last_seen = OffsetDateTime::now_utc();

        if report
            && let Some((display_name, belongs_to)) = self
                .props
                .get("DisplayName")
                .and_then(|d| self.props.get("BelongsTo").map(|b| (d, b)))
        {
            self.display_name = Some(display_name.to_owned());

            event!(
                Level::INFO,
                device_uri = %self.device_uri,
                %display_name,
                %belongs_to,
                addr = %xaddr,
                "Discovered device"
            );
        } else if let Some(friendly_name) = self.props.get("FriendlyName") {
            self.display_name = Some(friendly_name.to_owned());

            event!(
                Level::INFO,
                device_uri = %self.device_uri,
                display_name = %friendly_name,
                addr = %xaddr,
                "Discovered device"
            );
        } else {
            // No way to get a display name
        }

        event!(
            Level::DEBUG,
            device_uri = %self.device_uri,
            addresses = ?self.addresses,
            types = ?self.types,
            props = ?self.props,
            last_seen = ?self.last_seen,
            "Device updated",
        );

        Ok(())
    }

    fn update_metadata(&mut self, meta: &[u8]) -> Result<(), eyre::Report> {
        let (_header, _has_body, mut reader) = parser::deconstruct_raw(meta)?;

        let (_name, _attributes) =
            find_descendant(&mut reader, Some(constants::XML_WSX_NAMESPACE), "Metadata")?;

        // we're now in metadata

        // loop though the reader for each wsx:MetadataSection at depth 1 from where we are now
        loop {
            let (scope, attributes) = match find_descendant(
                &mut reader,
                Some(constants::XML_WSX_NAMESPACE),
                "MetadataSection",
            ) {
                Ok((name, attributes)) => (name, attributes),
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
                    if attribute.value == constants::WSDP_THIS_DEVICE_DIALECT {
                        // open ThisDevice
                        let (this_device_scope, ..) = find_descendant(
                            &mut reader,
                            Some(constants::XML_WSDP_NAMESPACE),
                            constants::WSDP_THIS_DEVICE,
                        )?;

                        let new_props = extract_wsdp_props(
                            &mut reader,
                            constants::XML_WSDP_NAMESPACE,
                            this_device_scope.borrow(),
                        )?;

                        self.props.extend(new_props);
                    } else if attribute.value == constants::WSDP_THIS_MODEL_DIALECT {
                        // open ThisModel
                        let (this_model_scope, ..) = find_descendant(
                            &mut reader,
                            Some(constants::XML_WSDP_NAMESPACE),
                            constants::WSDP_THIS_MODEL,
                        )?;

                        let new_props = extract_wsdp_props(
                            &mut reader,
                            constants::XML_WSDP_NAMESPACE,
                            this_model_scope.borrow(),
                        )?;

                        self.props.extend(new_props);
                    } else if attribute.value == constants::WSDP_RELATIONSHIP_DIALECT {
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
            let mut depth: usize = 0;

            loop {
                let event = reader.next()?;

                match event {
                    XmlEvent::StartElement { name, .. } if name.borrow() == scope.borrow() => {
                        depth += 1;
                    },
                    XmlEvent::EndElement { name } if name.borrow() == scope.borrow() => {
                        if depth == 0 {
                            break;
                        }

                        depth -= 1;
                    },
                    XmlEvent::CData(_)
                    | XmlEvent::Characters(_)
                    | XmlEvent::Comment(_)
                    | XmlEvent::Doctype { .. }
                    | XmlEvent::EndElement { .. }
                    | XmlEvent::ProcessingInstruction { .. }
                    | XmlEvent::StartDocument { .. }
                    | XmlEvent::StartElement { .. }
                    | XmlEvent::Whitespace(_) => {},
                    XmlEvent::EndDocument => {
                        event!(Level::ERROR, "Unexpected `EndDocument` found");
                        break;
                    },
                }
            }
        }

        Ok(())
    }
}

fn extract_wsdp_props<R>(
    reader: &mut Wrapper<R>,
    namespace: &str,
    closing: Name<'_>,
) -> Result<HashMap<Box<str>, Box<str>>, GenericParsingError>
where
    R: Read,
{
    // we're now in `namespace:path`, depth is already 1
    let mut depth: usize = 1;

    let mut bag = HashMap::<Box<str>, Box<str>>::new();

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                depth += 1;

                if depth == 2 && name.namespace_ref() == Some(namespace) {
                    let text = read_text(reader)?;
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
                if depth == 0 {
                    if name.borrow() == closing {
                        return Ok(bag);
                    }

                    return Err(GenericParsingError::InvalidDepth(depth));
                }
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

    Err(GenericParsingError::MissingEndElement(
        closing.to_string().into_boxed_str(),
    ))
}

type ExtractHostPropsResult =
    Result<(HashSet<Box<str>>, Option<(Box<str>, Box<str>)>), GenericParsingError>;

fn extract_host_props<R>(reader: &mut Wrapper<R>) -> ExtractHostPropsResult
where
    R: Read,
{
    // we are inside of the relationship metadata section, which contains ... RELATIONSHIPS
    // for each relationship, we find the one with Type=Host
    loop {
        let (_element, attributes) = match find_descendant(
            reader,
            Some(constants::XML_WSDP_NAMESPACE),
            constants::WSDP_RELATIONSHIP,
        ) {
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
                if attribute.value == constants::WSDP_RELATIONSHIP_TYPE_HOST {
                    match find_descendant(reader, Some(constants::XML_WSDP_NAMESPACE), "Host") {
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

                                if name.borrow().local_name == constants::WSDP_RELATIONSHIP
                                    && name.namespace_ref() == Some(constants::XML_WSDP_NAMESPACE)
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

fn read_types_and_pub_computer<R>(reader: &mut Wrapper<R>) -> ExtractHostPropsResult
where
    R: Read,
{
    let mut types = None;
    let mut computer = None;
    let mut computer_namespace_prefix = None;

    let mut depth = 0_usize;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                depth += 1;

                if depth == 1 {
                    match (name.namespace_ref(), name.local_name.as_str()) {
                        (Some(constants::WSDP_URI), "Types") => {
                            // we're in wsdp:Types
                            types = read_text(reader)?.map(String::into_boxed_str);

                            // `read_text` stops when it has hit the closing element, so we go back up 1 level
                            depth -= 1;
                        },
                        (Some(constants::XML_PUB_NAMESPACE), "Computer") => {
                            computer = read_text(reader)?.map(String::into_boxed_str);

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
            XmlEvent::EndElement { .. } => {
                if depth == 0 {
                    break;
                }

                depth -= 1;
            },
            XmlEvent::CData(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::EndDocument
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::StartDocument { .. }
            | XmlEvent::Whitespace(_) => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
        }
    }

    let types = types
        .unwrap_or_default()
        .split_whitespace()
        .map(Into::into)
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
