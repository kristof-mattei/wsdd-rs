use bytes::Bytes;
use color_eyre::eyre;
use hashbrown::{HashMap, HashSet};
use quick_xml::NsReader;
use quick_xml::events::Event;
use quick_xml::name::Namespace;
use quick_xml::name::ResolveResult::Bound;
use time::OffsetDateTime;
use tracing::{Level, event};
use url::Url;

use crate::constants::{
    WSDP_RELATIONSHIP, WSDP_RELATIONSHIP_DIALECT, WSDP_RELATIONSHIP_TYPE_HOST, WSDP_THIS_DEVICE,
    WSDP_THIS_DEVICE_DIALECT, WSDP_THIS_MODEL, WSDP_THIS_MODEL_DIALECT, XML_WSDP_NAMESPACE,
    XML_WSX_NAMESPACE,
};
use crate::network_address::NetworkAddress;
use crate::soap::parser;
use crate::soap::parser::generic::{GenericParsingError, parse_generic_body};

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
        xaddr: Url,
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

    #[expect(unused, reason = "WIP")]
    pub fn addresses(&self) -> &HashMap<Box<str>, HashSet<Box<str>>> {
        &self.addresses
    }

    #[cfg_attr(not(test), expect(unused, reason = "WIP"))]
    pub fn props(&self) -> &HashMap<Box<str>, Box<str>> {
        &self.props
    }

    #[expect(unused, reason = "WIP")]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }

    #[expect(unused, reason = "WIP")]
    pub fn last_seen(&self) -> &OffsetDateTime {
        &self.last_seen
    }

    #[expect(unused, reason = "WIP")]
    pub fn types(&self) -> &HashSet<Box<str>> {
        &self.types
    }

    //     def update(self, xml_str: str, xaddr: str, interface: NetworkInterface) -> None:
    // TODO better error type
    pub fn update(
        &mut self,
        meta: &Bytes,
        xaddr: Url,
        network_address: &NetworkAddress,
    ) -> Result<(), eyre::Report> {
        let (_header, _has_body, mut reader) = parser::deconstruct_raw(meta)?;

        parse_generic_body(&mut reader, XML_WSX_NAMESPACE, "Metadata")?;

        // we're now in metadata

        // loop though the reader for each wsx:MetadataSection at depth 1 from where we are now
        loop {
            let element =
                match parse_generic_body(&mut reader, XML_WSX_NAMESPACE, "MetadataSection") {
                    Ok((element, _depth)) => {
                        // we'll need to ensure that the depth is always the same
                        element
                    },
                    Err(GenericParsingError::MissingElement(_)) => {
                        // no more `MetadataSections to be found`
                        break;
                    },
                    Err(error) => return Err(error.into()),
                };

            for attribute in element.attributes() {
                let attribute =
                    attribute.map_err(|error| GenericParsingError::XmlError(error.into()))?;

                if attribute.key.0 == b"Dialect" {
                    let new_props = if attribute.value == WSDP_THIS_DEVICE_DIALECT.as_bytes() {
                        extract_wsdp_props(&mut reader, XML_WSDP_NAMESPACE, WSDP_THIS_DEVICE)?
                    } else if attribute.value == WSDP_THIS_MODEL_DIALECT.as_bytes() {
                        extract_wsdp_props(&mut reader, XML_WSDP_NAMESPACE, WSDP_THIS_MODEL)?
                    } else if attribute.value == WSDP_RELATIONSHIP_DIALECT.as_bytes() {
                        extract_host_props(&mut reader)?
                    } else {
                        event!(
                            Level::DEBUG,
                            dialect = %String::from_utf8_lossy(&attribute.value),
                            "unknown metadata dialect"
                        );
                        break;
                    };

                    for (new_prop_key, new_prop_value) in new_props {
                        self.props.insert(new_prop_key, new_prop_value);
                    }
                    break;
                }
            }
        }

        //         mds_path = 'soap:Body/wsx:Metadata/wsx:MetadataSection'
        //         sections = tree.findall(mds_path, namespaces)
        //         for section in sections:
        //             dialect = section.attrib['Dialect']
        //             if dialect == WSDP_URI + '/ThisDevice':
        //                 self.extract_wsdp_props(section, dialect)
        //             elif dialect == WSDP_URI + '/ThisModel':
        //                 self.extract_wsdp_props(section, dialect)
        //             elif dialect == WSDP_URI + '/Relationship':
        //                 host_xpath = 'wsdp:Relationship[@Type="{}/host"]/wsdp:Host'.format(WSDP_URI)
        //                 host_sec = section.find(host_xpath, namespaces)
        //                 if (host_sec is not None):
        //                     self.extract_host_props(host_sec)
        //             else:
        //                 logger.debug('unknown metadata dialect ({})'.format(dialect))

        //         url = urllib.parse.urlparse(xaddr)
        let url = xaddr;
        //         addr, _, _ = url.netloc.rpartition(':')
        // TODO error, don't blow up
        let host = url
            .host_str()
            .expect("addr must have host component")
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
                    addr = %url,
                    "discovered device"
                );
            } else if let Some(friendly_name) = self.props.get("FriendlyName") {
                //         elif ('FriendlyName' in self.props) and (report):
                //             self.display_name = self.props['FriendlyName']
                self.display_name = Some(friendly_name.clone());
                //             logger.info('discovered {} on {}'.format(self.display_name, addr))
                event!(
                    Level::INFO,
                    display_name = friendly_name,
                    addr = %url,
                    "discovered device"
                );
            } else {
                // No way to get a display name
            }
        }

        event!(Level::DEBUG, ?self.props);

        Ok(())
    }
}

fn extract_wsdp_props<'full_path, 'namespace, 'path, 'reader>(
    reader: &'reader mut NsReader<&[u8]>,
    namespace: &'namespace str,
    path: &'path str,
) -> Result<HashMap<Box<str>, Box<str>>, GenericParsingError<'full_path>>
where
    'full_path: 'path + 'namespace,
{
    parse_generic_body(reader, namespace, path)?;

    // we're now in `namespace:path`
    let mut bag = HashMap::<Box<str>, Box<str>>::new();

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == namespace.as_bytes() {
                    let text = reader.read_text(e.name())?;
                    // add to bag
                    let tag_name = str::from_utf8(e.local_name().into_inner())
                        .map_err(|error| quick_xml::Error::Encoding(error.into()))?;

                    bag.insert(
                        tag_name.to_owned().into_boxed_str(),
                        text.into_owned().into_boxed_str(),
                    );
                }
            },
            (Bound(Namespace(ns)), Event::End(e)) => {
                // this is detection for the closing element of `namespace:path`
                if ns == namespace.as_bytes() && e.name().local_name().as_ref() == path.as_bytes() {
                    return Ok(bag);
                }
            },
            (_, Event::Eof) => {
                break;
            },
            _ => {},
        }
    }

    Err(GenericParsingError::MissingClosingElement(
        format!("{}:{}", namespace, path).into(),
    ))
}

//     def extract_host_props(self, root: ElementTree.Element) -> None:
//         self.types = set(root.findtext('wsdp:Types', '', namespaces).split(' '))
//         if PUB_COMPUTER not in self.types:
//             return

//         comp = root.findtext(PUB_COMPUTER, '', namespaces)
//         self.props['DisplayName'], _, self.props['BelongsTo'] = (comp.partition('/'))
fn extract_host_props<'full_path>(
    reader: &'_ mut NsReader<&[u8]>,
) -> Result<HashMap<Box<str>, Box<str>>, GenericParsingError<'full_path>> {
    // we are inside of the relationship metadata section, which contains ... RELATIONSHIPS
    // for each relationship, we find the one with Type=Host
    loop {
        let element = match parse_generic_body(reader, XML_WSDP_NAMESPACE, WSDP_RELATIONSHIP) {
            Ok((element, _depth)) => {
                // we'll need to ensure that the depth is always the same
                element
            },
            Err(GenericParsingError::MissingElement(_)) => {
                // no more `MetadataSections to be found`
                break;
            },
            Err(error) => return Err(error),
        };

        for attribute in element.attributes() {
            let attribute =
                attribute.map_err(|error| GenericParsingError::XmlError(error.into()))?;

            if attribute.key.0 == b"Type" {
                if attribute.value == WSDP_RELATIONSHIP_TYPE_HOST.as_bytes() {
                    let new_props = HashMap::new();

                    return Ok(new_props);
                } else {
                    event!(
                        Level::DEBUG,
                        r#type = %String::from_utf8_lossy(&attribute.value),
                        "unknown relationship type"
                    );
                    break;
                };
            }
        }
    }

    Ok(HashMap::new())
}
