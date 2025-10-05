use bytes::Bytes;
use color_eyre::eyre;
use hashbrown::{HashMap, HashSet};
use time::OffsetDateTime;
use tracing::{Level, event};
use url::Url;

use crate::constants::XML_WSX_NAMESPACE;
use crate::network_address::NetworkAddress;
use crate::soap::parser;
use crate::soap::parser::generic::parse_generic_body;

pub struct WSDDiscoveredDevice {
    addresses: HashMap<Box<str>, HashSet<Box<str>>>,
    props: HashMap<Box<str>, String>,
    display_name: Option<Box<str>>,
    last_seen: OffsetDateTime,
    #[expect(unused, reason = "WIP")]
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

    //     def update(self, xml_str: str, xaddr: str, interface: NetworkInterface) -> None:
    pub fn update(
        &mut self,
        meta: &Bytes,
        xaddr: Url,
        network_address: &NetworkAddress,
    ) -> Result<(), eyre::Report> {
        let (_header, _has_body, mut reader) = parser::deconstruct_raw(meta)?;

        parse_generic_body(&mut reader, XML_WSX_NAMESPACE, "Metadata")?;

        // we're now in metadata

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
                self.display_name = Some(display_name.clone().into_boxed_str());

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
                self.display_name = Some(friendly_name.clone().into_boxed_str());
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

//     def extract_wsdp_props(self, root: ElementTree.Element, dialect: str) -> None:
//         _, _, propsRoot = dialect.rpartition('/')
//         # XPath support is limited, so filter by namespace on our own
//         nodes = root.findall('./wsdp:{0}/*'.format(propsRoot), namespaces)
//         ns_prefix = '{{{}}}'.format(WSDP_URI)
//         prop_nodes = [n for n in nodes if n.tag.startswith(ns_prefix)]
//         for node in prop_nodes:
//             tag_name = node.tag[len(ns_prefix):]
//             self.props[tag_name] = str(node.text)

//     def extract_host_props(self, root: ElementTree.Element) -> None:
//         self.types = set(root.findtext('wsdp:Types', '', namespaces).split(' '))
//         if PUB_COMPUTER not in self.types:
//             return

//         comp = root.findtext(PUB_COMPUTER, '', namespaces)
//         self.props['DisplayName'], _, self.props['BelongsTo'] = (comp.partition('/'))
