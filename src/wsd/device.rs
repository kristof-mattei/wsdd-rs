use std::sync::LazyLock;

use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

pub static INSTANCES: std::sync::LazyLock<RwLock<hashbrown::HashMap<Uuid, WSDDiscoveredDevice>>> =
    LazyLock::new(|| RwLock::new(hashbrown::HashMap::new()));

pub struct WSDDiscoveredDevice {}

// class WSDDiscoveredDevice:

//     # a dict of discovered devices with their UUID as key
//     instances: Dict[str, 'WSDDiscoveredDevice'] = {}

//     addresses: Dict[str, Set[str]]
//     props: Dict[str, str]
//     display_name: str
//     last_seen: float
//     types: Set[str]

impl WSDDiscoveredDevice {
    pub fn new(meta: String, xaddr: Url) -> Self {
        //         self.last_seen = 0.0
        //         self.addresses = {}
        //         self.props = {}
        //         self.display_name = ''
        //         self.types = set()

        let mut s = Self {};

        s.update(meta, xaddr);

        s
    }

    pub fn update(&mut self, _meta: String, _xaddr: Url) {}
}

//     def update(self, xml_str: str, xaddr: str, interface: NetworkInterface) -> None:
//         try:
//             tree = ETfromString(xml_str)
//         except ElementTree.ParseError:
//             return None
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
//         addr, _, _ = url.netloc.rpartition(':')
//         report = True
//         if interface.name not in self.addresses:
//             self.addresses[interface.name] = set([addr])
//         else:
//             if addr not in self.addresses[interface.name]:
//                 self.addresses[interface.name].add(addr)
//             else:
//                 report = False

//         self.last_seen = time.time()
//         if ('DisplayName' in self.props) and ('BelongsTo' in self.props) and (report):
//             self.display_name = self.props['DisplayName']
//             logger.info('discovered {} in {} on {}'.format(self.display_name, self.props['BelongsTo'], addr))
//         elif ('FriendlyName' in self.props) and (report):
//             self.display_name = self.props['FriendlyName']
//             logger.info('discovered {} on {}'.format(self.display_name, addr))

//         logger.debug(str(self.props))

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
