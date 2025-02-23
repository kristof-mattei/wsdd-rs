pub(crate) struct WSDClient {
    // udp_message_handler: WSDUDPMessageHandler<'nph>,
}
// impl<'nph> WSDClient<'nph> {
//     pub(crate) fn new(
//         multicast_handler: &Arc<MulticastHandler<'nph>>,
//         config: &Arc<Config>,
//     ) -> Self {
//         Self {
//             udp_message_handler: WSDUDPMessageHandler::new(multicast_handler, config),
//         }
//     }
// }

// class WSDClient(WSDUDPMessageHandler):

//     instances: ClassVar[List['WSDClient']] = []
//     probes: Dict[str, float]

//     def __init__(self, mch: MulticastHandler) -> None:
//         super().__init__(mch)

//         WSDClient.instances.append(self)

//         self.mch.add_handler(self.mch.mc_send_socket, self)
//         self.mch.add_handler(self.mch.recv_socket, self)

//         self.probes = {}

//         self.handlers[WSD_HELLO] = self.handle_hello
//         self.handlers[WSD_BYE] = self.handle_bye
//         self.handlers[WSD_PROBE_MATCH] = self.handle_probe_match
//         self.handlers[WSD_RESOLVE_MATCH] = self.handle_resolve_match

//         # avoid packet storm when hosts come up by delaying initial probe
//         time.sleep(random.randint(0, MAX_STARTUP_PROBE_DELAY))
//         self.send_probe()

//     def cleanup(self) -> None:
//         super().cleanup()
//         WSDClient.instances.remove(self)

//         self.mch.remove_handler(self.mch.mc_send_socket, self)
//         self.mch.remove_handler(self.mch.recv_socket, self)

//     def send_probe(self) -> None:
//         """WS-Discovery, Section 4.3, Probe message"""
//         self.remove_outdated_probes()

//         probe = ElementTree.Element('wsd:Probe')
//         ElementTree.SubElement(probe, 'wsd:Types').text = WSD_TYPE_DEVICE

//         xml, i = self.build_message_tree(WSA_DISCOVERY, WSD_PROBE, None, probe)
//         self.enqueue_datagram(self.xml_to_str(xml), self.mch.multicast_address, msg_type='Probe')
//         self.probes[i] = time.time()

//     def teardown(self) -> None:
//         super().teardown()
//         self.remove_outdated_probes()

//     def handle_packet(self, msg: str, src: Optional[UdpAddress] = None) -> None:
//         self.handle_message(msg, src)

//     def __extract_xaddr(self, xaddrs: str) -> Optional[str]:
//         for addr in xaddrs.strip().split():
//             if (self.mch.address.family == socket.AF_INET6) and ('//[fe80::' in addr):
//                 # use first link-local address for IPv6
//                 return addr
//             elif self.mch.address.family == socket.AF_INET:
//                 # use first (and very likely the only) IPv4 address
//                 return addr

//         return None

//     def handle_hello(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
//         pm_path = 'wsd:Hello'
//         endpoint, xaddrs = self.extract_endpoint_metadata(body, pm_path)
//         if not xaddrs:
//             logger.info('Hello without XAddrs, sending resolve')
//             msg = self.build_resolve_message(str(endpoint))
//             self.enqueue_datagram(msg, self.mch.multicast_address)
//             return None

//         xaddr = self.__extract_xaddr(xaddrs)
//         if xaddr is None:
//             return None

//         logger.info('Hello from {} on {}'.format(endpoint, xaddr))
//         self.perform_metadata_exchange(endpoint, xaddr)
//         return None

//     def handle_bye(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
//         bye_path = 'wsd:Bye'
//         endpoint, _ = self.extract_endpoint_metadata(body, bye_path)
//         device_uuid = str(uuid.UUID(endpoint))
//         if device_uuid in WSDDiscoveredDevice.instances:
//             del WSDDiscoveredDevice.instances[device_uuid]

//         return None

//     def handle_probe_match(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
//         # do not handle to probematches issued not sent by ourself
//         rel_msg = header.findtext('wsa:RelatesTo', None, namespaces)
//         if rel_msg not in self.probes:
//             logger.debug("unknown probe {}".format(rel_msg))
//             return None

//         # if XAddrs are missing, issue resolve request
//         pm_path = 'wsd:ProbeMatches/wsd:ProbeMatch'
//         endpoint, xaddrs = self.extract_endpoint_metadata(body, pm_path)
//         if not xaddrs:
//             logger.debug('probe match without XAddrs, sending resolve')
//             msg = self.build_resolve_message(str(endpoint))
//             self.enqueue_datagram(msg, self.mch.multicast_address)
//             return None

//         xaddr = self.__extract_xaddr(xaddrs)
//         if xaddr is None:
//             return None

//         logger.debug('probe match for {} on {}'.format(endpoint, xaddr))
//         self.perform_metadata_exchange(endpoint, xaddr)

//         return None

//     def build_resolve_message(self, endpoint: str) -> str:
//         resolve = ElementTree.Element('wsd:Resolve')
//         self.add_endpoint_reference(resolve, endpoint)

//         return self.build_message(WSA_DISCOVERY, WSD_RESOLVE, None, resolve)

//     def handle_resolve_match(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
//         rm_path = 'wsd:ResolveMatches/wsd:ResolveMatch'
//         endpoint, xaddrs = self.extract_endpoint_metadata(body, rm_path)
//         if not endpoint or not xaddrs:
//             logger.debug('resolve match without endpoint/xaddr')
//             return None

//         xaddr = self.__extract_xaddr(xaddrs)
//         if xaddr is None:
//             return None

//         logger.debug('resolve match for {} on {}'.format(endpoint, xaddr))
//         self.perform_metadata_exchange(endpoint, xaddr)

//         return None

//     def extract_endpoint_metadata(self, body: ElementTree.Element, prefix: str) -> Tuple[Optional[str], Optional[str]]:
//         prefix = prefix + '/'
//         addr_path = 'wsa:EndpointReference/wsa:Address'

//         endpoint = body.findtext(prefix + addr_path, namespaces=namespaces)
//         xaddrs = body.findtext(prefix + 'wsd:XAddrs', namespaces=namespaces)

//         return endpoint, xaddrs

//     def perform_metadata_exchange(self, endpoint, xaddr: str):
//         if not (xaddr.startswith('http://') or xaddr.startswith('https://')):
//             logger.debug('invalid XAddr: {}'.format(xaddr))
//             return

//         host = None
//         url = xaddr
//         if self.mch.address.family == socket.AF_INET6:
//             host = '[{}]'.format(url.partition('[')[2].partition(']')[0])
//             url = url.replace(']', '%{}]'.format(self.mch.address.interface))

//         body = self.build_getmetadata_message(endpoint)
//         request = urllib.request.Request(url, data=body.encode('utf-8'), method='POST')
//         request.add_header('Content-Type', 'application/soap+xml')
//         request.add_header('User-Agent', 'wsdd')
//         if host is not None:
//             request.add_header('Host', host)

//         try:
//             with urllib.request.urlopen(request, None, args.metadata_timeout) as stream:
//                 self.handle_metadata(stream.read(), endpoint, xaddr)
//         except urllib.error.URLError as e:
//             logger.warning('could not fetch metadata from: {} {}'.format(url, e))
//         except TimeoutError:
//             logger.warning('metadata exchange with {} timed out'.format(url))

//     def build_getmetadata_message(self, endpoint) -> str:
//         tree, _ = self.build_message_tree(endpoint, WSD_GET, None, None)
//         return self.xml_to_str(tree)

//     def handle_metadata(self, meta: str, endpoint: str, xaddr: str) -> None:
//         device_uuid = str(uuid.UUID(endpoint))
//         if device_uuid in WSDDiscoveredDevice.instances:
//             WSDDiscoveredDevice.instances[device_uuid].update(meta, xaddr, self.mch.address.interface)
//         else:
//             WSDDiscoveredDevice.instances[device_uuid] = WSDDiscoveredDevice(meta, xaddr, self.mch.address.interface)

//     def remove_outdated_probes(self) -> None:
//         cut = time.time() - PROBE_TIMEOUT * 2
//         self.probes = dict(filter(lambda x: x[1] > cut, self.probes.items()))

//     def add_header_elements(self, header: ElementTree.Element, extra: Any) -> None:
//         action_str = extra
//         if action_str == WSD_GET:
//             reply_to = ElementTree.SubElement(header, 'wsa:ReplyTo')
//             addr = ElementTree.SubElement(reply_to, 'wsa:Address')
//             addr.text = WSA_ANON

//             wsa_from = ElementTree.SubElement(header, 'wsa:From')
//             addr = ElementTree.SubElement(wsa_from, 'wsa:Address')
//             addr.text = args.uuid.urn
