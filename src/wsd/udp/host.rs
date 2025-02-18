pub(crate) struct WSDHost {
    // udp_message_handler: WSDUDPMessageHandler<'nph>,
}
// impl WSDHost {
//     pub(crate) fn new(
//         multicast_handler: &Arc<MulticastHandler<'nph>>,
//         config: &Arc<Config>,
//     ) -> Self {
//         Self {
//             // udp_message_handler: WSDUDPMessageHandler::new(multicast_handler, config),
//         }
//     }
// }
// class WSDHost(WSDUDPMessageHandler):
//     """Class for handling WSD requests coming from UDP datagrams."""

//     message_number: ClassVar[int] = 0
//     instances: ClassVar[List['WSDHost']] = []

//     def __init__(self, mch: MulticastHandler) -> None:
//         super().__init__(mch)

//         WSDHost.instances.append(self)

//         self.mch.add_handler(self.mch.recv_socket, self)

//         self.handlers[WSD_PROBE] = self.handle_probe
//         self.handlers[WSD_RESOLVE] = self.handle_resolve

//         self.send_hello()

//     def cleanup(self) -> None:
//         super().cleanup()
//         WSDHost.instances.remove(self)

//     def teardown(self) -> None:
//         super().teardown()
//         self.send_bye()

//     def handle_packet(self, msg: str, src: UdpAddress) -> None:
//         reply = self.handle_message(msg, src)
//         if reply:
//             self.enqueue_datagram(reply, src)

//     def send_hello(self) -> None:
//         """WS-Discovery, Section 4.1, Hello message"""
//         hello = ElementTree.Element('wsd:Hello')
//         self.add_endpoint_reference(hello)
//         # THINK: Microsoft does not send the transport address here due to privacy reasons. Could make this optional.
//         self.add_xaddr(hello, self.mch.address.transport_str)
//         self.add_metadata_version(hello)

//         msg = self.build_message(WSA_DISCOVERY, WSD_HELLO, None, hello)
//         self.enqueue_datagram(msg, self.mch.multicast_address, msg_type='Hello')

//     def send_bye(self) -> None:
//         """WS-Discovery, Section 4.2, Bye message"""
//         bye = ElementTree.Element('wsd:Bye')
//         self.add_endpoint_reference(bye)

//         msg = self.build_message(WSA_DISCOVERY, WSD_BYE, None, bye)
//         self.enqueue_datagram(msg, self.mch.multicast_address, msg_type='Bye')

//     def handle_probe(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
//         probe = body.find('./wsd:Probe', namespaces)
//         if probe is None:
//             return None

//         scopes = probe.find('./wsd:Scopes', namespaces)

//         if scopes:
//             # THINK: send fault message (see p. 21 in WSD)
//             logger.debug('scopes ({}) unsupported but probed'.format(scopes))
//             return None

//         types_elem = probe.find('./wsd:Types', namespaces)
//         if types_elem is None:
//             logger.debug('Probe message lacks wsd:Types element. Ignored.')
//             return None

//         types = types_elem.text
//         if not types == WSD_TYPE_DEVICE:
//             logger.debug('unknown discovery type ({}) for probe'.format(types))
//             return None

//         matches = ElementTree.Element('wsd:ProbeMatches')
//         match = ElementTree.SubElement(matches, 'wsd:ProbeMatch')
//         self.add_endpoint_reference(match)
//         self.add_types(match)
//         self.add_metadata_version(match)

//         return matches, WSD_PROBE_MATCH

//     def handle_resolve(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
//         resolve = body.find('./wsd:Resolve', namespaces)
//         if resolve is None:
//             return None

//         addr = resolve.find('./wsa:EndpointReference/wsa:Address', namespaces)
//         if addr is None:
//             logger.debug('invalid resolve request: missing endpoint address')
//             return None

//         if not addr.text == args.uuid.urn:
//             logger.debug('invalid resolve request: address ({}) does not match own one ({})'.format(
//                 addr.text, args.uuid.urn))
//             return None

//         matches = ElementTree.Element('wsd:ResolveMatches')
//         match = ElementTree.SubElement(matches, 'wsd:ResolveMatch')
//         self.add_endpoint_reference(match)
//         self.add_types(match)
//         self.add_xaddr(match, self.mch.address.transport_str)
//         self.add_metadata_version(match)

//         return matches, WSD_RESOLVE_MATCH

//     def add_header_elements(self, header: ElementTree.Element, extra: Any):
//         ElementTree.SubElement(
//             header, 'wsd:AppSequence', {
//                 'InstanceId': str(wsd_instance_id),
//                 'SequenceId': uuid.uuid1().urn,
//                 'MessageNumber': str(type(self).message_number)
//             })

//         type(self).message_number += 1
