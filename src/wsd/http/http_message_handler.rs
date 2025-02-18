use crate::wsd::message_handler::WSDMessageHandler;

struct WSDHttpMessageHandler {
    message_handler: WSDMessageHandler,
}

// class WSDHttpMessageHandler(WSDMessageHandler):

//     def __init__(self) -> None:
//         super().__init__()

//         self.handlers[WSD_GET] = self.handle_get

//     def handle_get(self, header: ElementTree.Element, body: ElementTree.Element) -> WSDMessage:
//         # see https://msdn.microsoft.com/en-us/library/hh441784.aspx for an
//         # example. Some of the properties below might be made configurable
//         # in future releases.
//         metadata = ElementTree.Element('wsx:Metadata')
//         section = ElementTree.SubElement(metadata, 'wsx:MetadataSection', {'Dialect': WSDP_URI + '/ThisDevice'})
//         device = ElementTree.SubElement(section, 'wsdp:ThisDevice')
//         ElementTree.SubElement(device, 'wsdp:FriendlyName').text = ('WSD Device {0}'.format(args.hostname))
//         ElementTree.SubElement(device, 'wsdp:FirmwareVersion').text = '1.0'
//         ElementTree.SubElement(device, 'wsdp:SerialNumber').text = '1'

//         section = ElementTree.SubElement(metadata, 'wsx:MetadataSection', {'Dialect': WSDP_URI + '/ThisModel'})
//         model = ElementTree.SubElement(section, 'wsdp:ThisModel')
//         ElementTree.SubElement(model, 'wsdp:Manufacturer').text = 'wsdd'
//         ElementTree.SubElement(model, 'wsdp:ModelName').text = 'wsdd'
//         ElementTree.SubElement(model, 'pnpx:DeviceCategory').text = 'Computers'

//         section = ElementTree.SubElement(metadata, 'wsx:MetadataSection', {'Dialect': WSDP_URI + '/Relationship'})
//         rel = ElementTree.SubElement(section, 'wsdp:Relationship', {'Type': WSDP_URI + '/host'})
//         host = ElementTree.SubElement(rel, 'wsdp:Host')
//         self.add_endpoint_reference(host)
//         ElementTree.SubElement(host, 'wsdp:Types').text = PUB_COMPUTER
//         ElementTree.SubElement(host, 'wsdp:ServiceId').text = args.uuid.urn

//         fmt = '{0}/Domain:{1}' if args.domain else '{0}/Workgroup:{1}'
//         value = args.domain if args.domain else args.workgroup.upper()
//         if args.domain:
//             dh = args.hostname if args.preserve_case else args.hostname.lower()
//         else:
//             dh = args.hostname if args.preserve_case else args.hostname.upper()

//         ElementTree.SubElement(host, PUB_COMPUTER).text = fmt.format(dh, value)

//         return metadata, WSD_GET_RESPONSE
