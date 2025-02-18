use core::str;
use std::collections::VecDeque;
use std::sync::Arc;

use hashbrown::HashMap;
use quick_xml::events::{BytesStart, BytesText, Event};
use quick_xml::name::ResolveResult;
use quick_xml::{NsReader, Writer};
use tracing::Level;

use crate::config::Config;
use crate::constants::{
    WSD_HTTP_PORT, WSD_TYPE_DEVICE_COMPUTER, XML_SOAP_NAMESPACE, XML_WSA_NAMESPACE,
};
use crate::udp_address::UdpAddress;

struct MessageTypeHandler {}

pub(crate) struct WSDMessageHandler {
    config: Arc<Config>,

    //     handlers: Dict[str, MessageTypeHandler]
    handlers: HashMap<String, MessageTypeHandler>,

    //     known_messages: Deque[str] = collections.deque([], WSD_MAX_KNOWN_MESSAGES)
    known_messages: VecDeque<String>,

    //     pending_tasks: List[asyncio.Task]
    pending_tasks: Vec<String>,
}
// class WSDMessageHandler(INetworkPacketHandler):

impl WSDMessageHandler {
    //     def __init__(self) -> None:
    //         self.handlers = {}
    //         self.pending_tasks = []
    pub fn new(config: &Arc<Config>) -> Self {
        Self {
            config: Arc::clone(config),
            handlers: HashMap::new(),
            known_messages: VecDeque::new(),
            pending_tasks: vec![],
        }
    }
    //     def cleanup(self):
    //         pass

    //     # shortcuts for building WSD responses
    //     def add_endpoint_reference(self, parent: ElementTree.Element, endpoint: Optional[str] = None) -> None:
    fn add_endpoint_reference<T: std::io::Write>(
        &self,
        parent: &mut Writer<T>,
        endpoint: Option<String>,
    ) -> Result<(), std::io::Error> {
        //         epr = ElementTree.SubElement(parent, 'wsa:EndpointReference')
        //         if endpoint is None:
        //             address.text = args.uuid.urn
        //         else:
        //             address.text = endpoint

        let endpoint = endpoint.unwrap_or_else(|| self.config.uuid.to_string());

        parent
            .create_element("wsa:EndpointReference")
            .write_inner_content(|writer| {
                //         address = ElementTree.SubElement(epr, 'wsa:Address')
                writer
                    .create_element("wsa:Address")
                    .write_text_content(BytesText::new(endpoint.as_str()))?;

                Ok(())
            })?;

        Ok(())
    }

    //     def add_metadata_version(self, parent: ElementTree.Element) -> None:
    fn add_metadata_version<T: std::io::Write>(
        &self,
        parent: &mut Writer<T>,
    ) -> Result<(), std::io::Error> {
        parent
            .create_element("wsd:MetadataVersion")
            .write_text_content(BytesText::new("1"))?;
        //         meta_data = ElementTree.SubElement(parent, 'wsd:MetadataVersion')
        //         meta_data.text = '1'

        Ok(())
    }

    //     def add_types(self, parent: ElementTree.Element) -> None:

    fn add_types<T: std::io::Write>(&self, parent: &mut Writer<T>) -> Result<(), std::io::Error> {
        parent
            .create_element("wsd:Types")
            .write_text_content(BytesText::new(WSD_TYPE_DEVICE_COMPUTER))?;
        //         dev_type = ElementTree.SubElement(parent, 'wsd:Types')
        //         dev_type.text = WSD_TYPE_DEVICE_COMPUTER

        Ok(())
    }

    //     def add_xaddr(self, parent: ElementTree.Element, transport_addr: str) -> None:

    fn add_xaddr<T: std::io::Write>(
        &self,
        parent: &mut Writer<T>,
        transport_addr: Option<&str>,
    ) -> Result<(), std::io::Error> {
        //         if transport_addr:
        if let Some(transport_addr) = transport_addr {
            // TODO use URL builder
            let text = format!(
                "http://{}:{}/{}",
                transport_addr, WSD_HTTP_PORT, self.config.uuid
            );

            parent
                .create_element("wsd:XAddrs")
                .write_text_content(BytesText::new(text.as_str()))?;
            // item = ElementTree.SubElement(parent, 'wsd:XAddrs')
            // item.text = 'http://{0}:{1}/{2}'.format(transport_addr, WSD_HTTP_PORT, args.uuid)
        }
        Ok(())
    }

    //     def build_message(self, to_addr: str, action_str: str, request_header: Optional[ElementTree.Element],
    //                       response: ElementTree.Element) -> str:
    fn bulid_messages(
        &self,
        _to_addr: String,
        _action_str: String,
        _request_header: Option<String>,
        _response: String,
    ) {
        //         retval = self.xml_to_str(self.build_message_tree(to_addr, action_str, request_header, response)[0])

        //         logger.debug('constructed xml for WSD message: {0}'.format(retval))

        //         return retval
    }

    //     def build_message_tree(self, to_addr: str, action_str: str, request_header: Optional[ElementTree.Element],
    //                            body: Optional[ElementTree.Element]) -> Tuple[ElementTree.Element, str]:
    fn build_message_tree(&self) {
        //         """
        //         Build a WSD message with a given action string including SOAP header.

        //         The message can be constructed based on a response to another
        //         message (given by its header) and with a optional response that
        //         serves as the message's body
        //         """
        //         root = ElementTree.Element('soap:Envelope')
        //         header = ElementTree.SubElement(root, 'soap:Header')

        //         to = ElementTree.SubElement(header, 'wsa:To')
        //         to.text = to_addr

        //         action = ElementTree.SubElement(header, 'wsa:Action')
        //         action.text = action_str

        //         msg_id = ElementTree.SubElement(header, 'wsa:MessageID')
        //         msg_id.text = uuid.uuid1().urn

        //         if request_header is not None:
        //             req_msg_id = request_header.find('./wsa:MessageID', namespaces)
        //             if req_msg_id is not None:
        //                 relates_to = ElementTree.SubElement(header, 'wsa:RelatesTo')
        //                 relates_to.text = req_msg_id.text

        //         self.add_header_elements(header, action_str)

        //         body_root = ElementTree.SubElement(root, 'soap:Body')
        //         if body is not None:
        //             body_root.append(body)

        //         for prefix, uri in namespaces.items():
        //             root.attrib['xmlns:' + prefix] = uri
    }

    //         return root, msg_id.text

    //     def add_header_elements(self, header: ElementTree.Element, extra: Any) -> None:
    //         pass

    fn serialize_name(name: BytesStart<'_>) -> Option<String> {
        Self::read_text(name.local_name().into_inner())
    }

    fn serialize_namespace(ns: ResolveResult<'_>) -> Option<String> {
        if let ResolveResult::Bound(b) = ns {
            Self::read_text(b.into_inner())
        } else {
            None
        }
    }

    fn location_match(
        location: &[(Option<String>, Option<String>)],
        expected: &[(Option<&str>, &str)],
    ) -> bool {
        location
            .iter()
            .map(|(l, r)| (l.as_deref(), r.as_deref()))
            .rev()
            .eq(expected.iter().map(|(l, r)| (*l, Some(*r))))
    }

    fn read_text(raw: &[u8]) -> Option<String> {
        match String::from_utf8(raw.to_vec()) {
            Ok(namespace) => Some(namespace),
            Err(err) => {
                tracing::event!(Level::WARN, ?err, ?raw, "Invalid XML");
                None
            },
        }
    }

    //     def handle_message(self, msg: str, src: Optional[UdpAddress] = None) -> Optional[str]:
    fn handle_message(&self, message: &str, _source: Option<UdpAddress>) {
        // """
        // handle a WSD message
        // """
        let mut reader = NsReader::from_str(message);

        let message_id_path = &[
            (Some(XML_SOAP_NAMESPACE), "Header"),
            (Some(XML_WSA_NAMESPACE), "MessageID"),
        ][..];

        let action_path = &[
            (Some(XML_SOAP_NAMESPACE), "Header"),
            (Some(XML_WSA_NAMESPACE), "Action"),
        ][..];

        let mut _action: Option<String> = None;
        let mut _message_id: Option<String> = None;

        // let mut header = None;
        // let mut body = None;

        // let mut depth = 0;

        let mut location = vec![];

        loop {
            match reader.read_resolved_event() {
                Ok((ns, event)) => match event {
                    Event::Start(bytes_start) => {
                        let namespace = Self::serialize_namespace(ns);
                        let name = Self::serialize_name(bytes_start);

                        location.push((namespace, name));

                        // if bytes_start.local_name().into_inner() == "Header".as_bytes() {
                        //     header = parse_header(reader)?;
                        // } else if bytes_start.local_name().into_inner() == "Body".as_bytes() {
                        //     body = parse_body(reader)?;
                        // }
                    },
                    Event::Text(text) => {
                        if Self::location_match(&location, action_path) {
                            //     // TODO error
                            _action = Self::read_text(text.as_ref());
                        } else if Self::location_match(&location, message_id_path) {
                            //     // TODO error
                            _message_id = Self::read_text(text.as_ref());
                        }
                    },
                    Event::End(_) => {
                        location.pop();
                    },
                    Event::Eof => {
                        break;
                    },
                    _ => {
                        // ...
                    },
                },
                Err(err) => panic!("Error at position {}: {:?}", reader.error_position(), err),
            }
        }

        // try:
        //     tree = ETfromString(msg)
        // except ElementTree.ParseError:
        //     return None

        // header = tree.find('./soap:Header', namespaces)
        // if header is None:
        //     return None

        // msg_id_tag = header.find('./wsa:MessageID', namespaces)
        // if msg_id_tag is None:
        //     return None

        // msg_id = str(msg_id_tag.text)

        // # check for duplicates
        // if self.is_duplicated_msg(msg_id):
        //     logger.debug('known message ({0}): dropping it'.format(msg_id))
        //     return None

        // action_tag = header.find('./wsa:Action', namespaces)
        // if action_tag is None:
        //     return None

        // action: str = str(action_tag.text)
        // _, _, action_method = action.rpartition('/')

        // if src:
        //     logger.info('{}:{}({}) - - "{} {} UDP" - -'.format(src.transport_str, src.port, src.interface,
        //                                                        action_method, msg_id))
        // else:
        //     # http logging is already done by according server
        //     logger.debug('processing WSD {} message ({})'.format(action_method, msg_id))

        // body = tree.find('./soap:Body', namespaces)
        // if body is None:
        //     return None

        // logger.debug('incoming message content is {0}'.format(msg))
        // if action in self.handlers:
        //     handler = self.handlers[action]
        //     retval = handler(header, body)
        //     if retval is not None:
        //         response, response_type = retval
        //         return self.build_message(WSA_ANON, response_type, header, response)
        // else:
        //     logger.debug('unhandled action {0}/{1}'.format(action, msg_id))

        // return None
    }
    //     def is_duplicated_msg(self, msg_id: str) -> bool:
    //         """
    //         Check for a duplicated message.

    //         Implements SOAP-over-UDP Appendix II Item 2
    //         """
    //         if msg_id in type(self).known_messages:
    //             return True

    //         type(self).known_messages.append(msg_id)

    //         return False

    //     def xml_to_str(self, xml: ElementTree.Element) -> str:
    //         retval = '<?xml version="1.0" encoding="utf-8"?>'
    //         retval = retval + ElementTree.tostring(xml, encoding='utf-8').decode('utf-8')

    //         return retval
}
