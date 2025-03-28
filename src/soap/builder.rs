use std::io::{Cursor, Write};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use hashbrown::HashMap;
use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesText, Event};
use tracing::{Level, event};
use uuid::Uuid;
use uuid::fmt::Urn;

use crate::config::Config;
use crate::constants::{
    WSA_ANON, WSA_DISCOVERY, WSA_URI, WSD_BYE, WSD_GET, WSD_HELLO, WSD_HTTP_PORT, WSD_PROBE,
    WSD_PROBE_MATCH, WSD_RESOLVE, WSD_RESOLVE_MATCH, WSD_TYPE_DEVICE, WSD_TYPE_DEVICE_COMPUTER,
    WSD_URI, XML_PUB_NAMESPACE, XML_WSA_NAMESPACE, XML_WSD_NAMESPACE, XML_WSDP_NAMESPACE,
};
use crate::url_ip_addr::UrlIpAddr;

static MESSAGES_BUILT: AtomicU64 = AtomicU64::new(0);

pub enum MessageType {
    Hello,
    Bye,
    Probe,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::Hello => write!(f, "Hello"),
            MessageType::Bye => write!(f, "Bye"),
            MessageType::Probe => write!(f, "Probe"),
        }
    }
}

type ExtraHeadersCallback =
    fn(&mut Builder, &mut Writer<Cursor<Vec<u8>>>) -> Result<(), std::io::Error>;

pub struct Builder<'config> {
    config: &'config Config,
    namespaces: HashMap<&'static str, &'static str>,
}

impl<'config> Builder<'config> {
    fn new(config: &'config Config) -> Self {
        Self {
            config,
            namespaces: HashMap::new(),
        }
    }

    fn build_message(
        &mut self,
        to_addr: &str,
        action: &str,
        relates_to: Option<&str>,
        add_extra_headers: Option<ExtraHeadersCallback>,
        body: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Urn), quick_xml::errors::Error> {
        let response =
            self.build_message_tree(to_addr, action, relates_to, add_extra_headers, body)?;

        event!(
            Level::DEBUG,
            "constructed xml for WSD message: {}",
            String::from_utf8_lossy(&response.0).as_ref()
        );

        Ok(response)
    }

    /// Build a WSD message with a given action string including SOAP header.
    ///
    /// The message can be constructed based on a response to another
    /// message (given by its header) and with a optional response that
    /// serves as the message's body
    fn build_message_tree(
        &mut self,
        to_addr: &str,
        action: &str,
        relates_to: Option<&str>,
        add_extra_headers: Option<ExtraHeadersCallback>,
        body: Option<&[u8]>,
    ) -> Result<(Vec<u8>, Urn), quick_xml::errors::Error> {
        self.namespaces
            .insert("soap", "http://www.w3.org/2003/05/soap-envelope");
        self.namespaces.insert("wsa", WSA_URI);

        let message_id = Uuid::new_v4().urn();

        let mut header_and_body = Writer::new(Cursor::new(Vec::new()));

        header_and_body
            .create_element("soap:Header")
            .write_inner_content(|writer| {
                writer
                    .create_element("wsa:To")
                    .write_text_content(BytesText::new(to_addr))?;

                writer
                    .create_element("wsa:Action")
                    .write_text_content(BytesText::new(action))?;

                // original codebase uses v1, but spec doesn't specify version,
                // and MS uses v4
                writer
                    .create_element("wsa:MessageID")
                    .write_text_content(BytesText::new(&message_id.to_string()))?;

                if let Some(relates_to) = relates_to {
                    writer
                        .create_element("wsa:RelatesTo")
                        .write_text_content(BytesText::new(relates_to))?;
                }

                if let Some(add_extra_headers) = add_extra_headers {
                    add_extra_headers(self, writer)?;
                };

                Ok(())
            })?;

        let body_writer = header_and_body.create_element("soap:Body");

        if let Some(body) = body {
            body_writer.write_inner_content(|writer| {
                writer.get_mut().write_all(body)?;

                Ok(())
            })?;
        } else {
            body_writer.write_empty()?;
        }

        let mut envelope = Writer::new(Cursor::new(Vec::<u8>::new()));

        envelope.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;

        self.namespaces
            .iter()
            .fold(
                envelope.create_element("soap:Envelope"),
                |envelope, (short_name, url)| {
                    envelope.with_attribute((format!("xmlns:{}", short_name).as_str(), *url))
                },
            )
            .write_inner_content(|writer| {
                writer
                    .get_mut()
                    .write_all(&header_and_body.into_inner().into_inner())
            })?;

        Ok((envelope.into_inner().into_inner(), message_id))
    }

    /// WS-Discovery, Section 4.1, Hello message
    pub fn build_hello(
        config: &Config,
        xaddr: IpAddr,
    ) -> Result<Vec<u8>, quick_xml::errors::Error> {
        let mut builder = Builder::new(config);

        let mut writer = Writer::new(Cursor::new(Vec::new()));

        writer
            .create_element("wsd:Hello")
            .write_inner_content(|writer| {
                builder.add_endpoint_reference(writer, None)?;

                // THINK: Microsoft does not send the transport address here due to privacy reasons. Could make this optional.
                builder.add_xaddr(writer, xaddr)?;
                builder.add_metadata_version(writer)?;

                Ok(())
            })?;

        let message = builder.build_message(
            WSA_DISCOVERY,
            WSD_HELLO,
            None,
            #[expect(clippy::redundant_closure_for_method_calls)]
            Some(|builder, element| builder.add_wsd_host_header_elements(element)),
            Some(&writer.into_inner().into_inner()),
        )?;

        Ok(message.0)
    }

    /// WS-Discovery, Section 4.2, Bye message
    pub fn build_bye(config: &Config) -> Result<Vec<u8>, quick_xml::errors::Error> {
        let mut builder = Builder::new(config);

        let mut writer = Writer::new(Cursor::new(Vec::new()));

        writer
            .create_element("wsd:Bye")
            .write_inner_content(|writer| {
                builder.add_endpoint_reference(writer, None)?;

                Ok(())
            })?;

        let message = builder.build_message(
            WSA_DISCOVERY,
            WSD_BYE,
            None,
            #[expect(clippy::redundant_closure_for_method_calls)]
            Some(|builder, element| builder.add_wsd_host_header_elements(element)),
            Some(&writer.into_inner().into_inner()),
        )?;

        Ok(message.0)
    }

    // WS-Discovery, Section 4.3, Probe message
    pub fn build_probe(config: &Config) -> Result<(Vec<u8>, Urn), quick_xml::errors::Error> {
        let mut builder = Builder::new(config);

        let mut writer = Writer::new(Cursor::new(Vec::new()));

        // xml, i = self.build_message_tree(WSA_DISCOVERY, WSD_PROBE, None, probe)

        writer
            .create_element("wsd:Probe")
            .write_inner_content(|writer| {
                builder.add_types(writer, WSD_TYPE_DEVICE)?;

                Ok(())
            })?;

        let message = builder.build_message(
            WSA_DISCOVERY,
            WSD_PROBE,
            None,
            #[expect(clippy::redundant_closure_for_method_calls)]
            Some(|builder, element| builder.add_wsd_host_header_elements(element)),
            Some(&writer.into_inner().into_inner()),
        )?;

        Ok((message.0, message.1))
    }

    // WS-Discovery, Section 6.1, Resolve message
    pub fn build_resolve(
        config: &Config,
        endpoint: Uuid,
    ) -> Result<(Vec<u8>, Urn), quick_xml::errors::Error> {
        let mut builder = Builder::new(config);

        let mut writer = Writer::new(Cursor::new(Vec::new()));

        writer
            .create_element("wsd:Resolve")
            .write_inner_content(|writer| {
                builder.add_endpoint_reference(writer, Some(endpoint))?;

                Ok(())
            })?;

        let message = builder.build_message(
            WSA_DISCOVERY,
            WSD_RESOLVE,
            None,
            #[expect(clippy::redundant_closure_for_method_calls)]
            Some(|builder, element| builder.add_wsd_host_header_elements(element)),
            Some(&writer.into_inner().into_inner()),
        )?;

        Ok((message.0, message.1))
    }

    pub fn build_resolve_matches(
        config: &Config,
        address: IpAddr,
        relates_to: &str,
    ) -> Result<Vec<u8>, quick_xml::errors::Error> {
        let mut builder = Builder::new(config);

        let mut writer = Writer::new(Cursor::new(Vec::new()));

        writer
            .create_element("wsd:ResolveMatches")
            .write_inner_content(|writer| {
                writer
                    .create_element("wsd:ResolveMatch")
                    .write_inner_content(|writer| {
                        builder.add_endpoint_reference(writer, None)?;

                        builder.add_types(writer, WSD_TYPE_DEVICE_COMPUTER)?;

                        builder.add_xaddr(writer, address)?;

                        builder.add_metadata_version(writer)?;

                        Ok(())
                    })?;

                Ok(())
            })?;

        let message = builder.build_message(
            WSA_ANON,
            WSD_RESOLVE_MATCH,
            Some(relates_to),
            #[expect(clippy::redundant_closure_for_method_calls)]
            Some(|builder, element| builder.add_wsd_host_header_elements(element)),
            Some(&writer.into_inner().into_inner()),
        )?;

        Ok(message.0)
    }

    pub fn build_probe_matches(
        config: &Config,
        relates_to: &str,
    ) -> Result<Vec<u8>, quick_xml::errors::Error> {
        let mut builder = Builder::new(config);

        let mut writer = Writer::new(Cursor::new(Vec::new()));

        writer
            .create_element("wsd:ProbeMatches")
            .write_inner_content(|writer| {
                writer
                    .create_element("wsd:ProbeMatch")
                    .write_inner_content(|writer| {
                        builder.add_endpoint_reference(writer, None)?;

                        builder.add_types(writer, WSD_TYPE_DEVICE_COMPUTER)?;

                        builder.add_metadata_version(writer)?;

                        Ok(())
                    })?;

                Ok(())
            })?;

        let message = builder.build_message(
            WSA_ANON,
            WSD_PROBE_MATCH,
            Some(relates_to),
            #[expect(clippy::redundant_closure_for_method_calls)]
            Some(|builder, element| builder.add_wsd_host_header_elements(element)),
            Some(&writer.into_inner().into_inner()),
        )?;

        Ok(message.0)
    }

    fn add_wsd_host_header_elements(
        &mut self,
        writer: &mut Writer<Cursor<Vec<u8>>>,
    ) -> Result<(), std::io::Error> {
        let wsd_instance_id = self.config.wsd_instance_id.to_string();
        let urn = Uuid::new_v4().urn().to_string();
        let message_number = MESSAGES_BUILT.fetch_add(1, Ordering::SeqCst).to_string();

        writer
            .create_element("wsd:AppSequence")
            .with_attributes([
                ("InstanceId", wsd_instance_id.as_str()),
                ("SequenceId", urn.as_str()),
                ("MessageNumber", &message_number),
            ])
            .write_empty()?;

        self.namespaces.insert("wsd", XML_WSD_NAMESPACE);

        Ok(())
    }

    fn add_wsd_client_get_header_elements(
        &mut self,
        writer: &mut Writer<Cursor<Vec<u8>>>,
    ) -> Result<(), std::io::Error> {
        writer
            .create_element("wsa:ReplyTo")
            .write_inner_content(|writer| {
                writer
                    .create_element("wsa:Address")
                    .write_text_content(BytesText::new(WSA_ANON))?;

                Ok(())
            })?;

        writer
            .create_element("wsa:From")
            .write_inner_content(|writer| {
                writer
                    .create_element("wsa:Address")
                    .write_text_content(BytesText::new(
                        self.config.uuid.urn().to_string().as_str(),
                    ))?;

                Ok(())
            })?;

        self.namespaces.insert("wsa", XML_WSA_NAMESPACE);

        Ok(())
    }

    fn add_types(
        &mut self,
        writer: &mut Writer<Cursor<Vec<u8>>>,
        types: &str,
    ) -> Result<(), std::io::Error> {
        writer
            .create_element("wsd:Types")
            .write_text_content(BytesText::new(types))?;

        self.namespaces.insert("wsd", XML_WSD_NAMESPACE);
        self.namespaces.insert("wsdp", XML_WSDP_NAMESPACE);
        self.namespaces.insert("pub", XML_PUB_NAMESPACE);

        Ok(())
    }

    fn add_endpoint_reference(
        &mut self,
        writer: &mut Writer<Cursor<Vec<u8>>>,
        endpoint: Option<Uuid>,
    ) -> Result<(), std::io::Error> {
        let endpoint = endpoint.unwrap_or(self.config.uuid).urn().to_string();

        let text = BytesText::new(endpoint.as_ref());

        writer
            .create_element("wsa:EndpointReference")
            .write_inner_content(|writer| {
                writer
                    .create_element("wsa:Address")
                    .write_text_content(text)?;

                Ok(())
            })?;

        self.namespaces.insert("wsa", XML_WSA_NAMESPACE);

        Ok(())
    }

    fn add_xaddr(
        &mut self,
        writer: &mut Writer<Cursor<Vec<u8>>>,
        ip_addr: IpAddr,
    ) -> Result<(), std::io::Error> {
        let address = format!(
            "http://{}:{}/{}",
            UrlIpAddr::from(ip_addr),
            WSD_HTTP_PORT,
            self.config.uuid
        );

        let text = BytesText::new(&address);

        writer
            .create_element("wsd:XAddrs")
            .write_text_content(text)?;

        self.namespaces.insert("wsd", XML_WSD_NAMESPACE);

        Ok(())
    }

    fn add_metadata_version(
        &mut self,
        writer: &mut Writer<Cursor<Vec<u8>>>,
    ) -> Result<(), std::io::Error> {
        let text = BytesText::new("1");

        writer
            .create_element("wsd:MetadataVersion")
            .write_text_content(text)?;

        self.namespaces.insert("wsd", WSD_URI);

        Ok(())
    }

    pub fn build_get(config: &Config, endpoint: Uuid) -> Result<Vec<u8>, quick_xml::Error> {
        let mut builder = Builder::new(config);

        builder
            .build_message(
                endpoint.as_urn().to_string().as_str(),
                WSD_GET,
                None,
                #[expect(clippy::redundant_closure_for_method_calls)]
                Some(|builder, element| builder.add_wsd_client_get_header_elements(element)),
                None,
            )
            .map(|(m, _)| m)
    }

    // def handle_probe(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
    //     probe = body.find('./wsd:Probe', namespaces)
    //     if probe is None:
    //         return None

    //     scopes = probe.find('./wsd:Scopes', namespaces)

    //     if scopes:
    //         # THINK: send fault message (see p. 21 in WSD)
    //         logger.debug('scopes ({}) unsupported but probed'.format(scopes))
    //         return None

    //     types_elem = probe.find('./wsd:Types', namespaces)
    //     if types_elem is None:
    //         logger.debug('Probe message lacks wsd:Types element. Ignored.')
    //         return None

    //     types = types_elem.text
    //     if not types == WSD_TYPE_DEVICE:
    //         logger.debug('unknown discovery type ({}) for probe'.format(types))
    //         return None

    //     matches = ElementTree.Element('wsd:ProbeMatches')
    //     match = ElementTree.SubElement(matches, 'wsd:ProbeMatch')
    //     self.add_endpoint_reference(match)
    //     self.add_types(match)
    //     self.add_metadata_version(match)

    //     return matches, WSD_PROBE_MATCH

    // def handle_resolve(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
    //     resolve = body.find('./wsd:Resolve', namespaces)
    //     if resolve is None:
    //         return None

    //     addr = resolve.find('./wsa:EndpointReference/wsa:Address', namespaces)
    //     if addr is None:
    //         logger.debug('invalid resolve request: missing endpoint address')
    //         return None

    //     if not addr.text == args.uuid.urn:
    //         logger.debug('invalid resolve request: address ({}) does not match own one ({})'.format(
    //             addr.text, args.uuid.urn))
    //         return None

    //     matches = ElementTree.Element('wsd:ResolveMatches')
    //     match = ElementTree.SubElement(matches, 'wsd:ResolveMatch')
    //     self.add_endpoint_reference(match)
    //     self.add_types(match)
    //     self.add_xaddr(match, self.mch.address.transport_str)
    //     self.add_metadata_version(match)

    //     return matches, WSD_RESOLVE_MATCH

    // def handle_message(self, msg: str, src: Optional[UdpAddress] = None) -> Optional[str]:
    //     """
    //     handle a WSD message
    //     """
    //     try:
    //         tree = ETfromString(msg)
    //     except ElementTree.ParseError:
    //         return None

    //     header = tree.find('./soap:Header', namespaces)
    //     if header is None:
    //         return None

    //     msg_id_tag = header.find('./wsa:MessageID', namespaces)
    //     if msg_id_tag is None:
    //         return None

    //     msg_id = str(msg_id_tag.text)

    //     # check for duplicates
    //     if self.is_duplicated_msg(msg_id):
    //         logger.debug('known message ({0}): dropping it'.format(msg_id))
    //         return None

    //     action_tag = header.find('./wsa:Action', namespaces)
    //     if action_tag is None:
    //         return None

    //     action: str = str(action_tag.text)
    //     _, _, action_method = action.rpartition('/')

    //     if src:
    //         logger.info('{}:{}({}) - - "{} {} UDP" - -'.format(src.transport_str, src.port, src.interface,
    //                                                            action_method, msg_id))
    //     else:
    //         # http logging is already done by according server
    //         logger.debug('processing WSD {} message ({})'.format(action_method, msg_id))

    //     body = tree.find('./soap:Body', namespaces)
    //     if body is None:
    //         return None

    //     logger.debug('incoming message content is {0}'.format(msg))
    //     if action in self.handlers:
    //         handler = self.handlers[action]
    //         retval = handler(header, body)
    //         if retval is not None:
    //             response, response_type = retval
    //             return self.build_message(WSA_ANON, response_type, header, response)
    //     else:
    //         logger.debug('unhandled action {0}/{1}'.format(action, msg_id))

    //     return None
}
