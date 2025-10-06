mod bye;
mod empty_body;
mod hello;
mod probe;
mod probe_matches;
mod resolve;
mod resolve_matches;

use std::io::Write;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

use tracing::{Level, event};
use uuid::Uuid;
use uuid::fmt::Urn;
use xml::EventWriter;
use xml::writer::XmlEvent;

use crate::config::Config;
use crate::constants::{
    WSA_ANON, WSA_DISCOVERY, WSD_BYE, WSD_GET, WSD_HELLO, WSD_HTTP_PORT, WSD_PROBE,
    WSD_PROBE_MATCH, WSD_RESOLVE, WSD_RESOLVE_MATCH, XML_SOAP_NAMESPACE, XML_WSA_NAMESPACE,
};
use crate::soap::builder::bye::Bye;
use crate::soap::builder::empty_body::EmptyBody;
use crate::soap::builder::hello::Hello;
use crate::soap::builder::probe::Probe;
use crate::soap::builder::probe_matches::ProbeMatches;
use crate::soap::builder::resolve::Resolve;
use crate::soap::builder::resolve_matches::ResolveMatches;
use crate::url_ip_addr::UrlIpAddr;

pub enum MessageType {
    Hello,
    Bye,
    Probe,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            MessageType::Hello => write!(f, "Hello"),
            MessageType::Bye => write!(f, "Bye"),
            MessageType::Probe => write!(f, "Probe"),
        }
    }
}

type WriteElementCallback<W> =
    fn(&mut Builder, &mut EventWriter<W>) -> Result<(), xml::writer::Error>;

pub struct Builder<'config, 'm> {
    config: &'config Config,
    messages_built: &'m AtomicU64,
}

#[cfg_attr(
    not(test),
    expect(
        clippy::cfg_not_test,
        reason = "Adding in the ability to control UUID generation seems excessive"
    )
)]
fn generate_message_id() -> Urn {
    #[cfg(test)]
    {
        Uuid::nil().urn()
    }

    #[cfg(not(test))]
    {
        Uuid::new_v4().urn()
    }
}

#[cfg_attr(
    not(test),
    expect(
        clippy::cfg_not_test,
        reason = "Adding in the ability to control UUID generation seems excessive"
    )
)]
fn sequence_id() -> Urn {
    #[cfg(test)]
    {
        Uuid::nil().urn()
    }

    #[cfg(not(test))]
    {
        Uuid::new_v4().urn()
    }
}

trait WriteBody<W>
where
    W: Write,
{
    fn namespaces(&self) -> impl Iterator<Item = (impl Into<String>, impl Into<String>)> {
        std::iter::empty::<(String, String)>()
    }

    fn write_body(
        self,
        builder: &mut Builder,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error>;
}

impl<'config, 'm> Builder<'config, 'm> {
    fn new(config: &'config Config, messages_built: &'m AtomicU64) -> Self {
        Self {
            config,
            messages_built,
        }
    }

    fn build_message<B, W>(
        &mut self,
        to_addr: &str,
        action: &str,
        relates_to: Option<Urn>,
        add_extra_headers: Option<WriteElementCallback<W>>,
        body: B,
    ) -> Result<(W, Urn), xml::writer::Error>
    where
        B: WriteBody<W>,
        W: Write + Default + AsRef<[u8]>,
    {
        let response =
            self.build_message_tree::<B, W>(to_addr, action, relates_to, add_extra_headers, body)?;

        event!(
            Level::DEBUG,
            "constructed xml for WSD message: {}",
            String::from_utf8_lossy(response.0.as_ref()).as_ref()
        );

        Ok(response)
    }

    /// Build a WSD message with a given action string including SOAP header.
    ///
    /// The message can be constructed based on a response to another
    /// message (given by its header) and with a optional response that
    /// serves as the message's body
    fn build_message_tree<B, W>(
        &mut self,
        to_addr: &str,
        action: &str,
        relates_to: Option<Urn>,
        add_extra_headers: Option<WriteElementCallback<W>>,
        body: B,
    ) -> Result<(W, Urn), xml::writer::Error>
    where
        B: WriteBody<W>,
        W: Write + Default,
    {
        let message_id = generate_message_id();

        let mut header_and_body = EventWriter::new(W::default());

        header_and_body.write(XmlEvent::StartDocument {
            version: xml::common::XmlVersion::Version10,
            encoding: Some("utf-8"),
            standalone: None,
        })?;

        let mut start_element = XmlEvent::start_element("soap:Envelope")
            .ns("soap", XML_SOAP_NAMESPACE)
            .ns("wsa", XML_WSA_NAMESPACE);

        for (prefix, namespace) in body.namespaces() {
            start_element = start_element.ns(prefix, namespace);
        }

        header_and_body.write(start_element)?;

        header_and_body.write(XmlEvent::start_element("soap:Header"))?;
        header_and_body.write(XmlEvent::start_element("wsa:To"))?;
        header_and_body.write(XmlEvent::Characters(to_addr))?;
        header_and_body.write(XmlEvent::end_element())?;

        header_and_body.write(XmlEvent::start_element("wsa:Action"))?;
        header_and_body.write(XmlEvent::Characters(action))?;
        header_and_body.write(XmlEvent::end_element())?;

        // original codebase uses v1, but spec doesn't specify version,
        // and MS uses v4
        header_and_body.write(XmlEvent::start_element("wsa:MessageID"))?;
        header_and_body.write(XmlEvent::Characters(&message_id.to_string()))?;
        header_and_body.write(XmlEvent::end_element())?;

        if let Some(relates_to) = relates_to {
            header_and_body.write(XmlEvent::start_element("wsa:RelatesTo"))?;
            header_and_body.write(XmlEvent::Characters(
                relates_to.encode_lower(&mut Uuid::encode_buffer()),
            ))?;
            header_and_body.write(XmlEvent::end_element())?;
        }

        if let Some(add_extra_headers) = add_extra_headers {
            add_extra_headers(self, &mut header_and_body)?;
        }

        // close soap:Heap
        header_and_body.write(XmlEvent::end_element())?;

        header_and_body.write(XmlEvent::start_element("soap:Body"))?;

        WriteBody::<W>::write_body(body, self, &mut header_and_body)?;

        // close body
        header_and_body.write(XmlEvent::end_element())?;

        // close envelope
        header_and_body.write(XmlEvent::end_element())?;

        Ok((header_and_body.into_inner(), message_id))
    }

    /// WS-Discovery, Section 4.1, Hello message
    pub fn build_hello(
        config: &Config,
        messages_built: &AtomicU64,
        xaddr: IpAddr,
    ) -> Result<Vec<u8>, xml::writer::Error> {
        let mut builder = Builder::new(config, messages_built);

        let message = builder.build_message::<Hello, Vec<u8>>(
            WSA_DISCOVERY,
            WSD_HELLO,
            None,
            None,
            Hello::new(xaddr),
        )?;

        Ok(message.0)
    }

    /// WS-Discovery, Section 4.2, Bye message
    pub fn build_bye(
        config: &Config,
        messages_built: &AtomicU64,
    ) -> Result<Vec<u8>, xml::writer::Error> {
        let mut builder = Builder::new(config, messages_built);

        let message = builder.build_message(WSA_DISCOVERY, WSD_BYE, None, None, Bye::new())?;

        Ok(message.0)
    }

    // WS-Discovery, Section 4.3, Probe message
    pub fn build_probe(
        config: &Config,
        messages_built: &AtomicU64,
    ) -> Result<(Vec<u8>, Urn), xml::writer::Error> {
        let mut builder = Builder::new(config, messages_built);

        let message = builder.build_message(WSA_DISCOVERY, WSD_PROBE, None, None, Probe::new())?;

        Ok((message.0, message.1))
    }

    // WS-Discovery, Section 6.1, Resolve message
    pub fn build_resolve(
        config: &Config,
        endpoint: Uuid,
        messages_built: &AtomicU64,
    ) -> Result<(Vec<u8>, Urn), xml::writer::Error> {
        let mut builder = Builder::new(config, messages_built);

        let message = builder.build_message(
            WSA_DISCOVERY,
            WSD_RESOLVE,
            None,
            None,
            Resolve::new(endpoint),
        )?;

        Ok((message.0, message.1))
    }

    pub fn build_resolve_matches(
        config: &Config,
        address: IpAddr,
        messages_built: &AtomicU64,
        relates_to: Urn,
    ) -> Result<Vec<u8>, xml::writer::Error> {
        let mut builder = Builder::new(config, messages_built);

        let message = builder.build_message(
            WSA_ANON,
            WSD_RESOLVE_MATCH,
            Some(relates_to),
            #[expect(
                clippy::redundant_closure_for_method_calls,
                reason = "lifetimes aren't passed when using function pointer"
            )]
            Some(|builder, element| builder.add_wsd_host_header_elements(element)),
            ResolveMatches::new(address),
        )?;

        Ok(message.0)
    }

    pub fn build_probe_matches(
        config: &Config,
        messages_built: &AtomicU64,
        relates_to: Urn,
    ) -> Result<Vec<u8>, xml::writer::Error> {
        let mut builder = Builder::new(config, messages_built);

        let message = builder.build_message(
            WSA_ANON,
            WSD_PROBE_MATCH,
            Some(relates_to),
            #[expect(
                clippy::redundant_closure_for_method_calls,
                reason = "lifetimes aren't passed when using function pointer"
            )]
            Some(|builder, element| builder.add_wsd_host_header_elements(element)),
            ProbeMatches::new(),
        )?;

        Ok(message.0)
    }

    fn add_wsd_host_header_elements<W>(
        &mut self,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error>
    where
        W: Write,
    {
        let wsd_instance_id = self.config.wsd_instance_id.to_string();
        let sequence_id = sequence_id().to_string();
        let message_number = self
            .messages_built
            .fetch_add(1, Ordering::SeqCst)
            .to_string();

        writer.write(
            XmlEvent::start_element("wsd:AppSequence")
                .attr("InstanceId", wsd_instance_id.as_str())
                .attr("SequenceId", sequence_id.as_str())
                .attr("MessageNumber", &message_number),
        )?;

        writer.write(XmlEvent::end_element())?;

        Ok(())
    }

    fn add_wsd_client_get_header_elements(
        &mut self,
        writer: &mut EventWriter<Vec<u8>>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("wsa:ReplyTo"))?;
        writer.write(XmlEvent::start_element("wsa:Address"))?;
        writer.write(XmlEvent::Characters(WSA_ANON))?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        writer.write(XmlEvent::start_element("wsa:From"))?;
        writer.write(XmlEvent::start_element("wsa:Address"))?;
        writer.write(XmlEvent::Characters(
            self.config.uuid.urn().to_string().as_str(),
        ))?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }

    #[expect(clippy::unused_self, reason = "Builder consistency")]
    fn add_types<W>(
        &self,
        writer: &mut EventWriter<W>,
        types: &str,
    ) -> Result<(), xml::writer::Error>
    where
        W: Write,
    {
        writer.write(XmlEvent::start_element("wsd:Types"))?;
        writer.write(XmlEvent::Characters(types))?;
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }

    fn add_endpoint_reference<W: Write>(
        &mut self,
        writer: &mut EventWriter<W>,
        endpoint: Option<Uuid>,
    ) -> Result<(), xml::writer::Error> {
        let endpoint = endpoint.unwrap_or(self.config.uuid).urn().to_string();

        writer.write(XmlEvent::start_element("wsa:EndpointReference"))?;
        writer.write(XmlEvent::start_element("wsa:Address"))?;
        writer.write(XmlEvent::Characters(&endpoint))?;
        writer.write(XmlEvent::end_element())?;
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }

    fn add_xaddr<W: Write>(
        &mut self,
        writer: &mut EventWriter<W>,
        ip_addr: IpAddr,
    ) -> Result<(), xml::writer::Error> {
        let address = format!(
            "http://{}:{}/{}",
            UrlIpAddr::from(ip_addr),
            WSD_HTTP_PORT,
            self.config.uuid
        );

        writer.write(XmlEvent::start_element("wsd:XAddrs"))?;
        writer.write(XmlEvent::Characters(&address))?;
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }

    #[expect(clippy::unused_self, reason = "Builder consistency")]
    fn add_metadata_version<W: Write>(
        &self,
        writer: &mut EventWriter<W>,
    ) -> Result<(), xml::writer::Error> {
        writer.write(XmlEvent::start_element("wsd:MetadataVersion"))?;
        writer.write(XmlEvent::Characters("1"))?;
        writer.write(XmlEvent::end_element())?;

        Ok(())
    }

    pub fn build_get(
        config: &Config,
        endpoint: Uuid,
        messages_built: &AtomicU64,
    ) -> Result<Vec<u8>, xml::writer::Error> {
        let mut builder = Builder::new(config, messages_built);

        builder
            .build_message(
                endpoint.as_urn().to_string().as_str(),
                WSD_GET,
                None,
                #[expect(
                    clippy::redundant_closure_for_method_calls,
                    reason = "lifetimes aren't passed when using function pointer"
                )]
                Some(|builder, writer| builder.add_wsd_client_get_header_elements(writer)),
                EmptyBody::new(),
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
