mod body;
mod header;

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
    WSA_ANON, WSA_DISCOVERY, WSD_BYE, WSD_GET, WSD_HELLO, WSD_PROBE, WSD_PROBE_MATCH, WSD_RESOLVE,
    WSD_RESOLVE_MATCH, XML_SOAP_NAMESPACE, XML_WSA_NAMESPACE,
};
use crate::soap::builder::body::WriteBody;
use crate::soap::builder::body::bye::Bye;
use crate::soap::builder::body::empty_body::EmptyBody;
use crate::soap::builder::body::hello::Hello;
use crate::soap::builder::body::probe::Probe;
use crate::soap::builder::body::probe_matches::ProbeMatches;
use crate::soap::builder::body::resolve::Resolve;
use crate::soap::builder::body::resolve_matches::ResolveMatches;
use crate::soap::builder::header::WriteExtraHeaders;
use crate::soap::builder::header::app_sequence::AppSequence;
use crate::soap::builder::header::none::NoExtraHeaders;
use crate::soap::builder::header::reply_to_from::ReplyToFrom;

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

pub struct Builder<'config> {
    config: &'config Config,
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

impl<'config> Builder<'config> {
    fn new(config: &'config Config) -> Self {
        Self { config }
    }

    fn build_message<H, B, W>(
        &mut self,
        to_addr: &str,
        action: &str,
        relates_to: Option<Urn>,
        extra_headers: H,
        body: B,
    ) -> Result<(W, Urn), xml::writer::Error>
    where
        H: WriteExtraHeaders<W>,
        B: WriteBody<W>,
        W: Write + Default + AsRef<[u8]>,
    {
        let response =
            self.build_message_tree::<H, B, W>(to_addr, action, relates_to, extra_headers, body)?;

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
    fn build_message_tree<H, B, W>(
        &mut self,
        to_addr: &str,
        action: &str,
        relates_to: Option<Urn>,
        extra_headers: H,
        body: B,
    ) -> Result<(W, Urn), xml::writer::Error>
    where
        H: WriteExtraHeaders<W>,
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

        for (prefix, namespace) in extra_headers.namespaces() {
            start_element = start_element.ns(prefix, namespace);
        }

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

        WriteExtraHeaders::<W>::write_extra_headers(extra_headers, &mut header_and_body)?;

        // close soap:Heap
        header_and_body.write(XmlEvent::end_element())?;

        header_and_body.write(XmlEvent::start_element("soap:Body"))?;

        WriteBody::<W>::write_body(body, self.config, &mut header_and_body)?;

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
        let mut builder = Builder::new(config);

        let message = builder.build_message::<_, _, Vec<u8>>(
            WSA_DISCOVERY,
            WSD_HELLO,
            None,
            AppSequence::new(
                &config.wsd_instance_id,
                messages_built.fetch_add(1, Ordering::SeqCst),
            ),
            Hello::new(xaddr),
        )?;

        Ok(message.0)
    }

    /// WS-Discovery, Section 4.2, Bye message
    pub fn build_bye(
        config: &Config,
        messages_built: &AtomicU64,
    ) -> Result<Vec<u8>, xml::writer::Error> {
        let mut builder = Builder::new(config);

        let message = builder.build_message(
            WSA_DISCOVERY,
            WSD_BYE,
            None,
            AppSequence::new(
                &config.wsd_instance_id,
                messages_built.fetch_add(1, Ordering::SeqCst),
            ),
            Bye::new(),
        )?;

        Ok(message.0)
    }

    // WS-Discovery, Section 4.3, Probe message
    pub fn build_probe(config: &Config) -> Result<(Vec<u8>, Urn), xml::writer::Error> {
        let mut builder = Builder::new(config);

        let message = builder.build_message(
            WSA_DISCOVERY,
            WSD_PROBE,
            None,
            NoExtraHeaders::new(),
            Probe::new(),
        )?;

        Ok((message.0, message.1))
    }

    // WS-Discovery, Section 6.1, Resolve message
    pub fn build_resolve(
        config: &Config,
        endpoint: Uuid,
    ) -> Result<(Vec<u8>, Urn), xml::writer::Error> {
        let mut builder = Builder::new(config);

        let message = builder.build_message(
            WSA_DISCOVERY,
            WSD_RESOLVE,
            None,
            NoExtraHeaders::new(),
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
        let mut builder = Builder::new(config);

        let message = builder.build_message(
            WSA_ANON,
            WSD_RESOLVE_MATCH,
            Some(relates_to),
            AppSequence::new(
                &config.wsd_instance_id,
                messages_built.fetch_add(1, Ordering::SeqCst),
            ),
            ResolveMatches::new(address),
        )?;

        Ok(message.0)
    }

    pub fn build_probe_matches(
        config: &Config,
        messages_built: &AtomicU64,
        relates_to: Urn,
    ) -> Result<Vec<u8>, xml::writer::Error> {
        let mut builder = Builder::new(config);

        let message = builder.build_message(
            WSA_ANON,
            WSD_PROBE_MATCH,
            Some(relates_to),
            AppSequence::new(
                &config.wsd_instance_id,
                messages_built.fetch_add(1, Ordering::SeqCst),
            ),
            ProbeMatches::new(),
        )?;

        Ok(message.0)
    }

    pub fn build_get(config: &Config, endpoint: Uuid) -> Result<Vec<u8>, xml::writer::Error> {
        let mut builder = Builder::new(config);

        builder
            .build_message(
                endpoint.as_urn().to_string().as_str(),
                WSD_GET,
                None,
                ReplyToFrom::new(&config.uuid_as_urn_str),
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
