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
use crate::constants;
use crate::soap::builder::body::WriteBody;
use crate::soap::builder::body::bye::Bye;
use crate::soap::builder::body::empty_body::EmptyBody;
use crate::soap::builder::body::hello::Hello;
use crate::soap::builder::body::metadata::MetaData;
use crate::soap::builder::body::probe::Probe;
use crate::soap::builder::body::probe_matches::ProbeMatches;
use crate::soap::builder::body::resolve::Resolve;
use crate::soap::builder::body::resolve_matches::ResolveMatches;
use crate::soap::builder::header::WriteExtraHeaders;
use crate::soap::builder::header::app_sequence::AppSequence;
use crate::soap::builder::header::none::NoExtraHeaders;
use crate::soap::builder::header::reply_to_from::ReplyToFrom;
use crate::soap::{MulticastMessage, UnicastMessage};
use crate::wsd::device::DeviceUri;

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
        Uuid::now_v7().urn()
    }
}

impl<'config> Builder<'config> {
    fn new(config: &'config Config) -> Self {
        Self { config }
    }

    fn build_message<D, H, B, W>(
        &mut self,
        to_addr: D,
        action: &str,
        relates_to: Option<Urn>,
        extra_headers: H,
        body: B,
    ) -> Result<(W, Urn), xml::writer::Error>
    where
        D: AsRef<str>,
        H: WriteExtraHeaders<W>,
        B: WriteBody<W>,
        W: Write + Default + AsRef<[u8]>,
    {
        let response = self.build_message_tree::<D, H, B, W>(
            &to_addr,
            action,
            relates_to,
            extra_headers,
            body,
        )?;

        event!(
            Level::DEBUG,
            to_addr = %to_addr.as_ref(),
            %action,
            ?relates_to,
            xml = %String::from_utf8_lossy(response.0.as_ref()).as_ref(),
            "constructed xml for WSD message",
        );

        Ok(response)
    }

    /// Build a WSD message with a given action string including SOAP header.
    ///
    /// The message can be constructed based on a response to another
    /// message (given by its header) and with a optional response that
    /// serves as the message's body
    fn build_message_tree<D, H, B, W>(
        &mut self,
        to_addr: &D,
        action: &str,
        relates_to: Option<Urn>,
        extra_headers: H,
        body: B,
    ) -> Result<(W, Urn), xml::writer::Error>
    where
        D: AsRef<str>,
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
            .ns("soap", constants::XML_SOAP_NAMESPACE)
            .ns("wsa", constants::XML_WSA_NAMESPACE);

        for (prefix, namespace) in extra_headers.namespaces() {
            start_element = start_element.ns(prefix, namespace);
        }

        for (prefix, namespace) in body.namespaces() {
            start_element = start_element.ns(prefix, namespace);
        }

        header_and_body.write(start_element)?;

        header_and_body.write(XmlEvent::start_element("soap:Header"))?;
        header_and_body.write(XmlEvent::start_element("wsa:To"))?;
        header_and_body.write(XmlEvent::Characters(to_addr.as_ref()))?;
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
    ) -> Result<MulticastMessage, xml::writer::Error> {
        let mut builder = Builder::new(config);

        let (message, _): (Vec<_>, _) = builder.build_message(
            constants::WSA_DISCOVERY,
            constants::WSD_HELLO,
            None,
            AppSequence::new(
                &config.wsd_instance_id,
                &config.sequence_id,
                messages_built.fetch_add(1, Ordering::Relaxed),
            ),
            Hello::new(xaddr),
        )?;

        Ok(MulticastMessage::Hello(message.into_boxed_slice()))
    }

    /// WS-Discovery, Section 4.2, Bye message
    pub fn build_bye(
        config: &Config,
        messages_built: &AtomicU64,
    ) -> Result<MulticastMessage, xml::writer::Error> {
        let mut builder = Builder::new(config);

        let (message, _): (Vec<_>, _) = builder.build_message(
            constants::WSA_DISCOVERY,
            constants::WSD_BYE,
            None,
            AppSequence::new(
                &config.wsd_instance_id,
                &config.sequence_id,
                messages_built.fetch_add(1, Ordering::Relaxed),
            ),
            Bye::new(),
        )?;

        Ok(MulticastMessage::Bye(message.into_boxed_slice()))
    }

    // WS-Discovery, Section 4.3, Probe message
    pub fn build_probe(config: &Config) -> Result<(MulticastMessage, Urn), xml::writer::Error> {
        let mut builder = Builder::new(config);

        let (message, urn): (Vec<_>, _) = builder.build_message(
            constants::WSA_DISCOVERY,
            constants::WSD_PROBE,
            None,
            NoExtraHeaders::new(),
            Probe::new(),
        )?;

        Ok((MulticastMessage::Probe(message.into_boxed_slice()), urn))
    }

    // WS-Discovery, Section 6.1, Resolve message
    pub fn build_resolve(
        config: &Config,
        endpoint: &DeviceUri,
    ) -> Result<(MulticastMessage, Urn), xml::writer::Error> {
        let mut builder = Builder::new(config);

        let (message, urn): (Vec<_>, _) = builder.build_message(
            constants::WSA_DISCOVERY,
            constants::WSD_RESOLVE,
            None,
            NoExtraHeaders::new(),
            Resolve::new(endpoint),
        )?;

        Ok((MulticastMessage::Resolve(message.into_boxed_slice()), urn))
    }

    pub fn build_resolve_matches(
        config: &Config,
        address: IpAddr,
        messages_built: &AtomicU64,
        relates_to: Urn,
    ) -> Result<UnicastMessage, xml::writer::Error> {
        let mut builder = Builder::new(config);

        let (message, _): (Vec<_>, _) = builder.build_message(
            constants::WSA_ANON,
            constants::WSD_RESOLVE_MATCH,
            Some(relates_to),
            AppSequence::new(
                &config.wsd_instance_id,
                &config.sequence_id,
                messages_built.fetch_add(1, Ordering::Relaxed),
            ),
            ResolveMatches::new(address),
        )?;

        Ok(UnicastMessage::ResolveMatches(message.into_boxed_slice()))
    }

    pub fn build_probe_matches(
        config: &Config,
        messages_built: &AtomicU64,
        relates_to: Urn,
    ) -> Result<UnicastMessage, xml::writer::Error> {
        let mut builder = Builder::new(config);

        let (message, _): (Vec<_>, _) = builder.build_message(
            constants::WSA_ANON,
            constants::WSD_PROBE_MATCH,
            Some(relates_to),
            AppSequence::new(
                &config.wsd_instance_id,
                &config.sequence_id,
                messages_built.fetch_add(1, Ordering::Relaxed),
            ),
            ProbeMatches::new(),
        )?;

        Ok(UnicastMessage::ProbeMatches(message.into_boxed_slice()))
    }

    pub fn build_get(config: &Config, endpoint: &DeviceUri) -> Result<Vec<u8>, xml::writer::Error> {
        let mut builder = Builder::new(config);

        builder
            .build_message(
                endpoint,
                constants::WSD_GET,
                None,
                ReplyToFrom::new(&config.uuid_as_device_uri),
                EmptyBody::new(),
            )
            .map(|(m, _)| m)
    }

    pub fn build_get_response(
        config: &Config,
        relates_to: Urn,
    ) -> Result<UnicastMessage, xml::writer::Error> {
        let mut builder = Builder::new(config);

        let (message, _): (Vec<_>, _) = builder.build_message(
            constants::WSA_ANON,
            constants::WSD_GET_RESPONSE,
            Some(relates_to),
            NoExtraHeaders::new(),
            MetaData::new(),
        )?;

        Ok(UnicastMessage::GetResponse(message.into_boxed_slice()))
    }
}
