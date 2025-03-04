use std::borrow::Cow;
use std::io::{Cursor, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use color_eyre::eyre;
use quick_xml::Writer;
use quick_xml::events::{BytesDecl, BytesText, Event};
use tracing::{Level, event};
use uuid::Uuid;

use crate::config::Config;
use crate::constants::{WSA_DISCOVERY, WSA_URI, WSD_HELLO, WSD_URI, WSDP_URI};

const NAMESPACES: [(&str, &str); 7] = [
    ("soap", "http://www.w3.org/2003/05/soap-envelope"),
    ("wsa", WSA_URI),
    ("wsd", WSD_URI),
    ("wsx", "http://schemas.xmlsoap.org/ws/2004/09/mex"),
    ("wsdp", WSDP_URI),
    ("pnpx", "http://schemas.microsoft.com/windows/pnpx/2005/10"),
    ("pub", "http://schemas.microsoft.com/windows/pub/2005/07"),
];

static MESSAGES_BUILT: AtomicU64 = AtomicU64::new(0);

struct Builder {
    config: Arc<Config>,
}

#[expect(unused)]
impl Builder {
    fn new(config: &Arc<Config>) -> Self {
        Self {
            config: Arc::clone(config),
        }
    }

    fn build_message(
        &self,
        to_addr: &str,
        action: &str,
        request_header: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Vec<u8>, eyre::Report> {
        let response = self.build_message_tree(to_addr, action, request_header, body)?;

        event!(
            Level::DEBUG,
            response = String::from_utf8_lossy(&response).as_ref(),
            "constructed xml for WSD message"
        );

        Ok(response)
    }

    /// Build a WSD message with a given action string including SOAP header.
    ///
    /// The message can be constructed based on a response to another
    /// message (given by its header) and with a optional response that
    /// serves as the message's body
    fn build_message_tree(
        &self,
        to_addr: &str,
        action: &str,
        _request_header: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Vec<u8>, eyre::Report> {
        let mut writer = Writer::new(Cursor::new(Vec::new()));
        writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;

        // TODO we ideally want to postpone this to the end where we only record namespaces actually in the file
        // but tis is _SO_ much easier
        let envelope = NAMESPACES.iter().fold(
            writer.create_element("soap:Envelope"),
            |envelope, (short_name, url)| {
                envelope.with_attribute((format!("xmlns:{}", short_name).as_str(), *url))
            },
        );

        envelope.write_inner_content(|writer| {
            writer
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
                        .write_text_content(BytesText::new(
                            Uuid::new_v4().urn().to_string().as_str(),
                        ))?;

                    self.add_header_elements(writer, action)?;

                    Ok(())
                })?;

            writer
                .create_element("soap:Body")
                .write_inner_content(|writer| {
                    writer.get_mut().write_all(body.unwrap_or(&[]))?;

                    Ok(())
                })?;
            Ok(())
        })?;

        Ok(writer.into_inner().into_inner())
    }

    fn build_hello(&self, xaddr: SocketAddr) -> Result<String, eyre::Report> {
        let mut writer = Writer::new(Cursor::new(Vec::new()));

        writer
            .create_element("wsd:Hello")
            .write_inner_content(|writer| {
                self.add_endpoint_reference(writer, None)?;

                // THINK: Microsoft does not send the transport address here due to privacy reasons. Could make this optional.
                self.add_xaddr(writer, xaddr)?;
                self.add_metadata_version(writer)?;

                Ok(())
            })?;

        let message = self.build_message(
            WSA_DISCOVERY,
            WSD_HELLO,
            None,
            Some(&writer.into_inner().into_inner()),
        )?;

        Ok(String::from_utf8(message).unwrap())
    }

    fn add_header_elements<'element, 'result>(
        &self,
        element: &'element mut Writer<Cursor<Vec<u8>>>,
        _action: &str,
    ) -> Result<&'result mut Writer<Cursor<Vec<u8>>>, std::io::Error>
    where
        'element: 'result,
    {
        let wsd_instance_id = self.config.wsd_instance_id.to_string();
        let urn = Uuid::new_v4().urn().to_string();
        let message_number = MESSAGES_BUILT.fetch_add(1, Ordering::SeqCst).to_string();

        element
            .create_element("wsd:AppSequence")
            .with_attributes([
                ("InstanceId", wsd_instance_id.as_str()),
                ("SequenceId", urn.as_str()),
                ("MessageNumber", &message_number),
            ])
            .write_empty()
    }

    fn add_endpoint_reference<'element, 'result>(
        &self,
        element: &'element mut Writer<Cursor<Vec<u8>>>,
        endpoint: Option<&str>,
    ) -> Result<&'result mut Writer<Cursor<Vec<u8>>>, std::io::Error>
    where
        'element: 'result,
    {
        let endpoint = endpoint.map_or_else(
            || {
                let urn = self.config.uuid.urn().to_string();

                Cow::Owned(urn)
            },
            Cow::Borrowed,
        );

        let text = BytesText::new(endpoint.as_ref());

        element
            .create_element("wsa:EndpointReference")
            .write_inner_content(|writer| {
                writer
                    .create_element("wsa:Address")
                    .write_text_content(text)?;

                Ok(())
            })
    }

    fn add_xaddr<'element, 'result>(
        &self,
        element: &'element mut Writer<Cursor<Vec<u8>>>,
        socket_addr: SocketAddr,
    ) -> Result<&'result mut Writer<Cursor<Vec<u8>>>, std::io::Error>
    where
        'element: 'result,
    {
        let address = format!(
            "http://{}:{}/{}",
            socket_addr.ip(),
            socket_addr.port(),
            self.config.uuid
        );

        let text = BytesText::new(&address);

        element
            .create_element("wsd:XAddrs")
            .write_text_content(text)
    }

    #[expect(clippy::unused_self)]
    fn add_metadata_version<'element, 'result>(
        &self,
        element: &'element mut Writer<Cursor<Vec<u8>>>,
    ) -> Result<&'result mut Writer<Cursor<Vec<u8>>>, std::io::Error>
    where
        'element: 'result,
    {
        let text = BytesText::new("1");

        element
            .create_element("wsd:MetadataVersion")
            .write_text_content(text)
    }
}
