pub mod generic;
pub mod probe;
pub mod resolve;

use std::borrow::Cow;
use std::net::SocketAddr;
use std::sync::Arc;

use quick_xml::events::Event;
use quick_xml::name::Namespace;
use quick_xml::name::ResolveResult::Bound;
use quick_xml::reader::NsReader;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{Level, event};
use uuid::fmt::Urn;

use crate::constants::{WSA_URI, XML_SOAP_NAMESPACE};
use crate::max_size_deque::MaxSizeDeque;
use crate::network_address::NetworkAddress;

pub struct MessageHandler {
    handled_messages: Arc<RwLock<MaxSizeDeque<Urn>>>,
    network_address: NetworkAddress,
}

pub struct Header<'r> {
    #[expect(unused, reason = "WIP")]
    pub to: Option<Cow<'r, str>>,
    pub action: Cow<'r, str>,
    pub message_id: Urn,
    pub relates_to: Option<Urn>,
}

type ParsedHeader<'r> = Result<Header<'r>, HeaderError>;

#[derive(Error, Debug)]
pub enum MessageHandlerError {
    #[error("Missing Header")]
    MissingHeader,
    #[error("Missing Body")]
    MissingBody,
    #[error("Message already processed")]
    DuplicateMessage,
    #[error("Error parsing XML")]
    XmlError(#[from] quick_xml::errors::Error),
    #[error("Header Error")]
    HeaderError(#[from] HeaderError),
}

#[derive(Error, Debug)]
pub enum HeaderError {
    #[error("Missing Message Id")]
    MissingMessageId,
    #[error("Missing Action")]
    MissingAction,
    #[error("Invalid Message Id")]
    InvalidMessageId(uuid::Error),
    #[error("Invalid Relates To")]
    InvalidRelatesTo(uuid::Error),
    #[error("Error parsing XML")]
    XmlError(#[from] quick_xml::errors::Error),
}

impl MessageHandler {
    pub fn new(
        handled_messages: Arc<RwLock<MaxSizeDeque<Urn>>>,
        network_address: NetworkAddress,
    ) -> Self {
        Self {
            handled_messages,
            network_address,
        }
    }

    /// Handle a WSD message
    pub async fn deconstruct_message<'r>(
        &self,
        raw: &'r [u8],
        src: Option<SocketAddr>,
    ) -> Result<(Header<'r>, NsReader<&'r [u8]>), MessageHandlerError> {
        let mut reader = NsReader::from_reader(raw);

        let mut header = None;
        let mut has_body = false;

        // as per https://www.w3.org/TR/soap12/#soapenvelope, the Header, Body order is fixed. We don't need to code for Body, Header
        loop {
            match reader.read_resolved_event()? {
                (Bound(Namespace(ns)), Event::Start(e)) => {
                    if ns == XML_SOAP_NAMESPACE.as_bytes() {
                        if e.name().local_name().as_ref() == b"Header" {
                            header = Some(parse_header(&mut reader)?);
                        } else if e.name().local_name().as_ref() == b"Body" {
                            has_body = true;
                            break;
                        } else {
                            // ...
                        }
                    }
                },
                (_, Event::Eof) => {
                    break;
                },
                _ => (),
            }
        }

        let Some(header) = header else {
            return Err(MessageHandlerError::MissingHeader);
        };

        // check for duplicates
        if self.is_duplicated_msg(header.message_id).await {
            event!(
                Level::DEBUG,
                "known message ({}): dropping it",
                header.message_id
            );

            // TODO improve reason
            return Err(MessageHandlerError::DuplicateMessage);
        }

        let action_method = header.action.rsplit_once('/').unwrap().1;

        if let Some(src) = src {
            event!(
                Level::INFO,
                "{}({}) - - \"{} {} UDP\" - -",
                src,
                self.network_address.interface,
                action_method,
                header.message_id
            );
        } else {
            // http logging is already done by according server
            event!(
                Level::DEBUG,
                "processing WSD {} message ({})",
                action_method,
                header.message_id
            );
        }

        if !has_body {
            return Err(MessageHandlerError::MissingBody);
        }

        event!(
            Level::DEBUG,
            "incoming message content is {}",
            String::from_utf8_lossy(raw)
        );

        Ok((header, reader))
    }

    /// Implements SOAP-over-UDP Appendix II Item 2
    async fn is_duplicated_msg(&self, message_id: Urn) -> bool {
        // reverse iter, as it is more likely that we see a message that we just saw vs one we've seen little earlier
        if self
            .handled_messages
            .read()
            .await
            .iter()
            .rev()
            .any(|&m| m == message_id)
        {
            true
        } else {
            self.handled_messages.write().await.push_back(message_id);

            false
        }
    }
}

fn parse_header<'r>(reader: &mut NsReader<&'r [u8]>) -> ParsedHeader<'r> {
    // <wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
    // <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
    // <wsa:MessageID>urn:uuid:ae0a8a7b-0138-11f0-8bff-d45ddf1e11a9</wsa:MessageID>
    // <wsa:RelatesTo>urn:uuid:ff876786-d5fd-4cc5-825b-fc494834cf19</wsa:RelatesTo>
    // <wsd:AppSequence InstanceId="1742000334" SequenceId="urn:uuid:ae0a8b77-0138-11f0-93f3-d45ddf1e11a9" MessageNumber="1" />
    let mut to = None;
    let mut action = None;
    let mut message_id = None;
    let mut relates_to = None;

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == WSA_URI.as_bytes() {
                    // header items can be in any order, as per SOAP 1.1 and 1.2
                    match e.name().local_name().as_ref() {
                        b"To" => {
                            to = Some(reader.read_text(e.to_end().name())?);
                        },
                        b"Action" => {
                            action = Some(reader.read_text(e.to_end().name())?);
                        },
                        b"MessageID" => {
                            let m_id = reader.read_text(e.to_end().name())?;

                            let m_id =
                                m_id.parse::<Urn>().map_err(HeaderError::InvalidMessageId)?;

                            message_id = Some(m_id);
                        },
                        b"RelatesTo" => {
                            let r_to = reader.read_text(e.to_end().name())?;

                            let r_to =
                                r_to.parse::<Urn>().map_err(HeaderError::InvalidRelatesTo)?;

                            relates_to = Some(r_to);
                        },
                        _ => {

                            // Not a match, continue
                        },
                    }
                }
            },
            (Bound(Namespace(ns)), Event::End(e)) => {
                if ns == XML_SOAP_NAMESPACE.as_bytes()
                    && e.name().local_name().as_ref() == b"Header"
                {
                    break;
                }
            },
            _ => (),
        }
    }

    let Some(message_id) = message_id else {
        return Err(HeaderError::MissingMessageId);
    };

    let Some(action) = action else {
        return Err(HeaderError::MissingAction);
    };

    Ok(Header {
        to,
        action,
        message_id,
        relates_to,
    })
}
