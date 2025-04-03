pub mod generic;
pub mod probe;
pub mod resolve;

use std::borrow::Cow;
use std::sync::Arc;

use quick_xml::events::Event;
use quick_xml::name::Namespace;
use quick_xml::name::ResolveResult::Bound;
use quick_xml::reader::NsReader;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{Level, event};

use crate::constants::{WSA_URI, XML_SOAP_NAMESPACE};
use crate::max_size_deque::MaxSizeDeque;

pub struct MessageHandler {
    handled_messages: Arc<RwLock<MaxSizeDeque<String>>>,
}

struct Header<'r> {
    message_id: Option<Cow<'r, str>>,
    action: Option<Cow<'r, str>>,
}

type ParsedHeader<'r> = Result<Header<'r>, quick_xml::errors::Error>;

#[derive(Error, Debug)]
pub enum MessageHandlerError {
    #[error("Missing Body")]
    MissingBody,
    #[error("Missing Message Id")]
    MissingMessageId,
    #[error("Missing Action")]
    MissingAction,
    #[error("Message already processed")]
    DuplicateMessage,
    #[error("Error parsing XML")]
    XmlError(#[from] quick_xml::errors::Error),
}

impl MessageHandler {
    pub fn new(handled_messages: Arc<RwLock<MaxSizeDeque<String>>>) -> Self {
        Self { handled_messages }
    }

    /// Handle a WSD message
    pub async fn deconstruct_message<'r>(
        &self,
        raw: &'r [u8],
        // src: Option<SocketAddr>,
    ) -> Result<(Cow<'r, str>, Cow<'r, str>, NsReader<&'r [u8]>), MessageHandlerError> {
        let mut reader = NsReader::from_reader(raw);

        let mut message_id = None;
        let mut action = None;
        let mut has_body = false;

        // as per https://www.w3.org/TR/soap12/#soapenvelope, the Header, Body order is fixed. We don't need to code for Body, Header
        loop {
            match reader.read_resolved_event()? {
                (Bound(Namespace(ns)), Event::Start(e)) => {
                    if ns == XML_SOAP_NAMESPACE.as_bytes() {
                        if e.name().local_name().as_ref() == b"Header" {
                            let header = parse_header(&mut reader)?;

                            message_id = header.message_id;
                            action = header.action;
                        } else if e.name().local_name().as_ref() == b"Body" {
                            has_body = true;
                            break;
                        }
                    }
                },
                (_, Event::Eof) => {
                    break;
                },
                _ => (),
            }
        }

        let Some(message_id) = message_id else {
            return Err(MessageHandlerError::MissingMessageId);
        };

        let Some(action) = action else {
            return Err(MessageHandlerError::MissingAction);
        };

        // check for duplicates
        if self.is_duplicated_msg(message_id.as_ref()).await {
            event!(Level::DEBUG, "known message ({}): dropping it", message_id);

            // TODO improve reason
            return Err(MessageHandlerError::DuplicateMessage);
        }

        let action_method = action.rsplit_once('/').unwrap().1;

        // if let Some(src) = src {
        event!(
            Level::INFO,
            "GONE GONE - - \"{} {} UDP\" - -",
            // "{}({}) - - \"{} {} UDP\" - -",
            // src.transport_address,
            // src.network_address.interface,
            action_method,
            message_id
        );
        // } else {
        //     // http logging is already done by according server
        //     event!(
        //         Level::DEBUG,
        //         "processing WSD {} message ({})",
        //         action_method,
        //         message_id
        //     );
        // }

        if !has_body {
            return Err(MessageHandlerError::MissingBody);
        }

        event!(
            Level::DEBUG,
            "incoming message content is {}",
            String::from_utf8_lossy(raw)
        );

        Ok((message_id, action, reader))
    }

    /// Implements SOAP-over-UDP Appendix II Item 2
    async fn is_duplicated_msg(&self, message_id: &str) -> bool {
        // reverse iter, as it is more likely that we see a message that we just saw vs one we've seen little earlier
        if self
            .handled_messages
            .read()
            .await
            .iter()
            .rev()
            .any(|m| m == message_id)
        {
            true
        } else {
            self.handled_messages
                .write()
                .await
                .push_back(message_id.to_owned());

            false
        }
    }
}

fn parse_header<'r>(reader: &mut NsReader<&'r [u8]>) -> ParsedHeader<'r> {
    let mut message_id = None;
    let mut action = None;

    loop {
        match reader.read_resolved_event()? {
            (Bound(Namespace(ns)), Event::Start(e)) => {
                if ns == WSA_URI.as_bytes() {
                    // header items can be in any order, as per SOAP 1.1 and 1.2
                    if e.name().local_name().as_ref() == b"MessageID" {
                        message_id = Some(reader.read_text(e.to_end().name())?);
                    } else if e.name().local_name().as_ref() == b"Action" {
                        action = Some(reader.read_text(e.to_end().name())?);
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

    Ok(Header { message_id, action })
}
