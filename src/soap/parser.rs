pub mod generic;
pub mod probe;
pub mod resolve;

use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{Level, event};
use uuid::fmt::Urn;
use xml::reader::XmlEvent;
use xml::{EventReader, ParserConfig};

use crate::constants::{WSA_URI, XML_SOAP_NAMESPACE};
use crate::max_size_deque::MaxSizeDeque;
use crate::network_address::NetworkAddress;
use crate::xml::{TextReadError, read_text};

pub struct MessageHandler {
    handled_messages: Arc<RwLock<MaxSizeDeque<Urn>>>,
    network_address: NetworkAddress,
}

pub struct Header {
    #[expect(unused, reason = "WIP")]
    pub to: Option<Box<str>>,
    pub action: Box<str>,
    pub message_id: Urn,
    pub relates_to: Option<Urn>,
}

type ParsedHeaderResult = Result<Header, HeaderError>;

#[derive(Error, Debug)]
pub enum MessageHandlerError {
    #[error("Missing Header")]
    MissingHeader,
    #[error("Missing Body")]
    MissingBody,
    #[error("Message already processed")]
    DuplicateMessage,
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
    #[error("Header Error")]
    HeaderError(#[from] HeaderError),
    #[error("Text Read Error")]
    TextReadError(#[from] TextReadError),
}
impl MessageHandlerError {
    #[track_caller]
    pub(crate) fn log(&self, buffer: &[u8]) {
        match self {
            &MessageHandlerError::DuplicateMessage => {
                // nothing
            },
            missing @ &(MessageHandlerError::MissingHeader | MessageHandlerError::MissingBody) => {
                event!(
                    Level::TRACE,
                    ?missing,
                    message = &*String::from_utf8_lossy(buffer),
                    "XML Message did not have required elements",
                );
            },
            &MessageHandlerError::TextReadError(ref error) => {
                event!(
                    Level::TRACE,
                    %error,
                    message = &*String::from_utf8_lossy(buffer),
                    "XML Message text read error",
                );
            },
            &MessageHandlerError::HeaderError(
                HeaderError::InvalidMessageId(ref uuid_error)
                | HeaderError::InvalidRelatesTo(ref uuid_error),
            ) => {
                event!(
                    Level::TRACE,
                    ?uuid_error,
                    message = &*String::from_utf8_lossy(buffer),
                    "XML Message Header was malformed",
                );
            },
            &MessageHandlerError::HeaderError(
                ref error @ (HeaderError::MissingAction | HeaderError::MissingMessageId),
            ) => {
                event!(
                    Level::TRACE,
                    %error,
                    message = &*String::from_utf8_lossy(buffer),
                    "XML Message Header is missing pieces",
                );
            },
            &MessageHandlerError::HeaderError(HeaderError::TextReadError(
                ref error @ TextReadError::NonTextContents(ref content),
            )) => {
                event!(
                    Level::ERROR,
                    ?error,
                    ?content,
                    message = &*String::from_utf8_lossy(buffer),
                    "Invalid contents in text element",
                );
            },
            &MessageHandlerError::HeaderError(HeaderError::TextReadError(
                TextReadError::MissingEndElement(ref end_element),
            )) => {
                event!(
                    Level::ERROR,
                    ?end_element,
                    message = &*String::from_utf8_lossy(buffer),
                    "Missing end element",
                );
            },
            &MessageHandlerError::HeaderError(HeaderError::TextReadError(
                TextReadError::InvalidDepth(depth),
            )) => {
                event!(
                    Level::ERROR,
                    ?depth,
                    message = &*String::from_utf8_lossy(buffer),
                    "Invalid opening/closing element depth",
                );
            },
            &MessageHandlerError::HeaderError(HeaderError::TextReadError(
                TextReadError::XmlError(ref error),
            ))
            | &MessageHandlerError::HeaderError(HeaderError::XmlError(ref error))
            | &MessageHandlerError::XmlError(ref error) => {
                event!(
                    Level::ERROR,
                    ?error,
                    message = &*String::from_utf8_lossy(buffer),
                    "Error while decoding XML",
                );
            },
        }
    }
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
    #[error("Error reading text")]
    TextReadError(#[from] TextReadError),
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
}

type RawMessageResult<'r> =
    Result<(Header, bool, EventReader<BufReader<&'r [u8]>>), MessageHandlerError>;

pub fn deconstruct_raw(raw: &[u8]) -> RawMessageResult<'_> {
    let mut reader = ParserConfig::new()
        .ignore_comments(true)
        .create_reader(BufReader::new(raw));

    let mut header = None;
    let mut has_body = false;

    // as per https://www.w3.org/TR/soap12/#soapenvelope, the Header, Body order is fixed. We don't need to code for Body, Header
    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if name.namespace_ref() == Some(XML_SOAP_NAMESPACE) {
                    if name.local_name == "Header" {
                        header = Some(parse_header(&mut reader)?);
                    } else if name.local_name == "Body" {
                        has_body = true;
                        break;
                    } else {
                        // ...
                    }
                }
            },
            XmlEvent::EndDocument => {
                break;
            },
            XmlEvent::StartDocument { .. }
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::EndElement { .. }
            | XmlEvent::CData(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Whitespace(_)
            | XmlEvent::Doctype { .. } => (),
        }
    }

    let Some(header) = header else {
        return Err(MessageHandlerError::MissingHeader);
    };

    Ok((header, has_body, reader))
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
    ) -> Result<(Header, EventReader<BufReader<&'r [u8]>>), MessageHandlerError> {
        let (header, has_body, reader) = deconstruct_raw(raw)?;

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

fn parse_header(reader: &mut EventReader<BufReader<&[u8]>>) -> ParsedHeaderResult {
    // <wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
    let mut to = None;
    // <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
    let mut action = None;
    // <wsa:MessageID>urn:uuid:ae0a8a7b-0138-11f0-8bff-d45ddf1e11a9</wsa:MessageID>
    let mut message_id = None;
    // <wsa:RelatesTo>urn:uuid:ff876786-d5fd-4cc5-825b-fc494834cf19</wsa:RelatesTo>
    let mut relates_to = None;
    // TODO?
    // <wsd:AppSequence InstanceId="1742000334" SequenceId="urn:uuid:ae0a8b77-0138-11f0-93f3-d45ddf1e11a9" MessageNumber="1" />

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if name.namespace_ref() == Some(WSA_URI) {
                    // header items can be in any order, as per SOAP 1.1 and 1.2
                    match &*name.local_name {
                        "To" => {
                            to = read_text(reader, name.borrow())?.map(String::into_boxed_str);
                        },
                        "Action" => {
                            action = read_text(reader, name.borrow())?.map(String::into_boxed_str);
                        },
                        "MessageID" => {
                            let m_id = read_text(reader, name.borrow())?
                                .map(|m_id| {
                                    m_id.parse::<Urn>().map_err(HeaderError::InvalidMessageId)
                                })
                                .transpose()?;

                            message_id = m_id;
                        },
                        "RelatesTo" => {
                            let r_to = read_text(reader, name.borrow())?
                                .map(|r_to| {
                                    r_to.parse::<Urn>().map_err(HeaderError::InvalidRelatesTo)
                                })
                                .transpose()?;

                            relates_to = r_to;
                        },
                        _ => {
                            // Not a match, continue
                        },
                    }
                }
            },
            XmlEvent::EndElement { name, .. } => {
                if name.namespace_ref() == Some(XML_SOAP_NAMESPACE) && name.local_name == "Header" {
                    break;
                }
            },
            XmlEvent::StartDocument { .. }
            | XmlEvent::EndDocument
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::CData(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Whitespace(_)
            | XmlEvent::Doctype { .. } => (),
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
