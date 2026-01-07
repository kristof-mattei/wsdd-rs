pub mod bye;
pub mod generic;
pub mod get;
pub mod hello;
pub mod probe;
pub mod probe_match;
pub mod resolve;
pub mod resolve_match;
pub mod xaddrs;

use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{Level, event};
use uuid::fmt::Urn;
use xml::ParserConfig;
use xml::reader::XmlEvent;

use crate::constants;
use crate::max_size_deque::MaxSizeDeque;
use crate::network_address::NetworkAddress;
use crate::network_interface::NetworkInterface;
use crate::soap::parser::get::Get;
use crate::soap::{self, WSDMessage};
use crate::wsd::device::DeviceUri;
use crate::xml::{GenericParsingError, TextReadError, Wrapper, read_text};

pub struct MessageHandler {
    handled_messages: Arc<RwLock<MaxSizeDeque<Urn>>>,
    network_address: NetworkAddress,
}

pub struct Header {
    pub to: Option<DeviceUri>,
    pub action: Box<str>,
    pub message_id: Urn,
    pub relates_to: Option<Urn>,
}

type ParsedHeaderResult = Result<Header, HeaderError>;

#[derive(Error, Debug)]
pub enum MessageHandlerError {
    #[error("Message already processed")]
    DuplicateMessage,
    #[error("Header Error")]
    HeaderError(#[from] HeaderError),
    #[error("Generic Parsing Error")]
    GenericParsingError(#[from] GenericParsingError),
    #[error("Invalid action")]
    InvalidAction(Box<str>),
    #[error("Error parsing XML")]
    XmlError(#[from] xml::reader::Error),
}
impl MessageHandlerError {
    #[track_caller]
    pub(crate) fn log(&self, buffer: &[u8]) {
        match self {
            &MessageHandlerError::DuplicateMessage => {
                // nothing
            },
            &MessageHandlerError::GenericParsingError(GenericParsingError::InvalidElementOrder) => {
                event!(
                    Level::TRACE,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "XML Message has elements in invalid order"
                );
            },
            &MessageHandlerError::GenericParsingError(GenericParsingError::MissingElement(
                ref element,
            )) => {
                event!(
                    Level::TRACE,
                    ?element,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "XML Message did not have required elements",
                );
            },
            &MessageHandlerError::GenericParsingError(GenericParsingError::TextReadError(
                ref error,
            )) => {
                event!(
                    Level::TRACE,
                    %error,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "XML Message text read error",
                );
            },
            &MessageHandlerError::InvalidAction(ref malformed_action) => {
                event!(
                    Level::TRACE,
                    malformed_action,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "XML Message Action was malformed",
                );
            },
            &MessageHandlerError::HeaderError(
                HeaderError::InvalidMessageId(ref uuid_error)
                | HeaderError::InvalidRelatesTo(ref uuid_error),
            )
            | &MessageHandlerError::GenericParsingError(GenericParsingError::InvalidUrnUuid(
                ref uuid_error,
            )) => {
                event!(
                    Level::TRACE,
                    ?uuid_error,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "XML Message Header was malformed",
                );
            },
            &MessageHandlerError::HeaderError(
                ref error @ (HeaderError::MissingAction | HeaderError::MissingMessageId),
            ) => {
                event!(
                    Level::TRACE,
                    %error,
                    wsd_message = %String::from_utf8_lossy(buffer),
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
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "Invalid contents in text element",
                );
            },
            &MessageHandlerError::HeaderError(HeaderError::TextReadError(
                TextReadError::XmlError(ref error),
            ))
            | &MessageHandlerError::HeaderError(HeaderError::XmlError(ref error))
            | &MessageHandlerError::XmlError(ref error)
            | &MessageHandlerError::GenericParsingError(GenericParsingError::XmlError(ref error)) =>
            {
                event!(
                    Level::ERROR,
                    ?error,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "Error while decoding XML",
                );
            },
            &MessageHandlerError::GenericParsingError(
                GenericParsingError::InvalidDocumentPosition,
            ) => {
                event!(
                    Level::ERROR,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "XML parsing function called at incorrect document position"
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

type RawMessageResult<R> = Result<(Header, bool, Wrapper<R>), MessageHandlerError>;

pub fn deconstruct_raw<R>(raw: R) -> RawMessageResult<R>
where
    R: Read,
{
    let mut reader = Wrapper::new(
        ParserConfig::new()
            .cdata_to_characters(true)
            .ignore_comments(true)
            .trim_whitespace(true)
            .whitespace_to_characters(true)
            .create_reader(raw),
    );

    let mut header = None;
    let mut has_body = false;

    // as per https://www.w3.org/TR/soap12/#soapenvelope, the Header, Body order is fixed. We don't need to code for Body, Header
    loop {
        // this is the only loop that should hit `XmlEvent::StartDocument` and `XmlEvent::Doctype`
        // in all other parsing functions we could theoretically mark them as `unreachable!()`
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                if name.namespace_ref() == Some(constants::XML_SOAP_NAMESPACE) {
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
            XmlEvent::CData(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::EndElement { .. }
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::StartDocument { .. }
            | XmlEvent::Whitespace(_) => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
        }
    }

    let Some(header) = header else {
        return Err(GenericParsingError::MissingElement(Box::from("soap:Header")).into());
    };

    Ok((header, has_body, reader))
}

fn validate_action_body(
    raw: &[u8],
    header: Header,
    source_info: Option<(SocketAddr, &NetworkInterface)>,
    has_body: bool,
) -> Result<Header, MessageHandlerError> {
    event!(
        Level::DEBUG,
        xml = %String::from_utf8_lossy(raw).trim(),
        "incoming message content",
    );

    let Some((_, action_method)) = header.action.rsplit_once('/') else {
        return Err(MessageHandlerError::InvalidAction(header.action));
    };

    if let Some((src, network_interface)) = source_info {
        event!(
            Level::INFO,
            "{}({}) - - \"{} {} UDP\" - -",
            src,
            network_interface,
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
        return Err(GenericParsingError::MissingElement(Box::from("soap:Body")).into());
    }

    Ok(header)
}

fn parse_message_body(
    header: &Header,
    mut reader: Wrapper<&[u8]>,
) -> Result<WSDMessage, MessageHandlerError> {
    let response = match &*header.action {
        constants::WSD_GET => Ok(Get {}.into()),
        constants::WSD_HELLO => Ok(soap::parser::hello::parse_hello(&mut reader)?.into()),
        constants::WSD_BYE => Ok(soap::parser::bye::parse_bye(&mut reader)?.into()),
        constants::WSD_PROBE_MATCH => {
            Ok(soap::parser::probe_match::parse_probe_match(&mut reader)?.into())
        },
        constants::WSD_RESOLVE_MATCH => {
            Ok(soap::parser::resolve_match::parse_resolve_match(&mut reader)?.into())
        },
        constants::WSD_PROBE => Ok(soap::parser::probe::parse_probe(&mut reader)?.into()),
        constants::WSD_RESOLVE => Ok(soap::parser::resolve::parse_resolve(&mut reader)?.into()),
        action => {
            event!(
                Level::DEBUG,
                ?action,
                ?header.message_id,
                "Unhandled action",
            );

            Err(MessageHandlerError::InvalidAction(Box::from(action)))
        },
    }?;

    Ok(response)
}

/// Handle a WSD message
pub fn deconstruct_http_message(raw: &[u8]) -> Result<(Header, WSDMessage), MessageHandlerError> {
    let (header, has_body, reader) = deconstruct_raw(raw)?;

    let header = validate_action_body(raw, header, None, has_body)?;

    let body = parse_message_body(&header, reader)?;

    Ok((header, body))
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
    pub async fn deconstruct_message(
        &self,
        raw: &[u8],
        source: SocketAddr,
    ) -> Result<(Header, WSDMessage), MessageHandlerError> {
        let (header, has_body, reader) = deconstruct_raw(raw)?;

        // check for duplicates
        if self.is_duplicated_msg(header.message_id).await {
            event!(
                Level::DEBUG,
                message_id = %header.message_id,
                "known message: dropping it",
            );

            return Err(MessageHandlerError::DuplicateMessage);
        }

        let header = validate_action_body(
            raw,
            header,
            Some((source, &*self.network_address.interface)),
            has_body,
        )?;

        let body = parse_message_body(&header, reader)?;

        Ok((header, body))
    }

    /// Implements SOAP-over-UDP Appendix II Item 2
    /// Deduplicates best-effort: read lock filters most repeats cheaply, then a write
    /// lock inserts the ID if it is still absent. The unlocked gap means a rapid burst
    /// can insert and evict the same `Urn` before our write guard runs, so some
    /// in-flight duplicates may be reprocessed, but we avoid taking a write lock for
    /// every message.
    pub async fn is_duplicated_msg(&self, message_id: Urn) -> bool {
        {
            let read_lock = self.handled_messages.read().await;

            if read_lock.contains(&message_id) {
                return true;
            }
        }

        let mut write_lock = self.handled_messages.write().await;

        if write_lock.push_back(message_id) {
            // the queue did NOT have the message_id, so it's a new message
            false
        } else {
            // the queue did have the message id, duplicated message
            true
        }
    }
}

fn parse_header<R>(reader: &mut Wrapper<R>) -> ParsedHeaderResult
where
    R: Read,
{
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

    let mut depth = 0_usize;

    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                depth += 1;

                if depth == 1 && name.namespace_ref() == Some(constants::WSA_URI) {
                    // header items can be in any order, as per SOAP 1.1 and 1.2
                    match &*name.local_name {
                        "To" => {
                            to = read_text(reader)?.map(|to| DeviceUri::new(to.into_boxed_str()));

                            depth -= 1;
                        },
                        "Action" => {
                            action = read_text(reader)?.map(String::into_boxed_str);

                            depth -= 1;
                        },
                        "MessageID" => {
                            let m_id = read_text(reader)?
                                .map(|m_id| {
                                    m_id.parse::<Urn>().map_err(HeaderError::InvalidMessageId)
                                })
                                .transpose()?;

                            message_id = m_id;

                            depth -= 1;
                        },
                        "RelatesTo" => {
                            let r_to = read_text(reader)?
                                .map(|r_to| {
                                    r_to.parse::<Urn>().map_err(HeaderError::InvalidRelatesTo)
                                })
                                .transpose()?;

                            relates_to = r_to;

                            depth -= 1;
                        },
                        _ => {
                            // Not a match, continue
                        },
                    }
                }
            },
            XmlEvent::EndElement { name, .. } => {
                if depth == 0
                    && name.namespace_ref() == Some(constants::XML_SOAP_NAMESPACE)
                    && name.local_name == "Header"
                {
                    break;
                }

                depth -= 1;
            },
            XmlEvent::CData(_)
            | XmlEvent::Characters(_)
            | XmlEvent::Comment(_)
            | XmlEvent::Doctype { .. }
            | XmlEvent::EndDocument
            | XmlEvent::ProcessingInstruction { .. }
            | XmlEvent::StartDocument { .. }
            | XmlEvent::Whitespace(_) => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use ipnet::IpNet;
    use libc::RT_SCOPE_SITE;
    use tokio::sync::RwLock;
    use tokio::time::{Duration, timeout};
    use uuid::Uuid;
    use uuid::fmt::Urn;

    use crate::max_size_deque::MaxSizeDeque;
    use crate::network_address::NetworkAddress;
    use crate::network_interface::NetworkInterface;
    use crate::soap::parser::MessageHandler;

    fn handler_for_tests(history: usize) -> MessageHandler {
        MessageHandler::new(
            Arc::new(RwLock::new(MaxSizeDeque::new(history))),
            NetworkAddress::new(
                IpNet::new(Ipv4Addr::new(127, 1, 2, 3).into(), 16).unwrap(),
                Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
            ),
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn is_duplicated_msg_drops_read_lock_before_waiting_for_write_lock() {
        let handler = handler_for_tests(8);
        let message_id = Urn::from_uuid(Uuid::now_v7());

        let first_hit = timeout(
            Duration::from_millis(100),
            handler.is_duplicated_msg(message_id),
        )
        .await
        .expect("read guard must be released before awaiting a write guard");

        assert!(
            !first_hit,
            "first observation of a message id should be reported as new"
        );

        let second_hit = handler.is_duplicated_msg(message_id).await;

        assert!(
            second_hit,
            "the message id must be seen as duplicate after it is stored"
        );
    }
}
