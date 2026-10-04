pub mod app_sequence;
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
use xml::ParserConfig;
use xml::common::XmlVersion;
use xml::reader::XmlEvent;

use crate::constants;
use crate::max_size_deque::MaxSizeDeque;
use crate::network_address::NetworkAddress;
use crate::network_interface::NetworkInterface;
use crate::soap::parser::app_sequence::{AppSequence, InvalidAppSequence};
use crate::soap::parser::get::Get;
use crate::soap::{self, MessageId, WSDMessage};
use crate::wsd::device::DeviceUri;
use crate::xml::{TextReadError, XmlError, XmlReader, read_text};

pub struct MessageHandler {
    network_address: NetworkAddress,
    recent_messages: Arc<RwLock<MaxSizeDeque<MessageId>>>,
}

pub struct Header {
    pub to: Option<DeviceUri>,
    pub action: Box<str>,
    pub message_id: MessageId,
    pub relates_to: Option<MessageId>,
    /// `None` when the block is absent.
    pub app_sequence: Option<Result<AppSequence, InvalidAppSequence>>,
}

#[derive(Error, Debug)]
pub enum HeaderParsingError {
    #[error("Error parsing XML: {}", .0)]
    Xml(#[from] XmlError),
    #[error("Missing Message Id")]
    MissingMessageId,
    #[error("Missing Action")]
    MissingAction,
    #[error("Missing wsd:AppSequence")]
    MissingAppSequence,
    #[error("Invalid wsd:AppSequence: {}", .0)]
    InvalidAppSequence(InvalidAppSequence),
    #[error("Duplicate wsd:AppSequence")]
    DuplicateAppSequence,
    #[error("Duplicate soap:Header")]
    DuplicateHeader,
    #[error("Unsupported XML version: {}", .0)]
    UnsupportedXmlVersion(XmlVersion),
}

impl From<xml::reader::Error> for HeaderParsingError {
    fn from(value: xml::reader::Error) -> Self {
        Self::Xml(XmlError::from(value))
    }
}

impl From<TextReadError> for HeaderParsingError {
    fn from(value: TextReadError) -> Self {
        Self::Xml(XmlError::from(value))
    }
}

#[derive(Error, Debug)]
pub enum BodyParsingError {
    #[error("Error parsing XML: {}", .0)]
    Xml(#[from] XmlError),
    #[error("Invalid element order")]
    InvalidElementOrder,
    #[error("MetadataVersion is not an unsigned 64-bit number: {}", .0)]
    InvalidMetadataVersion(Box<str>),
    #[error("Invalid UUID: {}", .0)]
    InvalidUrnUuid(uuid::Error),
    #[error("Invalid wsd:Types: {}", .0)]
    InvalidTypes(Box<str>),
}

impl From<xml::reader::Error> for BodyParsingError {
    fn from(value: xml::reader::Error) -> Self {
        Self::Xml(XmlError::from(value))
    }
}

impl From<TextReadError> for BodyParsingError {
    fn from(value: TextReadError) -> Self {
        Self::Xml(XmlError::from(value))
    }
}

type ParsedHeaderResult = Result<Header, HeaderParsingError>;

#[derive(Error, Debug)]
pub enum MessageHandlerError {
    #[error("Message already processed")]
    DuplicateMessage,
    #[error("Header parsing error: {}", .0)]
    HeaderError(#[from] HeaderParsingError),
    #[error("Body parsing error: {}", .0)]
    BodyError(#[from] BodyParsingError),
    #[error("Malformed action: {}", .0)]
    MalformedAction(Box<str>),
    #[error("Unsupported action: {}", .0)]
    UnsupportedAction(Box<str>),
}

impl MessageHandlerError {
    #[track_caller]
    pub(crate) fn log(&self, buffer: &[u8]) {
        match *self {
            MessageHandlerError::DuplicateMessage => {
                // nothing
            },
            MessageHandlerError::HeaderError(ref error) => {
                event!(
                    Level::TRACE,
                    ?error,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "Header parsing error",
                );
            },
            MessageHandlerError::BodyError(ref error) => {
                event!(
                    Level::TRACE,
                    ?error,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "Body parsing error",
                );
            },
            MessageHandlerError::MalformedAction(ref action) => {
                event!(
                    Level::TRACE,
                    %action,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "Malformed action",
                );
            },
            MessageHandlerError::UnsupportedAction(ref action) => {
                event!(
                    Level::TRACE,
                    %action,
                    wsd_message = %String::from_utf8_lossy(buffer),
                    "Unsupported action",
                );
            },
        }
    }
}

type RawMessageResult<R> = Result<(Header, bool, XmlReader<R>), MessageHandlerError>;

pub fn deconstruct_raw<R>(raw: R) -> RawMessageResult<R>
where
    R: Read,
{
    let mut reader = XmlReader::new(
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
    #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
    loop {
        // this is the only loop that should hit `XmlEvent::StartDocument` and `XmlEvent::Doctype`
        // in all other parsing functions we could theoretically mark them as `unreachable!()`
        match reader.next().map_err(HeaderParsingError::from)? {
            XmlEvent::StartDocument {
                version: version @ XmlVersion::Version11,
                ..
            } => {
                return Err(HeaderParsingError::UnsupportedXmlVersion(version).into());
            },
            XmlEvent::StartElement { name, .. }
                if name.namespace_ref() == Some(constants::XML_SOAP_NAMESPACE) =>
            {
                if name.local_name == "Header" {
                    if header.is_some() {
                        return Err(HeaderParsingError::DuplicateHeader.into());
                    }

                    header = Some(parse_header(&mut reader)?);
                } else if name.local_name == "Body" {
                    has_body = true;
                    break;
                } else {
                    // ...
                }
            },
            XmlEvent::EndDocument => {
                break;
            },
            _ => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
        }
    }

    let Some(header) = header else {
        return Err(
            HeaderParsingError::from(XmlError::MissingElement(Box::from("soap:Header"))).into(),
        );
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
        return Err(MessageHandlerError::MalformedAction(header.action));
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
        return Err(
            BodyParsingError::from(XmlError::MissingElement(Box::from("soap:Body"))).into(),
        );
    }

    Ok(header)
}

/// A Target Service MUST include `wsd:AppSequence`, see documentation/ws-discovery.pdf, 4.1 and 5.3.
fn require_app_sequence(header: &Header) -> Result<AppSequence, HeaderParsingError> {
    match header.app_sequence {
        None => Err(HeaderParsingError::MissingAppSequence),
        Some(Err(ref error)) => Err(HeaderParsingError::InvalidAppSequence(error.clone())),
        Some(Ok(ref app_sequence)) => Ok(app_sequence.clone()),
    }
}

fn parse_message_body(
    header: &Header,
    mut reader: XmlReader<&[u8]>,
) -> Result<WSDMessage, MessageHandlerError> {
    let response = match &*header.action {
        constants::WSD_GET => Ok(Get {}.into()),
        constants::WSD_HELLO => {
            let app_sequence = require_app_sequence(header)?;

            Ok(soap::parser::hello::parse_hello(&mut reader, app_sequence)?.into())
        },
        constants::WSD_BYE => {
            let app_sequence = require_app_sequence(header)?;

            Ok(soap::parser::bye::parse_bye(&mut reader, app_sequence)?.into())
        },
        constants::WSD_PROBE_MATCH => {
            require_app_sequence(header)?;

            Ok(soap::parser::probe_match::parse_probe_matches(&mut reader)?.into())
        },
        constants::WSD_RESOLVE_MATCH => {
            require_app_sequence(header)?;

            Ok(soap::parser::resolve_match::parse_resolve_matches(&mut reader)?.into())
        },
        constants::WSD_PROBE => Ok(soap::parser::probe::parse_probe(&mut reader)?.into()),
        constants::WSD_RESOLVE => Ok(soap::parser::resolve::parse_resolve(&mut reader)?.into()),
        action => Err(MessageHandlerError::UnsupportedAction(Box::from(action))),
    }?;

    Ok(response)
}

impl MessageHandler {
    pub fn new(
        network_address: NetworkAddress,
        recent_messages: Arc<RwLock<MaxSizeDeque<MessageId>>>,
    ) -> Self {
        Self {
            network_address,
            recent_messages,
        }
    }

    /// Handle a WSD message received over UDP.
    pub async fn deconstruct_message<B>(
        &self,
        raw: B,
        source: SocketAddr,
    ) -> Result<(Header, WSDMessage), MessageHandlerError>
    where
        B: AsRef<[u8]>,
    {
        self.deconstruct(raw.as_ref(), Some(source)).await
    }

    /// Handle a WSD message received over HTTP.
    pub async fn deconstruct_http_message<B>(
        &self,
        raw: B,
    ) -> Result<(Header, WSDMessage), MessageHandlerError>
    where
        B: AsRef<[u8]>,
    {
        self.deconstruct(raw.as_ref(), None).await
    }

    async fn deconstruct(
        &self,
        raw: &[u8],
        source: Option<SocketAddr>,
    ) -> Result<(Header, WSDMessage), MessageHandlerError> {
        let (header, has_body, reader) = deconstruct_raw(raw)?;

        // check for duplicates
        if self.is_duplicated_msg(&header.message_id).await {
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
            source.map(|source| (source, &*self.network_address.interface)),
            has_body,
        )?;

        let body = parse_message_body(&header, reader)?;

        Ok((header, body))
    }

    /// Implements SOAP-over-UDP Appendix II Item 2
    /// Deduplicates best-effort: read lock filters most repeats cheaply, then a write
    /// lock inserts the ID if it is still absent. The unlocked gap means a rapid burst
    /// can insert and evict the same id before our write guard runs, so some
    /// in-flight duplicates may be reprocessed, but we avoid taking a write lock for
    /// every message.
    pub async fn is_duplicated_msg(&self, message_id: &MessageId) -> bool {
        {
            let read_lock = self.recent_messages.read().await;

            if read_lock.contains(message_id) {
                return true;
            }
        }

        let mut write_lock = self.recent_messages.write().await;

        if write_lock.push_back(message_id.clone()) {
            // the queue did NOT have the message_id, so it's a new message
            false
        } else {
            // the queue did have the message id, duplicated message
            true
        }
    }
}

fn parse_header<R>(reader: &mut XmlReader<R>) -> ParsedHeaderResult
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
    // <wsd:AppSequence InstanceId="1742000334" SequenceId="urn:uuid:ae0a8b77-0138-11f0-93f3-d45ddf1e11a9" MessageNumber="1" />
    let mut app_sequence = None;

    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement { name, .. }
                if reader.depth() == entry_depth + 1
                    && name.namespace_ref() == Some(constants::WSA_URI) =>
            {
                // header items can be in any order, as per SOAP 1.1 and 1.2
                match &*name.local_name {
                    "To" => {
                        to = read_text(reader)?.map(|to| DeviceUri::new(to.into_boxed_str()));
                    },
                    "Action" => {
                        action = read_text(reader)?.map(String::into_boxed_str);
                    },
                    "MessageID" => {
                        message_id =
                            read_text(reader)?.map(|m_id| MessageId::new(m_id.into_boxed_str()));
                    },
                    "RelatesTo" => {
                        relates_to =
                            read_text(reader)?.map(|r_to| MessageId::new(r_to.into_boxed_str()));
                    },
                    _ => {
                        // Not a match, continue
                    },
                }
            },
            XmlEvent::StartElement {
                name, attributes, ..
            } if reader.depth() == entry_depth + 1
                && name.namespace_ref() == Some(constants::XML_WSD_NAMESPACE)
                && name.local_name == "AppSequence" =>
            {
                if app_sequence.is_some() {
                    return Err(HeaderParsingError::DuplicateAppSequence);
                }

                app_sequence = Some(AppSequence::from_attributes(&attributes));
            },
            XmlEvent::EndElement { .. } if reader.depth() < entry_depth => {
                break;
            },
            element @ XmlEvent::EndDocument => {
                return Err(XmlError::UnexpectedEvent(Box::new(element)).into());
            },
            _ => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
        }
    }

    let Some(message_id) = message_id else {
        return Err(HeaderParsingError::MissingMessageId);
    };

    let Some(action) = action else {
        return Err(HeaderParsingError::MissingAction);
    };

    Ok(Header {
        to,
        action,
        message_id,
        relates_to,
        app_sequence,
    })
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use ipnet::IpNet;
    use libc::RT_SCOPE_SITE;
    use pretty_assertions::{assert_eq, assert_matches};
    use tokio::sync::RwLock;
    use tokio::time::{Duration, timeout};
    use uuid::Uuid;
    use xml::common::XmlVersion;

    use crate::constants;
    use crate::max_size_deque::MaxSizeDeque;
    use crate::network_address::NetworkAddress;
    use crate::network_interface::NetworkInterface;
    use crate::soap::MessageId;
    use crate::soap::parser::app_sequence::{AppSequence, InvalidAppSequence};
    use crate::soap::parser::{
        BodyParsingError, HeaderParsingError, MessageHandler, MessageHandlerError, deconstruct_raw,
    };
    use crate::xml::XmlError;

    fn handler_for_tests(history: usize) -> MessageHandler {
        MessageHandler::new(
            NetworkAddress::new(
                IpNet::new(Ipv4Addr::new(127, 1, 2, 3).into(), 16).unwrap(),
                Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
            ),
            Arc::new(RwLock::new(MaxSizeDeque::new(history))),
        )
    }

    #[tokio::test(flavor = "current_thread")]
    async fn is_duplicated_msg_drops_read_lock_before_waiting_for_write_lock() {
        let handler = handler_for_tests(8);
        let message_id = MessageId::from(Uuid::now_v7().urn());

        let first_hit = timeout(
            Duration::from_millis(100),
            handler.is_duplicated_msg(&message_id),
        )
        .await
        .expect("read guard must be released before awaiting a write guard");

        assert!(
            !first_hit,
            "first observation of a message id should be reported as new"
        );

        let second_hit = handler.is_duplicated_msg(&message_id).await;

        assert!(
            second_hit,
            "the message id must be seen as duplicate after it is stored"
        );
    }

    #[test]
    fn rejects_second_soap_header() {
        let header = format!(
            "<soap:Header><wsa:Action>{}</wsa:Action><wsa:MessageID>{}</wsa:MessageID></soap:Header>",
            constants::WSD_PROBE,
            Uuid::now_v7().urn()
        );
        let message = format!(
            r#"<soap:Envelope xmlns:soap="{}" xmlns:wsa="{}">{}{}<soap:Body /></soap:Envelope>"#,
            constants::XML_SOAP_NAMESPACE,
            constants::WSA_URI,
            header,
            header
        );

        let result = deconstruct_raw(message.as_bytes());

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::DuplicateHeader
            ))
        );
    }

    #[test]
    fn accepts_message_declared_as_xml_1_0() {
        let probe = format!(
            r#"<?xml version="1.0" encoding="utf-8"?>{}"#,
            message(constants::WSD_PROBE, "", "<wsd:Probe />")
        );

        assert_matches!(deconstruct_raw(probe.as_bytes()).map(|_| ()), Ok(()));
    }

    #[test]
    fn rejects_message_declared_as_xml_1_1() {
        let probe = format!(
            r#"<?xml version="1.1" encoding="utf-8"?>{}"#,
            message(constants::WSD_PROBE, "", "<wsd:Probe />")
        );

        assert_matches!(
            deconstruct_raw(probe.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::UnsupportedXmlVersion(XmlVersion::Version11)
            ))
        );
    }

    fn message(action: &str, app_sequence: &str, body: &str) -> String {
        format!(
            r#"<soap:Envelope xmlns:soap="{}" xmlns:wsa="{}" xmlns:wsd="{}"><soap:Header><wsa:To>{}</wsa:To><wsa:Action>{}</wsa:Action><wsa:MessageID>{}</wsa:MessageID>{}</soap:Header><soap:Body>{}</soap:Body></soap:Envelope>"#,
            constants::XML_SOAP_NAMESPACE,
            constants::WSA_URI,
            constants::XML_WSD_NAMESPACE,
            constants::WSA_DISCOVERY,
            action,
            Uuid::now_v7().urn(),
            app_sequence,
            body
        )
    }

    const HELLO_BODY: &str = "<wsd:Hello><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:MetadataVersion>1</wsd:MetadataVersion></wsd:Hello>";

    const BYE_BODY: &str = "<wsd:Bye><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference></wsd:Bye>";

    const FULL_APP_SEQUENCE: &str = r#"<wsd:AppSequence InstanceId="3" SequenceId="urn:uuid:ae0a8b77-0138-11f0-93f3-d45ddf1e11a9" MessageNumber="7" />"#;

    fn full_app_sequence() -> AppSequence {
        AppSequence::new(3, Some("urn:uuid:ae0a8b77-0138-11f0-93f3-d45ddf1e11a9"), 7)
    }

    const SOURCE: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 1, 2, 4), 3702));

    #[test]
    fn parses_app_sequence() {
        let hello = message(constants::WSD_HELLO, FULL_APP_SEQUENCE, "");

        let (header, _, _) = deconstruct_raw(hello.as_bytes()).unwrap();

        assert_eq!(header.app_sequence, Some(Ok(full_app_sequence())));
    }

    #[test]
    fn reads_malformed_app_sequence_as_error() {
        let hello = message(
            constants::WSD_HELLO,
            r#"<wsd:AppSequence InstanceId="x" MessageNumber="7" />"#,
            "",
        );

        let (header, _, _) = deconstruct_raw(hello.as_bytes()).unwrap();

        assert_eq!(
            header.app_sequence,
            Some(Err(InvalidAppSequence::InvalidInstanceId(Box::from("x"))))
        );
    }

    #[test]
    fn reads_missing_app_sequence_as_none() {
        let hello = message(constants::WSD_HELLO, "", "");

        let (header, _, _) = deconstruct_raw(hello.as_bytes()).unwrap();

        assert_eq!(header.app_sequence, None);
    }

    #[test]
    fn rejects_duplicate_app_sequence() {
        let hello = message(
            constants::WSD_HELLO,
            r#"<wsd:AppSequence InstanceId="1" MessageNumber="2" /><wsd:AppSequence InstanceId="1" MessageNumber="2" />"#,
            "",
        );

        assert_matches!(
            deconstruct_raw(hello.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::DuplicateAppSequence
            ))
        );
    }

    #[tokio::test]
    async fn accepts_hello_with_app_sequence() {
        let hello = message(constants::WSD_HELLO, FULL_APP_SEQUENCE, HELLO_BODY);

        let (_, message) = handler_for_tests(8)
            .deconstruct_message(&hello, SOURCE)
            .await
            .unwrap();

        assert_eq!(
            message.into_hello().map(|hello| hello.app_sequence),
            Some(full_app_sequence())
        );
    }

    #[tokio::test]
    async fn accepts_bye_with_app_sequence() {
        let bye = message(constants::WSD_BYE, FULL_APP_SEQUENCE, BYE_BODY);

        let (_, message) = handler_for_tests(8)
            .deconstruct_message(&bye, SOURCE)
            .await
            .unwrap();

        assert_eq!(
            message.into_bye().map(|bye| bye.app_sequence),
            Some(full_app_sequence())
        );
    }

    #[tokio::test]
    async fn rejects_hello_without_app_sequence() {
        let hello = message(constants::WSD_HELLO, "", HELLO_BODY);

        let result = handler_for_tests(8)
            .deconstruct_message(&hello, SOURCE)
            .await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::MissingAppSequence
            ))
        );
    }

    #[tokio::test]
    async fn rejects_hello_with_malformed_app_sequence() {
        let hello = message(
            constants::WSD_HELLO,
            r#"<wsd:AppSequence InstanceId="x" MessageNumber="2" />"#,
            HELLO_BODY,
        );

        let result = handler_for_tests(8)
            .deconstruct_message(&hello, SOURCE)
            .await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::InvalidAppSequence(InvalidAppSequence::InvalidInstanceId(_))
            ))
        );
    }

    #[tokio::test]
    async fn accepts_probe_without_app_sequence() {
        let probe = message(constants::WSD_PROBE, "", "<wsd:Probe />");

        let result = handler_for_tests(8)
            .deconstruct_message(&probe, SOURCE)
            .await;

        assert_matches!(result.map(|_| ()), Ok(()));
    }

    const APP_SEQUENCE: &str = r#"<wsd:AppSequence InstanceId="1" MessageNumber="2" />"#;

    #[tokio::test]
    async fn rejects_hello_without_metadata_version() {
        let hello = message(
            constants::WSD_HELLO,
            APP_SEQUENCE,
            "<wsd:Hello><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference></wsd:Hello>",
        );

        let result = handler_for_tests(8)
            .deconstruct_message(&hello, SOURCE)
            .await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::BodyError(BodyParsingError::Xml(
                XmlError::MissingElement(_)
            )))
        );
    }

    #[tokio::test]
    async fn accepts_bye_without_metadata_version() {
        let bye = message(
            constants::WSD_BYE,
            APP_SEQUENCE,
            "<wsd:Bye><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference></wsd:Bye>",
        );

        let result = handler_for_tests(8).deconstruct_message(&bye, SOURCE).await;

        assert_matches!(result.map(|_| ()), Ok(()));
    }

    #[tokio::test]
    async fn rejects_hello_with_malformed_metadata_version() {
        let hello = message(
            constants::WSD_HELLO,
            APP_SEQUENCE,
            "<wsd:Hello><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:MetadataVersion>x</wsd:MetadataVersion></wsd:Hello>",
        );

        let result = handler_for_tests(8)
            .deconstruct_message(&hello, SOURCE)
            .await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::BodyError(BodyParsingError::InvalidMetadataVersion(ref text))) if &**text == "x"
        );
    }

    #[tokio::test]
    async fn accepts_bye_with_malformed_metadata_version() {
        let bye = message(
            constants::WSD_BYE,
            APP_SEQUENCE,
            "<wsd:Bye><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:MetadataVersion>x</wsd:MetadataVersion></wsd:Bye>",
        );

        let result = handler_for_tests(8).deconstruct_message(&bye, SOURCE).await;

        assert_matches!(result.map(|_| ()), Ok(()));
    }

    #[tokio::test]
    async fn rejects_hello_with_undeclared_type_prefix() {
        let hello = message(
            constants::WSD_HELLO,
            APP_SEQUENCE,
            "<wsd:Hello><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:Types>nope:Device</wsd:Types><wsd:MetadataVersion>1</wsd:MetadataVersion></wsd:Hello>",
        );

        let result = handler_for_tests(8)
            .deconstruct_message(&hello, SOURCE)
            .await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::BodyError(BodyParsingError::InvalidTypes(ref raw_types))) if &**raw_types == "nope:Device"
        );
    }

    #[tokio::test]
    async fn accepts_bye_with_undeclared_type_prefix() {
        let bye = message(
            constants::WSD_BYE,
            APP_SEQUENCE,
            "<wsd:Bye><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:Types>nope:Device</wsd:Types></wsd:Bye>",
        );

        let result = handler_for_tests(8).deconstruct_message(&bye, SOURCE).await;

        assert_matches!(result.map(|_| ()), Ok(()));
    }
}
