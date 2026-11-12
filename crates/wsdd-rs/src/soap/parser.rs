pub(crate) mod app_sequence;
pub(crate) mod bye;
pub(crate) mod generic;
pub(crate) mod get;
pub(crate) mod hello;
pub(crate) mod probe;
pub(crate) mod probe_match;
pub(crate) mod resolve;
pub(crate) mod resolve_match;
pub(crate) mod xaddrs;

use std::io::Read;
use std::net::SocketAddr;
use std::sync::Arc;

use thiserror::Error;
use tokio::sync::RwLock;
use tracing::{Level, event};
use xml::ParserConfig;
use xml::attribute::OwnedAttribute;
use xml::common::{XmlVersion, is_whitespace_char};
use xml::namespace::Namespace;
use xml::reader::XmlEvent;

use crate::constants;
use crate::max_size_deque::MaxSizeDeque;
use crate::network_address::NetworkAddress;
use crate::network_interface::NetworkInterface;
use crate::soap::parser::app_sequence::{AppSequence, InvalidAppSequence};
use crate::soap::parser::generic::resolve_qname;
use crate::soap::parser::get::Get;
use crate::soap::{MessageId, WSDMessage};
use crate::wsd::device::DeviceUri;
use crate::xml::{TextReadError, XmlError, XmlReader, read_text};

pub(crate) struct MessageHandler {
    network_address: NetworkAddress,
    recent_messages: Arc<RwLock<MaxSizeDeque<MessageId>>>,
}

/// The header blocks of every message.
pub(crate) struct Header {
    pub to: Option<DeviceUri>,
    pub action: Box<str>,
    pub message_id: MessageId,
}

/// Every header block that was read, before the action decides which of them the message requires.
pub(crate) struct RawHeader {
    header: Header,
    /// `None` when `wsa:RelatesTo` is absent or empty.
    relationship: Option<Relationship>,
    /// `None` when the block is absent.
    app_sequence: Option<Result<AppSequence, InvalidAppSequence>>,
}

/// The `[relationship]` of documentation/ws-addressing.pdf, 3.
enum Relationship {
    /// The type `wsa:Reply`, with the `[message id]` of the request.
    Reply(MessageId),
    /// The type `wsd:Suppression` of documentation/ws-discovery.pdf, 4.1.
    Suppression,
    /// Any other type.
    Other,
}

#[derive(Error, Debug)]
pub(crate) enum HeaderParsingError {
    #[error("Error parsing XML: {}", .0)]
    Xml(#[from] XmlError),
    #[error("Missing Message Id")]
    MissingMessageId,
    #[error("Missing Action")]
    MissingAction,
    #[error("Missing RelatesTo")]
    MissingRelatesTo,
    #[error("Unexpected RelatesTo")]
    UnexpectedRelatesTo,
    #[error("RelatesTo of the type wsd:Suppression")]
    SuppressionRelatesTo,
    #[error("Invalid RelationshipType: {}", .0)]
    InvalidRelationshipType(Box<str>),
    #[error("Missing wsd:AppSequence")]
    MissingAppSequence,
    #[error("Invalid wsd:AppSequence: {}", .0)]
    InvalidAppSequence(InvalidAppSequence),
    #[error("Duplicate {}", .0)]
    DuplicateAddressingBlock(AddressingBlock),
    #[error("Duplicate wsd:AppSequence")]
    DuplicateAppSequence,
    #[error("Duplicate soap:Header")]
    DuplicateHeader,
    #[error("Unsupported XML version: {}", .0)]
    UnsupportedXmlVersion(XmlVersion),
    #[error("Document type declaration")]
    DocumentTypeDeclaration,
    #[error("Not a SOAP 1.2 envelope: {}", .0)]
    NotASoap12Envelope(Box<str>),
    #[error("Unexpected child of soap:Envelope: {}", .0)]
    UnexpectedEnvelopeChild(Box<str>),
}

/// A `wsa` header block read by `parse_header`.
#[derive(Debug)]
pub(crate) enum AddressingBlock {
    To,
    Action,
    MessageId,
    RelatesTo,
}

impl std::fmt::Display for AddressingBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            AddressingBlock::To => f.write_str("wsa:To"),
            AddressingBlock::Action => f.write_str("wsa:Action"),
            AddressingBlock::MessageId => f.write_str("wsa:MessageID"),
            AddressingBlock::RelatesTo => f.write_str("wsa:RelatesTo"),
        }
    }
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
pub(crate) enum BodyParsingError {
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

#[derive(Error, Debug)]
pub(crate) enum MessageHandlerError {
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

pub(crate) fn deconstruct_raw<R>(
    raw: R,
) -> Result<(RawHeader, bool, XmlReader<R>), MessageHandlerError>
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

    #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
    let root = loop {
        // this is the only loop that should hit `XmlEvent::StartDocument` and `XmlEvent::Doctype`
        // in all other parsing functions we could theoretically mark them as `unreachable!()`
        match reader.next().map_err(HeaderParsingError::from)? {
            XmlEvent::StartDocument {
                version: version @ XmlVersion::Version11,
                ..
            } => {
                return Err(HeaderParsingError::UnsupportedXmlVersion(version).into());
            },
            // a SOAP 1.2 message MUST NOT contain a document type declaration, see documentation/soap12-part1.pdf, 5
            XmlEvent::Doctype { .. } => {
                return Err(HeaderParsingError::DocumentTypeDeclaration.into());
            },
            XmlEvent::StartElement { name, .. } => {
                break name;
            },
            XmlEvent::EndDocument => {
                return Err(HeaderParsingError::from(XmlError::MissingElement(Box::from(
                    "soap:Envelope",
                )))
                .into());
            },
            _ => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
        }
    };

    // the expanded name of the document element identifies a SOAP 1.2 message, see documentation/soap12-part1.pdf, 2.8
    if root.namespace_ref() != Some(constants::XML_SOAP_NAMESPACE) || root.local_name != "Envelope"
    {
        return Err(
            HeaderParsingError::NotASoap12Envelope(root.to_string().into_boxed_str()).into(),
        );
    }

    let mut header = None;
    let mut has_body = false;

    // `soap:Envelope` holds an optional `soap:Header` and a mandatory `soap:Body`, in that order, see documentation/soap12-part1.pdf, 5.1
    // every element here is a child of `soap:Envelope`, because `parse_header` reads up to and including `</soap:Header>`
    #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
    loop {
        match reader.next().map_err(HeaderParsingError::from)? {
            XmlEvent::StartElement { name, .. }
                if name.namespace_ref() == Some(constants::XML_SOAP_NAMESPACE)
                    && name.local_name == "Header" =>
            {
                if header.is_some() {
                    return Err(HeaderParsingError::DuplicateHeader.into());
                }

                header = Some(parse_header(&mut reader)?);
            },
            XmlEvent::StartElement { name, .. }
                if name.namespace_ref() == Some(constants::XML_SOAP_NAMESPACE)
                    && name.local_name == "Body" =>
            {
                has_body = true;
                break;
            },
            XmlEvent::StartElement { name, .. } => {
                return Err(HeaderParsingError::UnexpectedEnvelopeChild(
                    name.to_string().into_boxed_str(),
                )
                .into());
            },
            XmlEvent::EndElement { .. } | XmlEvent::EndDocument => {
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
fn require_app_sequence(
    app_sequence: Option<Result<AppSequence, InvalidAppSequence>>,
) -> Result<AppSequence, HeaderParsingError> {
    match app_sequence {
        None => Err(HeaderParsingError::MissingAppSequence),
        Some(Err(error)) => Err(HeaderParsingError::InvalidAppSequence(error)),
        Some(Ok(app_sequence)) => Ok(app_sequence),
    }
}

/// A Probe Match or Resolve Match MUST relate to the Probe or Resolve it answers, see documentation/ws-discovery.pdf, 5.3 and 6.2.
/// A reply relates to its request with a relationship of the type `wsa:Reply`, see documentation/ws-addressing.pdf, 3.
fn require_relates_to(relationship: Option<Relationship>) -> Result<MessageId, HeaderParsingError> {
    match relationship {
        Some(Relationship::Reply(relates_to)) => Ok(relates_to),
        None | Some(Relationship::Suppression | Relationship::Other) => {
            Err(HeaderParsingError::MissingRelatesTo)
        },
    }
}

/// A Hello with `wsa:RelatesTo` of any `RelationshipType` is dropped, because the Discovery Proxy suppression is not implemented, see documentation/ws-discovery.pdf, 4.1.
/// WSDAPI drops such a Hello too.
fn forbid_relates_to(relationship: Option<&Relationship>) -> Result<(), HeaderParsingError> {
    match relationship {
        None => Ok(()),
        Some(_) => Err(HeaderParsingError::UnexpectedRelatesTo),
    }
}

/// A request with `wsa:RelatesTo` is valid, and the spec has no receiver rule for it, see documentation/ws-addressing.pdf, 3.
/// A Get with `wsa:RelatesTo` of any `RelationshipType` is rejected, because `FDResPub` returns no `GetResponse` for it.
fn check_get_relationship(relationship: Option<&Relationship>) -> Result<(), HeaderParsingError> {
    match relationship {
        None => Ok(()),
        Some(&Relationship::Suppression) => Err(HeaderParsingError::SuppressionRelatesTo),
        Some(&(Relationship::Reply(_) | Relationship::Other)) => {
            Err(HeaderParsingError::UnexpectedRelatesTo)
        },
    }
}

/// A request with `wsa:RelatesTo` is valid, and the spec has no receiver rule for it, see documentation/ws-addressing.pdf, 3.
/// A Probe or a Resolve with `wsa:RelatesTo` of a type other than `wsa:Reply` is rejected, because WSDAPI sends no match for it.
fn check_request_relationship(
    relationship: Option<&Relationship>,
) -> Result<(), HeaderParsingError> {
    match relationship {
        None | Some(&Relationship::Reply(_)) => Ok(()),
        Some(&Relationship::Suppression) => Err(HeaderParsingError::SuppressionRelatesTo),
        Some(&Relationship::Other) => Err(HeaderParsingError::UnexpectedRelatesTo),
    }
}

/// Reads past `</soap:Body>`, then requires `</soap:Envelope>`, see documentation/soap12-part1.pdf, 5.1.
pub(crate) fn finish_envelope<R>(reader: &mut XmlReader<R>) -> Result<(), HeaderParsingError>
where
    R: Read,
{
    // `soap:Body` is at depth 2, and a body parser can stop anywhere inside it
    while reader.depth() > 1 {
        reader.next()?;
    }

    #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
    loop {
        match reader.next()? {
            XmlEvent::StartElement { name, .. } => {
                return Err(HeaderParsingError::UnexpectedEnvelopeChild(
                    name.to_string().into_boxed_str(),
                ));
            },
            XmlEvent::EndElement { .. } | XmlEvent::EndDocument => {
                return Ok(());
            },
            _ => {
                // these events are squelched by the parser config, or they're valid, but we ignore them
                // or they just won't occur
            },
        }
    }
}

/// Parses the body of `action`, and moves the header blocks that the action requires into the message.
fn parse_message_body(
    action: &str,
    relationship: Option<Relationship>,
    app_sequence: Option<Result<AppSequence, InvalidAppSequence>>,
    mut reader: XmlReader<&[u8]>,
) -> Result<WSDMessage, MessageHandlerError> {
    let response = match action {
        constants::WSD_GET => {
            check_get_relationship(relationship.as_ref())?;

            Ok(Get {}.into())
        },
        constants::WSD_HELLO => {
            forbid_relates_to(relationship.as_ref())?;

            let app_sequence = require_app_sequence(app_sequence)?;

            Ok(hello::parse_hello(&mut reader, app_sequence)?.into())
        },
        // a Bye with `wsa:RelatesTo` is handled as one without it: its outline allows other header blocks, and Clients SHOULD listen for a Bye, see documentation/ws-discovery.pdf, 4.2
        // WSDAPI drops such a Bye
        constants::WSD_BYE => {
            let app_sequence = require_app_sequence(app_sequence)?;

            Ok(bye::parse_bye(&mut reader, app_sequence)?.into())
        },
        constants::WSD_PROBE_MATCH => {
            let relates_to = require_relates_to(relationship)?;
            let app_sequence = require_app_sequence(app_sequence)?;

            Ok(probe_match::parse_probe_matches(&mut reader, relates_to, app_sequence)?.into())
        },
        constants::WSD_RESOLVE_MATCH => {
            let relates_to = require_relates_to(relationship)?;
            let app_sequence = require_app_sequence(app_sequence)?;

            Ok(resolve_match::parse_resolve_matches(&mut reader, relates_to, app_sequence)?.into())
        },
        constants::WSD_PROBE => {
            check_request_relationship(relationship.as_ref())?;

            Ok(probe::parse_probe(&mut reader)?.into())
        },
        constants::WSD_RESOLVE => {
            check_request_relationship(relationship.as_ref())?;

            Ok(resolve::parse_resolve(&mut reader)?.into())
        },
        action => Err(MessageHandlerError::UnsupportedAction(Box::from(action))),
    }?;

    finish_envelope(&mut reader)?;

    Ok(response)
}

impl MessageHandler {
    pub(crate) fn new(
        network_address: NetworkAddress,
        recent_messages: Arc<RwLock<MaxSizeDeque<MessageId>>>,
    ) -> Self {
        Self {
            network_address,
            recent_messages,
        }
    }

    /// Handle a WSD message received over UDP.
    pub(crate) async fn deconstruct_message<B>(
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
    pub(crate) async fn deconstruct_http_message<B>(
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
        let (
            RawHeader {
                header,
                relationship,
                app_sequence,
            },
            has_body,
            reader,
        ) = deconstruct_raw(raw)?;

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

        let body = parse_message_body(&header.action, relationship, app_sequence, reader)?;

        Ok((header, body))
    }

    /// Implements item 1 of documentation/soap-over-udp.pdf, Appendix II, the list of the last n `MessageID`s.
    /// Returns `true` for a known `MessageID` under the read lock alone, and takes the write lock only to insert an absent one.
    /// Between the two locks, other calls can insert the same `MessageID` and evict it again, so this call can return `false` for a duplicate.
    pub(crate) async fn is_duplicated_msg(&self, message_id: &MessageId) -> bool {
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

fn parse_header<R>(reader: &mut XmlReader<R>) -> Result<RawHeader, HeaderParsingError>
where
    R: Read,
{
    // for the `wsa` blocks, `Some(None)` is a block without text
    // <wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To>
    let mut to = None;
    // <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/ProbeMatches</wsa:Action>
    let mut action = None;
    // <wsa:MessageID>urn:uuid:ae0a8a7b-0138-11f0-8bff-d45ddf1e11a9</wsa:MessageID>
    let mut message_id = None;
    // <wsa:RelatesTo>urn:uuid:ff876786-d5fd-4cc5-825b-fc494834cf19</wsa:RelatesTo>
    let mut relationship = None;
    // <wsd:AppSequence InstanceId="1742000334" SequenceId="urn:uuid:ae0a8b77-0138-11f0-93f3-d45ddf1e11a9" MessageNumber="1" />
    let mut app_sequence = None;

    let entry_depth = reader.depth();

    loop {
        #[expect(clippy::wildcard_enum_match_arm, reason = "Library is stable")]
        match reader.next()? {
            XmlEvent::StartElement {
                name,
                attributes,
                namespace,
            } if reader.depth() == entry_depth + 1
                && name.namespace_ref() == Some(constants::WSA_URI) =>
            {
                // the `wsa` header blocks are read in any order, see documentation/soap12-part1.pdf, 5.2
                // a second `wsa:To`, `wsa:Action` or `wsa:MessageID` violates the cardinality, see documentation/ws-addressing.pdf, 3
                // a second `wsa:RelatesTo` is valid, see documentation/ws-addressing.pdf, 3.1
                // a second `wsa:RelatesTo` is rejected, because WSDAPI drops such a message
                // the outlines list at most one `wsa:RelatesTo`, see documentation/ws-discovery.pdf, 4.1, 5.3 and 6.2
                match &*name.local_name {
                    "To" => {
                        if to.is_some() {
                            return Err(HeaderParsingError::DuplicateAddressingBlock(
                                AddressingBlock::To,
                            ));
                        }

                        to = Some(read_text(reader)?.map(|to| DeviceUri::new(to.into_boxed_str())));
                    },
                    "Action" => {
                        if action.is_some() {
                            return Err(HeaderParsingError::DuplicateAddressingBlock(
                                AddressingBlock::Action,
                            ));
                        }

                        action = Some(read_text(reader)?.map(String::into_boxed_str));
                    },
                    "MessageID" => {
                        if message_id.is_some() {
                            return Err(HeaderParsingError::DuplicateAddressingBlock(
                                AddressingBlock::MessageId,
                            ));
                        }

                        message_id = Some(
                            read_text(reader)?.map(|m_id| MessageId::new(m_id.into_boxed_str())),
                        );
                    },
                    "RelatesTo" => {
                        if relationship.is_some() {
                            return Err(HeaderParsingError::DuplicateAddressingBlock(
                                AddressingBlock::RelatesTo,
                            ));
                        }

                        // an empty `wsa:RelatesTo` is ignored, because WSDAPI ignores it in a Hello or a Bye
                        relationship = Some(
                            read_text(reader)?
                                .map(|relates_to| {
                                    parse_relationship(&attributes, &namespace, relates_to)
                                })
                                .transpose()?,
                        );
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

    let Some(message_id) = message_id.flatten() else {
        return Err(HeaderParsingError::MissingMessageId);
    };

    let Some(action) = action.flatten() else {
        return Err(HeaderParsingError::MissingAction);
    };

    Ok(RawHeader {
        header: Header {
            to: to.flatten(),
            action,
            message_id,
        },
        relationship: relationship.flatten(),
        app_sequence,
    })
}

/// Reads the relationship of a `wsa:RelatesTo` with the text `relates_to`, of the type `wsa:Reply` when `RelationshipType` is absent, see documentation/ws-addressing.pdf, 3.
fn parse_relationship(
    attributes: &[OwnedAttribute],
    namespaces: &Namespace,
    relates_to: String,
) -> Result<Relationship, HeaderParsingError> {
    let Some(relationship_type) = attributes.iter().find(|attribute| {
        attribute.name.namespace.is_none() && attribute.name.local_name == "RelationshipType"
    }) else {
        return Ok(Relationship::Reply(MessageId::new(
            relates_to.into_boxed_str(),
        )));
    };

    // an `xs:QName` collapses its white space, see documentation/xmlschema-2.pdf, 3.2.18
    match resolve_qname(
        relationship_type.value.trim_matches(is_whitespace_char),
        namespaces,
    ) {
        Some((constants::WSA_URI, "Reply")) => Ok(Relationship::Reply(MessageId::new(
            relates_to.into_boxed_str(),
        ))),
        Some((constants::XML_WSD_NAMESPACE, "Suppression")) => Ok(Relationship::Suppression),
        Some(_) => Ok(Relationship::Other),
        None => Err(HeaderParsingError::InvalidRelationshipType(
            relationship_type.value.clone().into_boxed_str(),
        )),
    }
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
        AddressingBlock, BodyParsingError, HeaderParsingError, MessageHandler, MessageHandlerError,
        deconstruct_raw,
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

    #[test]
    fn rejects_document_type_declaration() {
        let probe = format!(
            r#"<?xml version="1.0" encoding="utf-8"?><!DOCTYPE soap:Envelope>{}"#,
            message(constants::WSD_PROBE, "", "<wsd:Probe />")
        );

        assert_matches!(
            deconstruct_raw(probe.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::DocumentTypeDeclaration
            ))
        );
    }

    /// A Probe whose `soap:Envelope` also declares `xmlns:x="urn:example"` and `xmlns:s11` for SOAP 1.1.
    fn probe_with_extra_namespaces() -> String {
        message(constants::WSD_PROBE, "", "<wsd:Probe />").replace(
            "xmlns:soap",
            r#"xmlns:x="urn:example" xmlns:s11="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soap"#,
        )
    }

    #[test]
    fn rejects_root_other_than_soap_envelope() {
        let probe = probe_with_extra_namespaces().replace("soap:Envelope", "x:NotAnEnvelope");

        assert_matches!(
            deconstruct_raw(probe.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::NotASoap12Envelope(_)
            ))
        );
    }

    #[test]
    fn rejects_soap_1_1_envelope() {
        let probe = probe_with_extra_namespaces().replace("soap:Envelope", "s11:Envelope");

        assert_matches!(
            deconstruct_raw(probe.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::NotASoap12Envelope(_)
            ))
        );
    }

    #[test]
    fn rejects_header_and_body_inside_another_element() {
        let probe = probe_with_extra_namespaces()
            .replace("<soap:Header>", "<x:Wrapper><soap:Header>")
            .replace("</soap:Body>", "</soap:Body></x:Wrapper>");

        assert_matches!(
            deconstruct_raw(probe.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedEnvelopeChild(_)
            ))
        );
    }

    #[test]
    fn rejects_element_between_header_and_body() {
        let probe =
            probe_with_extra_namespaces().replace("</soap:Header>", "</soap:Header><x:Extra />");

        assert_matches!(
            deconstruct_raw(probe.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedEnvelopeChild(_)
            ))
        );
    }

    #[tokio::test]
    async fn rejects_element_after_body() {
        let probe =
            probe_with_extra_namespaces().replace("</soap:Body>", "</soap:Body><x:Extra />");

        let result = handler_for_tests(8)
            .deconstruct_message(&probe, SOURCE)
            .await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedEnvelopeChild(_)
            ))
        );
    }

    #[tokio::test]
    async fn rejects_element_after_body_of_get() {
        let get = message(constants::WSD_GET, "", "").replace(
            "</soap:Body>",
            r#"</soap:Body><x:Extra xmlns:x="urn:example" />"#,
        );

        let result = handler_for_tests(8).deconstruct_http_message(&get).await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedEnvelopeChild(_)
            ))
        );
    }

    fn message(action: &str, header_blocks: &str, body: &str) -> String {
        format!(
            r#"<soap:Envelope xmlns:soap="{}" xmlns:wsa="{}" xmlns:wsd="{}"><soap:Header><wsa:To>{}</wsa:To><wsa:Action>{}</wsa:Action><wsa:MessageID>{}</wsa:MessageID>{}</soap:Header><soap:Body>{}</soap:Body></soap:Envelope>"#,
            constants::XML_SOAP_NAMESPACE,
            constants::WSA_URI,
            constants::XML_WSD_NAMESPACE,
            constants::WSA_DISCOVERY,
            action,
            Uuid::now_v7().urn(),
            header_blocks,
            body
        )
    }

    fn hello_body(metadata_version: u64) -> String {
        format!(
            "<wsd:Hello><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:MetadataVersion>{}</wsd:MetadataVersion></wsd:Hello>",
            metadata_version
        )
    }

    const BYE_BODY: &str = "<wsd:Bye><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference></wsd:Bye>";

    fn probe_matches_body(metadata_version: u64) -> String {
        format!(
            "<wsd:ProbeMatches><wsd:ProbeMatch><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:MetadataVersion>{}</wsd:MetadataVersion></wsd:ProbeMatch></wsd:ProbeMatches>",
            metadata_version
        )
    }

    fn resolve_matches_body(metadata_version: u64) -> String {
        format!(
            "<wsd:ResolveMatches><wsd:ResolveMatch><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference><wsd:XAddrs>http://192.168.100.5:5357/</wsd:XAddrs><wsd:MetadataVersion>{}</wsd:MetadataVersion></wsd:ResolveMatch></wsd:ResolveMatches>",
            metadata_version
        )
    }

    const FULL_APP_SEQUENCE: &str = r#"<wsd:AppSequence InstanceId="3" SequenceId="urn:uuid:ae0a8b77-0138-11f0-93f3-d45ddf1e11a9" MessageNumber="7" />"#;

    fn full_app_sequence() -> AppSequence {
        AppSequence::new(3, Some("urn:uuid:ae0a8b77-0138-11f0-93f3-d45ddf1e11a9"), 7)
    }

    const RELATES_TO: &str =
        "<wsa:RelatesTo>urn:uuid:00000000-0000-0000-0000-000000000002</wsa:RelatesTo>";

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

    #[test]
    fn rejects_duplicate_to() {
        let hello = message(
            constants::WSD_HELLO,
            &format!("<wsa:To>{}</wsa:To>", constants::WSA_DISCOVERY),
            "",
        );

        assert_matches!(
            deconstruct_raw(hello.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::DuplicateAddressingBlock(AddressingBlock::To)
            ))
        );
    }

    #[test]
    fn rejects_duplicate_action() {
        let hello = message(
            constants::WSD_HELLO,
            &format!("<wsa:Action>{}</wsa:Action>", constants::WSD_HELLO),
            "",
        );

        assert_matches!(
            deconstruct_raw(hello.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::DuplicateAddressingBlock(AddressingBlock::Action)
            ))
        );
    }

    #[test]
    fn rejects_duplicate_message_id() {
        let hello = message(
            constants::WSD_HELLO,
            &format!("<wsa:MessageID>{}</wsa:MessageID>", Uuid::now_v7().urn()),
            "",
        );

        assert_matches!(
            deconstruct_raw(hello.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::DuplicateAddressingBlock(AddressingBlock::MessageId)
            ))
        );
    }

    fn relates_to_with_type(relationship_type: &str) -> String {
        format!(
            r#"<wsa:RelatesTo RelationshipType="{}">urn:uuid:00000000-0000-0000-0000-000000000002</wsa:RelatesTo>"#,
            relationship_type
        )
    }

    const OTHER_TYPE_RELATES_TO: &str = r#"<wsa:RelatesTo xmlns:x="urn:x" RelationshipType="x:Other">urn:uuid:00000000-0000-0000-0000-000000000002</wsa:RelatesTo>"#;

    #[test]
    fn rejects_duplicate_relates_to() {
        let probe_matches = message(
            constants::WSD_PROBE_MATCH,
            &format!("{}{}", RELATES_TO, RELATES_TO),
            "",
        );

        assert_matches!(
            deconstruct_raw(probe_matches.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::DuplicateAddressingBlock(AddressingBlock::RelatesTo)
            ))
        );
    }

    #[test]
    fn rejects_relates_to_followed_by_empty_relates_to() {
        let hello = message(
            constants::WSD_HELLO,
            &format!("{}<wsa:RelatesTo />", RELATES_TO),
            "",
        );

        assert_matches!(
            deconstruct_raw(hello.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::DuplicateAddressingBlock(AddressingBlock::RelatesTo)
            ))
        );
    }

    #[test]
    fn rejects_two_empty_relates_to() {
        let hello = message(
            constants::WSD_HELLO,
            "<wsa:RelatesTo /><wsa:RelatesTo />",
            "",
        );

        assert_matches!(
            deconstruct_raw(hello.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::DuplicateAddressingBlock(AddressingBlock::RelatesTo)
            ))
        );
    }

    #[test]
    fn rejects_relationship_type_with_undeclared_prefix() {
        let probe = message(constants::WSD_PROBE, &relates_to_with_type("y:Other"), "");

        assert_matches!(
            deconstruct_raw(probe.as_bytes()).err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::InvalidRelationshipType(_)
            ))
        );
    }

    async fn deconstruct_get(header_blocks: &str) -> Result<(), MessageHandlerError> {
        let get = message(constants::WSD_GET, header_blocks, "");

        handler_for_tests(8)
            .deconstruct_http_message(&get)
            .await
            .map(|_| ())
    }

    #[tokio::test]
    async fn rejects_get_with_relates_to() {
        assert_matches!(
            deconstruct_get(RELATES_TO).await,
            Err(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn rejects_get_with_suppression_relates_to() {
        assert_matches!(
            deconstruct_get(&relates_to_with_type("wsd:Suppression")).await,
            Err(MessageHandlerError::HeaderError(
                HeaderParsingError::SuppressionRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn rejects_get_with_other_relates_to() {
        assert_matches!(
            deconstruct_get(OTHER_TYPE_RELATES_TO).await,
            Err(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedRelatesTo
            ))
        );
    }

    async fn deconstruct_probe(header_blocks: &str) -> Result<(), MessageHandlerError> {
        let probe = message(constants::WSD_PROBE, header_blocks, "<wsd:Probe />");

        handler_for_tests(8)
            .deconstruct_message(&probe, SOURCE)
            .await
            .map(|_| ())
    }

    #[tokio::test]
    async fn accepts_probe_with_relates_to() {
        assert_matches!(deconstruct_probe(RELATES_TO).await, Ok(()));
    }

    #[tokio::test]
    async fn accepts_probe_with_explicit_reply_relates_to() {
        assert_matches!(
            deconstruct_probe(&relates_to_with_type("wsa:Reply")).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn accepts_probe_with_reply_relationship_type_with_white_space() {
        assert_matches!(
            deconstruct_probe(&relates_to_with_type(" wsa:Reply ")).await,
            Ok(())
        );
    }

    #[tokio::test]
    async fn rejects_probe_with_suppression_relates_to() {
        assert_matches!(
            deconstruct_probe(&relates_to_with_type("wsd:Suppression")).await,
            Err(MessageHandlerError::HeaderError(
                HeaderParsingError::SuppressionRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn rejects_probe_with_other_relates_to() {
        assert_matches!(
            deconstruct_probe(OTHER_TYPE_RELATES_TO).await,
            Err(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn rejects_probe_with_unprefixed_reply_relationship_type() {
        // without a default namespace, `Reply` has no namespace
        assert_matches!(
            deconstruct_probe(&relates_to_with_type("Reply")).await,
            Err(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedRelatesTo
            ))
        );
    }

    async fn deconstruct_resolve(header_blocks: &str) -> Result<(), MessageHandlerError> {
        let resolve = message(
            constants::WSD_RESOLVE,
            header_blocks,
            "<wsd:Resolve><wsa:EndpointReference><wsa:Address>urn:uuid:00000000-0000-0000-0000-000000000001</wsa:Address></wsa:EndpointReference></wsd:Resolve>",
        );

        handler_for_tests(8)
            .deconstruct_message(&resolve, SOURCE)
            .await
            .map(|_| ())
    }

    #[tokio::test]
    async fn accepts_resolve_with_relates_to() {
        assert_matches!(deconstruct_resolve(RELATES_TO).await, Ok(()));
    }

    #[tokio::test]
    async fn rejects_resolve_with_suppression_relates_to() {
        assert_matches!(
            deconstruct_resolve(&relates_to_with_type("wsd:Suppression")).await,
            Err(MessageHandlerError::HeaderError(
                HeaderParsingError::SuppressionRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn rejects_resolve_with_other_relates_to() {
        assert_matches!(
            deconstruct_resolve(OTHER_TYPE_RELATES_TO).await,
            Err(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn accepts_hello_with_app_sequence() {
        let hello = message(constants::WSD_HELLO, FULL_APP_SEQUENCE, &hello_body(1));

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
    async fn rejects_hello_with_relates_to() {
        let hello = message(
            constants::WSD_HELLO,
            &format!("{}{}", RELATES_TO, FULL_APP_SEQUENCE),
            &hello_body(1),
        );

        let result = handler_for_tests(8)
            .deconstruct_message(&hello, SOURCE)
            .await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn rejects_suppression_hello() {
        let hello = message(
            constants::WSD_HELLO,
            &format!(
                r#"<wsa:RelatesTo RelationshipType="wsd:Suppression">urn:uuid:00000000-0000-0000-0000-000000000002</wsa:RelatesTo>{}"#,
                FULL_APP_SEQUENCE
            ),
            &hello_body(1),
        );

        let result = handler_for_tests(8)
            .deconstruct_message(&hello, SOURCE)
            .await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::UnexpectedRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn accepts_hello_with_empty_relates_to() {
        let hello = message(
            constants::WSD_HELLO,
            &format!("<wsa:RelatesTo />{}", FULL_APP_SEQUENCE),
            &hello_body(1),
        );

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
    async fn accepts_probe_matches_with_app_sequence() {
        let probe_matches = message(
            constants::WSD_PROBE_MATCH,
            &format!("{}{}", FULL_APP_SEQUENCE, RELATES_TO),
            &probe_matches_body(1),
        );

        let (_, message) = handler_for_tests(8)
            .deconstruct_message(&probe_matches, SOURCE)
            .await
            .unwrap();

        assert_eq!(
            message
                .into_probe_matches()
                .map(|probe_matches| probe_matches.app_sequence),
            Some(full_app_sequence())
        );
    }

    #[tokio::test]
    async fn accepts_resolve_matches_with_app_sequence() {
        let resolve_matches = message(
            constants::WSD_RESOLVE_MATCH,
            &format!("{}{}", FULL_APP_SEQUENCE, RELATES_TO),
            &resolve_matches_body(1),
        );

        let (_, message) = handler_for_tests(8)
            .deconstruct_message(&resolve_matches, SOURCE)
            .await
            .unwrap();

        assert_eq!(
            message
                .into_resolve_matches()
                .map(|resolve_matches| resolve_matches.app_sequence),
            Some(full_app_sequence())
        );
    }

    #[tokio::test]
    async fn parses_relates_to_of_probe_matches() {
        let probe_matches = message(
            constants::WSD_PROBE_MATCH,
            &format!("{}{}", APP_SEQUENCE, RELATES_TO),
            &probe_matches_body(1),
        );

        let (_, message) = handler_for_tests(8)
            .deconstruct_message(&probe_matches, SOURCE)
            .await
            .unwrap();

        assert_eq!(
            message
                .into_probe_matches()
                .map(|probe_matches| probe_matches.relates_to),
            Some(MessageId::new(Box::from(
                "urn:uuid:00000000-0000-0000-0000-000000000002"
            )))
        );
    }

    async fn deconstruct_probe_matches(relates_to: &str) -> Result<(), MessageHandlerError> {
        let probe_matches = message(
            constants::WSD_PROBE_MATCH,
            &format!("{}{}", APP_SEQUENCE, relates_to),
            &probe_matches_body(1),
        );

        handler_for_tests(8)
            .deconstruct_message(&probe_matches, SOURCE)
            .await
            .map(|_| ())
    }

    #[tokio::test]
    async fn rejects_probe_matches_with_suppression_relates_to() {
        assert_matches!(
            deconstruct_probe_matches(&relates_to_with_type("wsd:Suppression")).await,
            Err(MessageHandlerError::HeaderError(
                HeaderParsingError::MissingRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn rejects_probe_matches_with_other_relates_to() {
        assert_matches!(
            deconstruct_probe_matches(OTHER_TYPE_RELATES_TO).await,
            Err(MessageHandlerError::HeaderError(
                HeaderParsingError::MissingRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn rejects_probe_matches_without_relates_to() {
        let probe_matches = message(
            constants::WSD_PROBE_MATCH,
            APP_SEQUENCE,
            &probe_matches_body(1),
        );

        let result = handler_for_tests(8)
            .deconstruct_message(&probe_matches, SOURCE)
            .await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::MissingRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn parses_relates_to_of_resolve_matches() {
        let resolve_matches = message(
            constants::WSD_RESOLVE_MATCH,
            &format!("{}{}", APP_SEQUENCE, RELATES_TO),
            &resolve_matches_body(1),
        );

        let (_, message) = handler_for_tests(8)
            .deconstruct_message(&resolve_matches, SOURCE)
            .await
            .unwrap();

        assert_eq!(
            message
                .into_resolve_matches()
                .map(|resolve_matches| resolve_matches.relates_to),
            Some(MessageId::new(Box::from(
                "urn:uuid:00000000-0000-0000-0000-000000000002"
            )))
        );
    }

    #[tokio::test]
    async fn rejects_resolve_matches_without_relates_to() {
        let resolve_matches = message(
            constants::WSD_RESOLVE_MATCH,
            APP_SEQUENCE,
            &resolve_matches_body(1),
        );

        let result = handler_for_tests(8)
            .deconstruct_message(&resolve_matches, SOURCE)
            .await;

        assert_matches!(
            result.err(),
            Some(MessageHandlerError::HeaderError(
                HeaderParsingError::MissingRelatesTo
            ))
        );
    }

    #[tokio::test]
    async fn parses_metadata_version_of_hello() {
        let hello = message(
            constants::WSD_HELLO,
            APP_SEQUENCE,
            &hello_body(u64::from(u32::MAX) + 1),
        );

        let (_, message) = handler_for_tests(8)
            .deconstruct_message(&hello, SOURCE)
            .await
            .unwrap();

        assert_eq!(
            message.into_hello().map(|hello| hello.metadata_version),
            Some(u64::from(u32::MAX) + 1)
        );
    }

    #[tokio::test]
    async fn parses_metadata_version_of_probe_match() {
        let probe_matches = message(
            constants::WSD_PROBE_MATCH,
            &format!("{}{}", APP_SEQUENCE, RELATES_TO),
            &probe_matches_body(u64::from(u32::MAX) + 1),
        );

        let (_, message) = handler_for_tests(8)
            .deconstruct_message(&probe_matches, SOURCE)
            .await
            .unwrap();

        assert_eq!(
            message.into_probe_matches().map(|probe_matches| {
                probe_matches
                    .matches
                    .iter()
                    .map(|probe_match| probe_match.metadata_version)
                    .collect::<Vec<_>>()
            }),
            Some(vec![u64::from(u32::MAX) + 1])
        );
    }

    #[tokio::test]
    async fn parses_metadata_version_of_resolve_match() {
        let resolve_matches = message(
            constants::WSD_RESOLVE_MATCH,
            &format!("{}{}", APP_SEQUENCE, RELATES_TO),
            &resolve_matches_body(u64::from(u32::MAX) + 1),
        );

        let (_, message) = handler_for_tests(8)
            .deconstruct_message(&resolve_matches, SOURCE)
            .await
            .unwrap();

        assert_eq!(
            message
                .into_resolve_matches()
                .and_then(|resolve_matches| resolve_matches.resolve_match)
                .map(|resolve_match| resolve_match.metadata_version),
            Some(u64::from(u32::MAX) + 1)
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

    async fn assert_bye_accepted(header_blocks: &str) {
        let bye = message(
            constants::WSD_BYE,
            &format!("{}{}", header_blocks, FULL_APP_SEQUENCE),
            BYE_BODY,
        );

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
    async fn accepts_bye_with_relates_to() {
        assert_bye_accepted(RELATES_TO).await;
    }

    #[tokio::test]
    async fn accepts_bye_with_suppression_relates_to() {
        assert_bye_accepted(&relates_to_with_type("wsd:Suppression")).await;
    }

    #[tokio::test]
    async fn accepts_bye_with_empty_relates_to() {
        assert_bye_accepted("<wsa:RelatesTo />").await;
    }

    #[tokio::test]
    async fn rejects_hello_without_app_sequence() {
        let hello = message(constants::WSD_HELLO, "", &hello_body(1));

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
            &hello_body(1),
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
