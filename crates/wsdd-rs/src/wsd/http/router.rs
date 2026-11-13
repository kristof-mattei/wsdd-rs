use std::sync::Arc;

use axum::extract::State;
use axum::handler::HandlerWithoutStateExt as _;
use axum::http::{HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, debug_handler};
use bytes::Bytes;
use color_eyre::eyre;
use http::StatusCode;
use http::header::CONTENT_TYPE;
use tower_http::on_early_drop::{EarlyDropsAsFailures, OnEarlyDropLayer};
use tower_http::trace::{DefaultOnFailure, DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{Level, event};

use crate::config::Config;
use crate::constants;
use crate::soap::builder::{Builder, Fault, FaultCode};
use crate::soap::parser::{
    self, AddressingBlock, HeaderParsingError, MessageHandler, MessageHandlerError, RawHeader,
    ReadHeader, ReplyTo,
};
use crate::soap::{HostMessage, MessageId, UnicastMessage, WSDMessage};
use crate::span::MakeSpanWithUuid;
use crate::xml::XmlReader;

pub(crate) fn build_router(config: Arc<Config>, message_handler: MessageHandler) -> Router {
    let post_path = format!("/{}", config.uuid);

    let router = Router::new()
        .route(&post_path, post(handle_post))
        .fallback_service(handler_404.into_service())
        .route("/healthz", get(healthz))
        // inside the `TraceLayer` so the drop event lands in the request span
        .layer(OnEarlyDropLayer::new(EarlyDropsAsFailures::new(
            DefaultOnFailure::new().level(Level::DEBUG),
        )))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(MakeSpanWithUuid::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::TRACE))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state((config, Arc::new(message_handler)));

    router
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "All systems go!")
}

async fn handler_404() -> impl IntoResponse {
    StatusCode::NOT_FOUND
}

/// The answers of the HTTP endpoint.
enum Answer {
    /// 200 with a SOAP envelope.
    Message(UnicastMessage),
    /// 202 without a body.
    Accepted,
    /// A SOAP fault with its status.
    Fault(StatusCode, Box<[u8]>),
    /// 400 without a body.
    NotWellFormed,
}

#[debug_handler]
async fn handle_post(
    headers: HeaderMap,
    State((config, message_handler)): State<(Arc<Config>, Arc<MessageHandler>)>,
    body: Bytes,
) -> Response {
    // a request with another media type gets 415, see documentation/soap12-part2.pdf, 7.5.2.1, Table 18
    // FDResPub answers such a request with 400 and `Connection: close`
    if !headers.get(CONTENT_TYPE).is_some_and(starts_with_soap_xml) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response();
    }

    match build_response(&config, &message_handler, &body).await {
        Ok(Answer::Message(message)) => (
            StatusCode::OK,
            [(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)],
            message,
        )
            .into_response(),
        Ok(Answer::Accepted) => (
            StatusCode::ACCEPTED,
            [(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)],
        )
            .into_response(),
        Ok(Answer::Fault(status, fault)) => (
            status,
            [(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)],
            fault,
        )
            .into_response(),
        Ok(Answer::NotWellFormed) => StatusCode::BAD_REQUEST.into_response(),
        Err(error) => {
            event!(Level::ERROR, ?error, "Error parsing/building XML response");

            (StatusCode::BAD_REQUEST).into_response()
        },
    }
}

/// Returns whether `content_type` starts with `application/soap+xml` in any case, because `FDResPub` accepts every such `Content-Type`.
/// RFC 9110 does not allow all of them: `application/soap+xml-foo` is another media type (8.3.1), and `application/soap+xml; charset` has a malformed parameter (5.6.6).
fn starts_with_soap_xml(content_type: &HeaderValue) -> bool {
    content_type
        .as_bytes()
        .get(..constants::MIME_TYPE_SOAP_XML.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(constants::MIME_TYPE_SOAP_XML.as_bytes()))
}

async fn build_response(
    config: &Config,
    message_handler: &MessageHandler,
    buffer: &[u8],
) -> Result<Answer, eyre::Report> {
    let mut reader = parser::xml_reader(buffer);

    let answer = answer(config, message_handler, buffer, &mut reader).await;

    // a document that is not well-formed XML gets 400 without a body, whatever its header, see documentation/soap12-part2.pdf, 7.5.2.1, Table 18
    // FDResPub returns a fault for some of these documents, and 202 for the others
    if let Err(error) = parser::read_to_end(&mut reader) {
        event!(
            Level::TRACE,
            ?error,
            wsd_message = %String::from_utf8_lossy(buffer),
            "XML is not well-formed",
        );

        return Ok(Answer::NotWellFormed);
    }

    answer
}

async fn answer<'b>(
    config: &Config,
    message_handler: &MessageHandler,
    buffer: &'b [u8],
    reader: &mut XmlReader<&'b [u8]>,
) -> Result<Answer, eyre::Report> {
    let message = match ReadHeader::read(buffer, reader) {
        Ok(message) => message,
        Err(error) => {
            return Ok(answer_invalid_request(config, buffer, &error, None)?);
        },
    };

    if let Some(answer) = answer_from_header(config, message.header())? {
        return Ok(answer);
    }

    let reply_to = message.header().reply_to();

    let (header, body) = match message_handler
        .deconstruct_http_message(message, reader)
        .await
    {
        Ok(pieces) => pieces,
        Err(error) => {
            return Ok(answer_invalid_request(config, buffer, &error, None)?);
        },
    };

    let message = match body {
        Ok(message) => message,
        Err(error) => {
            return Ok(answer_invalid_request(
                config,
                buffer,
                &error,
                Some(&header.message_id),
            )?);
        },
    };

    match message {
        WSDMessage::HostMessage(HostMessage::Get(_get)) => match reply_to {
            // a Get without `wsa:ReplyTo` gets `wsa:EndpointUnavailable` after its body is read, because FDResPub returns it in that order
            // a sender MUST include `wsa:ReplyTo` when it expects a reply, and the spec has no receiver rule, see documentation/ws-addressing.pdf, 3
            None => Ok(valid_request_fault(
                config,
                Fault::EndpointUnavailable,
                Some(&header.message_id),
            )?),
            Some(_) => Ok(Answer::Message(Builder::build_get_response(
                config,
                &header.message_id,
            )?)),
        },
        WSDMessage::HostMessage(HostMessage::Probe(probe)) => {
            if probe.matches() {
                return Ok(Answer::Message(Builder::build_probe_matches(
                    config,
                    &header.message_id,
                )?));
            }

            event!(
                Level::DEBUG,
                ?probe.types,
                "client requests types we don't offer"
            );

            Ok(Answer::Accepted)
        },
        WSDMessage::ClientMessage(_) | WSDMessage::HostMessage(HostMessage::Resolve(_)) => {
            Err(eyre::Report::msg("Invalid Action"))
        },
    }
}

/// Answers a request from its header, before its body is read.
/// Returns `None` when the body decides the answer.
fn answer_from_header(
    config: &Config,
    header: &RawHeader,
) -> Result<Option<Answer>, xml::writer::Error> {
    let message_id = header.message_id();
    let reply_to = header.reply_to();

    // see documentation/ws-addressing.pdf, 3 and 4.2
    // FDResPub returns 202 for a Get without `wsa:To`
    let Some(to) = header.to() else {
        return invalid_request_fault(config, Fault::MessageInformationHeaderRequired, message_id)
            .map(Some);
    };

    // a `wsa:ReplyTo` without the `wsa:Address` of documentation/ws-addressing.pdf, 2.2, gets `wsa:InvalidMessageInformationHeader`, see 4.1
    // FDResPub returns 202 for it
    if let Some(ReplyTo::WithoutAddress) = reply_to {
        return invalid_request_fault(config, Fault::InvalidMessageInformationHeader, message_id)
            .map(Some);
    }

    match header.action() {
        constants::WSD_GET | constants::WSD_PROBE | constants::WSD_RESOLVE => {},
        _ => {
            // `wsa:ReplyTo` requires `wsa:MessageID`, see documentation/ws-addressing.pdf, 3 and 4.2
            if message_id.is_none() && reply_to.is_some() {
                return invalid_request_fault(
                    config,
                    Fault::MessageInformationHeaderRequired,
                    None,
                )
                .map(Some);
            }

            // a Hello, a Bye, a ProbeMatches, a ResolveMatches or another action gets `wsa:DestinationUnreachable`, whatever its `wsa:To`, because FDResPub returns it
            // the fault for an unsupported action is `wsa:ActionNotSupported`, see documentation/ws-addressing.pdf, 4.4
            return valid_request_fault(config, Fault::DestinationUnreachable, message_id)
                .map(Some);
        },
    }

    // a Get, a Probe or a Resolve expects a reply, which requires `wsa:MessageID`, see documentation/ws-addressing.pdf, 3 and 4.2
    // FDResPub returns `wsa:DestinationUnreachable` for a Get or a Probe with `wsa:ReplyTo`, and without it `wsa:EndpointUnavailable` for a Get and 202 for a Probe
    let Some(message_id) = message_id else {
        return invalid_request_fault(config, Fault::MessageInformationHeaderRequired, None)
            .map(Some);
    };

    // see documentation/ws-addressing.pdf, 4.3
    if header.action() == constants::WSD_GET && to != &config.uuid_as_device_uri {
        return valid_request_fault(config, Fault::DestinationUnreachable, Some(message_id))
            .map(Some);
    }

    // see documentation/devicesprofile.pdf, 3.5, R0031
    if let Some(ReplyTo::NotAnonymous) = reply_to {
        return valid_request_fault(
            config,
            Fault::InvalidMessageInformationHeader,
            Some(message_id),
        )
        .map(Some);
    }

    Ok(None)
}

/// Answers a request that failed to parse.
fn answer_invalid_request(
    config: &Config,
    buffer: &[u8],
    error: &MessageHandlerError,
    relates_to: Option<&MessageId>,
) -> Result<Answer, xml::writer::Error> {
    let fault = match *error {
        MessageHandlerError::DuplicateMessage => {
            return Ok(Answer::Accepted);
        },
        // a request with two `wsa:RelatesTo`, or with `wsa:RelatesTo` of the type `wsd:Suppression`, is valid, see documentation/ws-addressing.pdf, 3
        // such a request gets 202 without a body, because FDResPub returns 202 without a body for it
        MessageHandlerError::HeaderError(
            HeaderParsingError::DuplicateAddressingBlock(AddressingBlock::RelatesTo)
            | HeaderParsingError::SuppressionRelatesTo,
        ) => {
            error.log(buffer);

            return Ok(Answer::Accepted);
        },
        // a Get with `wsa:RelatesTo`, or a Probe or a Resolve with `wsa:RelatesTo` of a type other than `wsa:Reply`, is valid, see documentation/ws-addressing.pdf, 3
        // such a request gets `wsa:DestinationUnreachable`, because FDResPub returns it
        MessageHandlerError::HeaderError(HeaderParsingError::UnexpectedRelatesTo) => {
            error.log(buffer);

            return valid_request_fault(config, Fault::DestinationUnreachable, relates_to);
        },
        // a message whose version is not supported gets `env:VersionMismatch`, see documentation/soap12-part1.pdf, 2.8
        MessageHandlerError::HeaderError(HeaderParsingError::NotASoap12Envelope(_)) => {
            Fault::VersionMismatch
        },
        // `wsa:Action` is REQUIRED, see documentation/ws-addressing.pdf, 3 and 4.2, and a message without `soap:Header` has no `wsa:Action`
        MessageHandlerError::HeaderError(
            HeaderParsingError::MissingAction
            | HeaderParsingError::MissingHeader
            | HeaderParsingError::MissingMessageId,
        ) => Fault::MessageInformationHeaderRequired,
        // a second `wsa:To`, `wsa:Action`, `wsa:MessageID` or `wsa:ReplyTo`, or a `RelationshipType` that is not an `xs:QName`, see documentation/ws-addressing.pdf, 3 and 4.1
        // FDResPub returns 202 for a repeated block
        MessageHandlerError::HeaderError(
            HeaderParsingError::DuplicateAddressingBlock(
                AddressingBlock::To
                | AddressingBlock::Action
                | AddressingBlock::MessageId
                | AddressingBlock::ReplyTo,
            )
            | HeaderParsingError::InvalidRelationshipType(_),
        ) => Fault::InvalidMessageInformationHeader,
        // any other malformation gets `env:Sender`, see documentation/soap12-part1.pdf, 2.8
        // FDResPub returns 202 for it
        MessageHandlerError::HeaderError(
            HeaderParsingError::Xml(_)
            | HeaderParsingError::MissingRelatesTo
            | HeaderParsingError::MissingAppSequence
            | HeaderParsingError::InvalidAppSequence(_)
            | HeaderParsingError::DuplicateAppSequence
            | HeaderParsingError::DuplicateHeader
            | HeaderParsingError::UnsupportedXmlVersion(_)
            | HeaderParsingError::DocumentTypeDeclaration
            | HeaderParsingError::UnexpectedEnvelopeChild(_),
        )
        | MessageHandlerError::BodyError(_)
        | MessageHandlerError::MalformedAction(_)
        | MessageHandlerError::UnsupportedAction(_) => Fault::Sender,
    };

    error.log(buffer);

    invalid_request_fault(config, fault, relates_to)
}

/// A fault for an invalid request gets the status of documentation/soap12-part2.pdf, 7.5.2.2, Table 20.
fn invalid_request_fault(
    config: &Config,
    fault: Fault,
    relates_to: Option<&MessageId>,
) -> Result<Answer, xml::writer::Error> {
    let status = match fault.code() {
        FaultCode::Sender => StatusCode::BAD_REQUEST,
        FaultCode::VersionMismatch | FaultCode::Receiver => StatusCode::INTERNAL_SERVER_ERROR,
    };

    Ok(Answer::Fault(
        status,
        Builder::build_fault(config, fault, relates_to)?,
    ))
}

/// A fault for a valid request gets 500, because `FDResPub` returns 500 for every fault.
/// The status for an `env:Sender` fault is 400, see documentation/soap12-part2.pdf, 7.5.2.2, Table 20.
fn valid_request_fault(
    config: &Config,
    fault: Fault,
    relates_to: Option<&MessageId>,
) -> Result<Answer, xml::writer::Error> {
    Ok(Answer::Fault(
        StatusCode::INTERNAL_SERVER_ERROR,
        Builder::build_fault(config, fault, relates_to)?,
    ))
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use crate::wsd::http::router::starts_with_soap_xml;

    fn is_accepted(content_type: &'static str) -> bool {
        starts_with_soap_xml(&HeaderValue::from_static(content_type))
    }

    #[test]
    fn accepts_soap_xml() {
        assert!(is_accepted("application/soap+xml"));
    }

    #[test]
    fn accepts_soap_xml_with_parameter() {
        assert!(is_accepted("application/soap+xml; charset=utf-8"));
    }

    #[test]
    fn accepts_soap_xml_in_any_case() {
        assert!(is_accepted("APPLICATION/SOAP+XML"));
        assert!(is_accepted("Application/Soap+Xml"));
    }

    #[test]
    fn accepts_longer_subtype() {
        assert!(is_accepted("application/soap+xml-foo"));
    }

    #[test]
    fn accepts_malformed_parameter() {
        assert!(is_accepted("application/soap+xml; charset"));
    }

    #[test]
    fn rejects_shorter_subtype() {
        assert!(!is_accepted("application/soap"));
    }

    #[test]
    fn rejects_another_media_type() {
        assert!(!is_accepted("text/xml; charset=utf-8"));
    }
}
