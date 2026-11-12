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
use crate::soap::parser::{HeaderParsingError, MessageHandler, MessageHandlerError};
use crate::soap::{HostMessage, UnicastMessage, WSDMessage, builder};
use crate::span::MakeSpanWithUuid;

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
        Ok(Some(message)) => (
            StatusCode::OK,
            [(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)],
            message,
        )
            .into_response(),
        Ok(None) => (
            StatusCode::ACCEPTED,
            [(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)],
        )
            .into_response(),
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
) -> Result<Option<UnicastMessage>, eyre::Report> {
    let (header, message) = match message_handler.deconstruct_http_message(buffer).await {
        Ok(pieces) => pieces,
        Err(MessageHandlerError::DuplicateMessage) => {
            return Ok(None);
        },
        // a request with a repeated `wsa` header block gets 202 without a body, whatever its action, because WSDAPI returns 202 without a body for such a request
        // the `wsa:InvalidMessageInformationHeader` fault for a repeated `wsa:To`, `wsa:Action` or `wsa:MessageID` is not sent, see documentation/ws-addressing.pdf, 4.1
        // a request with `wsa:RelatesTo` of the type `wsd:Suppression` gets 202 without a body, because FDResPub returns 202 without a body for such a request
        Err(
            error @ MessageHandlerError::HeaderError(
                HeaderParsingError::DuplicateAddressingBlock(_)
                | HeaderParsingError::SuppressionRelatesTo,
            ),
        ) => {
            error.log(buffer);

            return Ok(None);
        },
        Err(error) => {
            error.log(buffer);

            return Err(eyre::Report::msg("Invalid XML"));
        },
    };

    // dispatch based on the SOAP Action header
    let response = match message {
        WSDMessage::HostMessage(HostMessage::Get(_get)) => {
            match header.to.as_ref() {
                Some(to) if to == &config.uuid_as_device_uri => Ok(Some(
                    builder::Builder::build_get_response(config, &header.message_id)?,
                )),
                Some(_) => {
                    // error when `To` doesn't match us
                    // send Error 500
                    // <?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing"><soap:Header><wsa:To>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</wsa:To><wsa:Action>http://schemas.xmlsoap.org/ws/2004/08/addressing/fault</wsa:Action><wsa:MessageID>urn:uuid:8b1ad6d1-d578-49f0-811e-f67fcb6e3bf2</wsa:MessageID><wsa:RelatesTo>urn:uuid:f3448e61-3f8c-4040-9dc3-013ac09f3a77</wsa:RelatesTo></soap:Header><soap:Body><soap:Fault><soap:Code><soap:Value>soap:Sender</soap:Value><soap:Subcode><soap:Value>wsa:DestinationUnreachable</soap:Value></soap:Subcode></soap:Code><soap:Reason><soap:Text xml:lang="en-US">No route can be determined to reach the destination role defined by the WS-Addressing To.</soap:Text></soap:Reason></soap:Fault></soap:Body></soap:Envelope>
                    Err(eyre::Report::msg("Invalid To"))
                },
                None => {
                    // no error when To is missing
                    Ok(None)
                },
            }
        },
        WSDMessage::HostMessage(HostMessage::Probe(probe)) => {
            if probe.matches() {
                return Ok(Some(builder::Builder::build_probe_matches(
                    config,
                    &header.message_id,
                )?));
            }

            event!(
                Level::DEBUG,
                ?probe.types,
                "client requests types we don't offer"
            );

            Ok(None)
        },
        WSDMessage::ClientMessage(_) | WSDMessage::HostMessage(_) => {
            return Err(eyre::Report::msg("Invalid Action"));
        },
    };

    response
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
