use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use axum::extract::State;
use axum::handler::HandlerWithoutStateExt as _;
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, debug_handler};
use bytes::Bytes;
use color_eyre::eyre;
use http::StatusCode;
use http::header::CONTENT_TYPE;
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{Level, event};

use crate::config::Config;
use crate::constants;
use crate::soap::parser::{MessageHandler, deconstruct_http_message};
use crate::soap::{HostMessage, UnicastMessage, WSDMessage, builder};
use crate::span::MakeSpanWithUuid;

pub fn build_router(
    config: Arc<Config>,
    messages_built: Arc<AtomicU64>,
    message_handler: MessageHandler,
) -> Router {
    let post_path = format!("/{}", config.uuid);

    let router = Router::new()
        .route(&post_path, post(handle_post))
        .fallback_service(handler_404.into_service())
        .route("/healthz", get(healthz))
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(MakeSpanWithUuid::new().level(Level::INFO))
                .on_request(DefaultOnRequest::new().level(Level::TRACE))
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .with_state((config, messages_built, Arc::new(message_handler)));

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
    State((config, messages_built, message_handler)): State<(
        Arc<Config>,
        Arc<AtomicU64>,
        Arc<MessageHandler>,
    )>,
    body: Bytes,
) -> Response {
    let valid_content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|raw| raw.to_str().ok())
        .is_some_and(|raw| raw.starts_with(constants::MIME_TYPE_SOAP_XML));

    if !valid_content_type {
        return (StatusCode::BAD_REQUEST, "Invalid Content-Type").into_response();
    }

    match build_response(&config, &message_handler, &body, &messages_built).await {
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

async fn build_response(
    config: &Config,
    message_handler: &MessageHandler,
    buffer: &[u8],
    messages_built: &AtomicU64,
) -> Result<Option<UnicastMessage>, eyre::Report> {
    let (header, message) = match deconstruct_http_message(buffer) {
        Ok(pieces) => pieces,
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
                    builder::Builder::build_get_response(config, header.message_id)?,
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
            // only the probe one is checked for duplicates
            if message_handler.is_duplicated_msg(header.message_id).await {
                event!(
                    Level::DEBUG,
                    message_id = %header.message_id,
                    "known message: dropping it",
                );

                return Ok(None);
            }

            if probe.types.is_empty() || probe.requested_type_match() {
                return Ok(Some(builder::Builder::build_probe_matches(
                    config,
                    messages_built,
                    header.message_id,
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
