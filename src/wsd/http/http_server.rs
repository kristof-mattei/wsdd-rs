use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::State;
use axum::handler::HandlerWithoutStateExt as _;
use axum::http::HeaderMap;
use axum::response::{AppendHeaders, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Router, debug_handler};
use bytes::Bytes;
use color_eyre::eyre::{self, Context as _};
use http::StatusCode;
use http::header::CONTENT_TYPE;
use tokio_util::sync::CancellationToken;
use tower_http::trace::{DefaultOnRequest, DefaultOnResponse, TraceLayer};
use tracing::{Level, event};
use uuid::fmt::Urn;

use crate::config::Config;
use crate::constants;
use crate::network_address::NetworkAddress;
use crate::soap::builder;
use crate::soap::parser::MessageHandler;
use crate::span::MakeSpanWithUuid;
use crate::wsd::HANDLED_MESSAGES;

#[expect(unused, reason = "WIP")]
pub struct WSDHttpServer {
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    address: NetworkAddress,
}

impl WSDHttpServer {
    pub fn init(
        bound_to: NetworkAddress,
        cancellation_token: CancellationToken,
        config: Arc<Config>,
        http_listen_address: SocketAddr,
    ) -> WSDHttpServer {
        let message_handler = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES), bound_to.clone());

        // launch axum server on http_listen_address
        let _handle = tokio::task::spawn(setup_server(
            cancellation_token.clone(),
            http_listen_address,
            build_router(Arc::clone(&config), message_handler),
        ));

        Self {
            cancellation_token,
            config,
            address: bound_to,
        }
    }
}

fn build_router(config: Arc<Config>, message_handler: MessageHandler) -> Router {
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
        .with_state((config, Arc::new(message_handler)));

    router
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "Hello, world!")
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
    let valid_content_type = headers
        .get(CONTENT_TYPE)
        .and_then(|raw| raw.to_str().ok())
        .is_some_and(|raw| raw.starts_with(constants::MIME_TYPE_SOAP_XML));

    if !valid_content_type {
        return (StatusCode::BAD_REQUEST, "Invalid Content-Type").into_response();
    }

    match build_response(&config, &message_handler, body).await {
        Ok(ok) => (
            StatusCode::OK,
            AppendHeaders([(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)]),
            ok,
        )
            .into_response(),
        Err(error) => {
            event!(Level::ERROR, ?error);
            (StatusCode::BAD_REQUEST).into_response()
        },
    }
}

fn handle_get(config: &Config, relates_to: Urn) -> Result<Vec<u8>, eyre::Report> {
    Ok(builder::Builder::build_get_response(config, relates_to)?)
}

async fn build_response(
    config: &Config,
    message_handler: &MessageHandler,
    buffer: Bytes,
) -> Result<Vec<u8>, eyre::Report> {
    let (header, _body_reader) = match message_handler.deconstruct_message(&buffer, None).await {
        Ok(pieces) => pieces,
        Err(error) => {
            error.log(&buffer);

            return Err(eyre::Report::msg("Invalid XML"));
        },
    };

    if &*header.action != constants::WSD_GET {
        return Err(eyre::Report::msg("Invalid Action"));
    }

    if header.to.as_deref() != Some(&config.uuid_as_urn_str) {
        return Err(eyre::Report::msg("Invalid To"));
    }

    let response = handle_get(config, header.message_id)?;

    Ok(response)
}

/// Set up server on socket, with a router, and a cancellation token for graceful shutdown
///
/// # Errors
/// * Couldn't bind to address
/// * Server failure
pub async fn setup_server(
    token: CancellationToken,
    bind_to: SocketAddr,
    router: Router,
) -> Result<(), eyre::Report> {
    event!(Level::INFO, ?bind_to, "Trying to bind");

    let listener = tokio::net::TcpListener::bind(bind_to)
        .await
        .wrap_err("Failed to bind Webserver to port")?;

    event!(Level::INFO, ?bind_to, "Webserver bound successfully");

    axum::serve(listener, router)
        .with_graceful_shutdown(token.cancelled_owned())
        .await
        .map_err(Into::into)
}
