use std::net::SocketAddr;
use std::sync::Arc;

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
    bound_to: NetworkAddress,
}

impl WSDHttpServer {
    pub async fn init(
        bound_to: NetworkAddress,
        cancellation_token: CancellationToken,
        config: Arc<Config>,
        http_listen_address: SocketAddr,
    ) -> Result<WSDHttpServer, std::io::Error> {
        let message_handler = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES), bound_to.clone());

        event!(Level::INFO, ?http_listen_address, "Trying to bind");

        let listener = tokio::net::TcpListener::bind(http_listen_address).await?;

        event!(Level::INFO, ?listener, "Bound successfully");

        // launch axum server on http_listen_address
        // this will never fail unless shut down
        // see `axum::serve`
        tokio::task::spawn(launch_http_server(
            cancellation_token.clone(),
            listener,
            build_router(Arc::clone(&config), message_handler),
        ));

        Ok(Self {
            cancellation_token,
            config,
            bound_to,
        })
    }

    pub async fn teardown(self, _graceful: bool) {
        self.cancellation_token.cancel();
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
            [(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)],
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

/// Set up server on a bound listener, with a router, and a cancellation token for graceful shutdown
///
/// # Errors
/// * Server failure
pub async fn launch_http_server(
    cancellation_token: CancellationToken,
    listener: tokio::net::TcpListener,
    router: Router,
) -> Result<(), eyre::Report> {
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(cancellation_token.cancelled_owned())
    .await
    .map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use libc::RT_SCOPE_SITE;
    use pretty_assertions::assert_eq;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::constants::MIME_TYPE_SOAP_XML;
    use crate::network_address::NetworkAddress;
    use crate::network_interface::NetworkInterface;
    use crate::test_utils::build_config;
    use crate::test_utils::xml::to_string_pretty;
    use crate::wsd::http::http_server::WSDHttpServer;

    #[tokio::test]
    async fn http_server_listens() {
        // host
        let host_endpoint_uuid = Uuid::new_v4();
        let host_instance_id = "host-instance-id";
        let host_config = Arc::new(build_config(host_endpoint_uuid, host_instance_id));
        let host_ip = Ipv4Addr::LOCALHOST;
        let host_http_listening_address = SocketAddr::V4(SocketAddrV4::new(host_ip, 6000));

        let cancellation_token = CancellationToken::new();

        let _http_server = WSDHttpServer::init(
            NetworkAddress::new(
                host_ip.into(),
                Arc::new(NetworkInterface::new_with_index("lo", RT_SCOPE_SITE, 5)),
            ),
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            host_http_listening_address,
        )
        .await
        .unwrap();

        let body = format!(
            include_str!("../../test/get-template.xml"),
            host_endpoint_uuid,
            Uuid::new_v4()
        );

        let builder = reqwest::ClientBuilder::new()
            .build()
            .unwrap()
            .post(format!(
                "http://{}/{}",
                host_http_listening_address, host_endpoint_uuid
            ))
            .header("Content-Type", MIME_TYPE_SOAP_XML)
            .header("User-Agent", "wsdd-rs");

        let response = builder
            .body(body)
            .timeout(host_config.metadata_timeout)
            .send()
            .await
            .unwrap();

        let expected_response = format!(
            include_str!("../../test/get-response-template.xml"),
            Uuid::nil(),
            Uuid::nil(),
            host_config.hostname,
            host_endpoint_uuid,
            host_endpoint_uuid,
            host_config.full_hostname
        );

        assert_eq!(
            to_string_pretty(expected_response.as_bytes()).unwrap(),
            to_string_pretty(&response.bytes().await.unwrap()).unwrap()
        );
    }
}
