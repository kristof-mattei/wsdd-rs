use std::net::SocketAddr;
use std::num::NonZeroU32;
use std::sync::Arc;

use axum::Router;
use color_eyre::eyre::{self, Context as _};
use socket2::{Domain, Socket, Type};
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::config::Config;
use crate::max_size_deque::MaxSizeDeque;
use crate::network_address::NetworkAddress;
use crate::soap::MessageId;
use crate::soap::parser::MessageHandler;
use crate::wsd::http::router::build_router;

pub(crate) struct WSDHttpServer {
    _bound_to: NetworkAddress,
    cancellation_token: CancellationToken,
    _config: Arc<Config>,
    handle: tokio::task::JoinHandle<Result<(), eyre::Error>>,
    #[cfg_attr(not(test), expect(unused, reason = "Not needed"))]
    http_bound_to: SocketAddr,
}

impl WSDHttpServer {
    pub(crate) fn init(
        bound_to: NetworkAddress,
        cancellation_token: CancellationToken,
        config: Arc<Config>,
        http_listen_address: SocketAddr,
        recent_messages: Arc<RwLock<MaxSizeDeque<MessageId>>>,
    ) -> Result<WSDHttpServer, eyre::Report> {
        let message_handler = MessageHandler::new(bound_to.clone(), recent_messages);

        event!(Level::DEBUG, ?http_listen_address, "Trying to bind");

        let listener = bind_listener(http_listen_address, bound_to.interface.index())?;

        let http_bound_to = listener
            .local_addr()
            .wrap_err("Failed to read the listener's local address")?;

        event!(Level::DEBUG, ?listener, "Bound successfully");

        // launch axum server on http_listen_address
        // this will never fail unless shut down
        // see `axum::serve`
        let handle = tokio::task::spawn(launch_http_server(
            cancellation_token.clone(),
            listener,
            build_router(Arc::clone(&config), message_handler),
        ));

        Ok(Self {
            _bound_to: bound_to,
            cancellation_token,
            _config: config,
            handle,
            http_bound_to,
        })
    }

    #[cfg(test)]
    pub(crate) fn http_bound_to(&self) -> SocketAddr {
        self.http_bound_to
    }

    pub(crate) async fn teardown(self) {
        self.cancellation_token.cancel();

        let _r = self.handle.await;
    }
}

fn bind_listener(
    address: SocketAddr,
    interface_index: u32,
) -> Result<tokio::net::TcpListener, eyre::Report> {
    // mirrors mio's backlog for `tokio::net::TcpListener::bind`, https://github.com/tokio-rs/mio/blob/79d1417c94e3a45c8bdd796e5422e22e8c488086/src/net/tcp/listener.rs#L92
    const LISTEN_BACKLOG: i32 = 128;

    let socket = Socket::new(Domain::for_address(address), Type::STREAM, None)
        .wrap_err("Failed to create the socket")?;

    socket
        .set_nonblocking(true)
        .wrap_err("Failed to set the socket to non-blocking")?;
    socket
        .set_reuse_address(true)
        .wrap_err("Failed to set SO_REUSEADDR")?;

    match address {
        // IPv4 binds have no scope, and another interface can have the same address
        SocketAddr::V4(_) => socket
            .bind_device_by_index_v4(NonZeroU32::new(interface_index))
            .wrap_err_with(|| format!("Failed to bind to interface {}", interface_index))?,
        // the scope id binds the socket to its interface
        SocketAddr::V6(_) => {},
    }

    socket
        .bind(&address.into())
        .wrap_err_with(|| format!("Failed to bind to {}", address))?;
    socket
        .listen(LISTEN_BACKLOG)
        .wrap_err_with(|| format!("Failed to listen on {}", address))?;

    tokio::net::TcpListener::from_std(socket.into())
        .wrap_err("Failed to convert the socket into a `TcpListener`")
}

/// Set up server on a bound listener, with a router, and a cancellation token for graceful shutdown.
///
/// # Errors
/// * Server failure
pub(crate) async fn launch_http_server(
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

    use http::header::{CONNECTION, CONTENT_LENGTH, CONTENT_TYPE, USER_AGENT};
    use http::{HeaderMap, StatusCode};
    use ipnet::IpNet;
    use libc::RT_SCOPE_SITE;
    use pretty_assertions::{assert_eq, assert_matches};
    use tokio::sync::RwLock;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::config::Config;
    use crate::constants::{self, WSD_MAX_KNOWN_MESSAGES};
    use crate::max_size_deque::MaxSizeDeque;
    use crate::network_address::NetworkAddress;
    use crate::network_interface::{NetworkInterface, if_nametoindex};
    use crate::test_utils::xml::to_string_pretty;
    use crate::test_utils::{build_config, find_first_non_lo_network_interface};
    use crate::wsd::http::http_server::{WSDHttpServer, bind_listener};

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn ipv4_listeners_on_different_interfaces_share_an_address() {
        let (_name, index) = find_first_non_lo_network_interface().unwrap();

        let first = bind_listener(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            if_nametoindex("lo").unwrap(),
        )
        .unwrap();

        let second = bind_listener(first.local_addr().unwrap(), index);

        assert_matches!(second, Ok(_));
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn http_server_listens() {
        // host
        let host_ip = Ipv4Addr::LOCALHOST;
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));
        let host_http_listening_address = SocketAddr::V4(SocketAddrV4::new(host_ip, 0));

        let cancellation_token = CancellationToken::new();

        let http_server = WSDHttpServer::init(
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 8).unwrap(),
                Arc::new(NetworkInterface::new_with_index(
                    "lo",
                    RT_SCOPE_SITE,
                    if_nametoindex("lo").unwrap(),
                )),
            ),
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            host_http_listening_address,
            Arc::new(RwLock::new(MaxSizeDeque::new(WSD_MAX_KNOWN_MESSAGES))),
        )
        .unwrap();

        let body = format!(
            include_str!("../../test/get-template.xml"),
            host_config.uuid_as_device_uri,
            Uuid::now_v7()
        );

        let builder = reqwest::ClientBuilder::new()
            .build()
            .unwrap()
            .post(format!(
                "http://{}/{}",
                http_server.http_bound_to, host_config.uuid
            ))
            .header(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)
            .header(USER_AGENT, "wsdd-rs");

        let response = builder
            .body(body)
            .timeout(host_config.metadata_timeout)
            .send()
            .await
            .unwrap();

        let expected_response = format!(
            include_str!("../../test/get-response-template.xml"),
            Uuid::nil(),
            Uuid::nil().urn(),
            host_config.hostname,
            host_config.uuid_as_device_uri,
            host_config.uuid_as_device_uri,
            host_config.full_hostname
        );

        assert_eq!(
            to_string_pretty(&response.bytes().await.unwrap()).unwrap(),
            to_string_pretty(expected_response.as_bytes()).unwrap()
        );
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn drops_duplicate_get() {
        // host
        let host_ip = Ipv4Addr::LOCALHOST;
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));
        let host_http_listening_address = SocketAddr::V4(SocketAddrV4::new(host_ip, 0));

        let cancellation_token = CancellationToken::new();

        let http_server = WSDHttpServer::init(
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 8).unwrap(),
                Arc::new(NetworkInterface::new_with_index(
                    "lo",
                    RT_SCOPE_SITE,
                    if_nametoindex("lo").unwrap(),
                )),
            ),
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            host_http_listening_address,
            Arc::new(RwLock::new(MaxSizeDeque::new(WSD_MAX_KNOWN_MESSAGES))),
        )
        .unwrap();

        // the template's MessageID is fixed, so the same body twice is a duplicate
        let body = format!(
            include_str!("../../test/get-template.xml"),
            host_config.uuid_as_device_uri,
            Uuid::now_v7()
        );

        let client = reqwest::ClientBuilder::new().build().unwrap();

        let url = format!("http://{}/{}", http_server.http_bound_to, host_config.uuid);

        let first = client
            .post(&url)
            .header(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)
            .header(USER_AGENT, "wsdd-rs")
            .body(body.clone())
            .timeout(host_config.metadata_timeout)
            .send()
            .await
            .unwrap();

        assert_eq!(first.status(), StatusCode::OK);

        let second = client
            .post(&url)
            .header(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)
            .header(USER_AGENT, "wsdd-rs")
            .body(body)
            .timeout(host_config.metadata_timeout)
            .send()
            .await
            .unwrap();

        assert_eq!(second.status(), StatusCode::ACCEPTED);
        // no content
        assert_eq!(second.bytes().await.unwrap(), vec![]);
    }

    const MESSAGE_ID: &str = "urn:uuid:00000000-0000-0000-0000-000000000001";

    fn to_block(address: &str) -> String {
        format!("<wsa:To>{}</wsa:To>", address)
    }

    fn message_id_block() -> String {
        format!("<wsa:MessageID>{}</wsa:MessageID>", MESSAGE_ID)
    }

    fn reply_to_block(address: &str) -> String {
        format!(
            "<wsa:ReplyTo><wsa:Address>{}</wsa:Address></wsa:ReplyTo>",
            address
        )
    }

    fn relates_to_block() -> String {
        format!("<wsa:RelatesTo>{}</wsa:RelatesTo>", Uuid::now_v7().urn())
    }

    fn relates_to_block_with_type(relationship_type: &str) -> String {
        format!(
            r#"<wsa:RelatesTo xmlns:x="urn:x" RelationshipType="{}">{}</wsa:RelatesTo>"#,
            relationship_type,
            Uuid::now_v7().urn()
        )
    }

    /// An envelope with `header` as the content of `soap:Header` and `body` as the content of `soap:Body`.
    fn envelope(header: &str, body: &str) -> String {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="{}" xmlns:wsa="{}" xmlns:wsd="{}"><soap:Header>{}</soap:Header><soap:Body>{}</soap:Body></soap:Envelope>"#,
            constants::XML_SOAP_NAMESPACE,
            constants::XML_WSA_NAMESPACE,
            constants::XML_WSD_NAMESPACE,
            header,
            body
        )
    }

    fn request(action: &str, blocks: &[String], body: &str) -> String {
        envelope(
            &format!("<wsa:Action>{}</wsa:Action>{}", action, blocks.concat()),
            body,
        )
    }

    /// A Get with every header block that its answer requires.
    fn valid_get_blocks(config: &Config) -> [String; 3] {
        [
            to_block(config.uuid_as_device_uri.as_ref()),
            message_id_block(),
            reply_to_block(constants::WSA_ANON),
        ]
    }

    /// A Get with every header block that its answer requires, and `relates_to`.
    fn get_with_relates_to(config: &Config, relates_to: String) -> String {
        let mut blocks = valid_get_blocks(config).to_vec();

        blocks.push(relates_to);

        request(constants::WSD_GET, &blocks, "")
    }

    /// A Probe for any type with `relates_to`.
    fn probe_with_relates_to(relates_to: &[String]) -> String {
        let mut blocks = vec![to_block(constants::WSA_DISCOVERY), message_id_block()];

        blocks.extend_from_slice(relates_to);

        request(constants::WSD_PROBE, &blocks, "<wsd:Probe />")
    }

    /// A fault with the `wsa:MessageID` of the builder in tests.
    fn expected_fault(
        extra_headers: &str,
        code: &str,
        subcode: Option<&str>,
        reason: &str,
        relates_to: Option<&str>,
    ) -> String {
        format!(
            r#"<?xml version="1.0" encoding="utf-8"?><soap:Envelope xmlns:soap="{}" xmlns:wsa="{}"><soap:Header><wsa:To>{}</wsa:To><wsa:Action>{}</wsa:Action><wsa:MessageID>{}</wsa:MessageID>{}{}</soap:Header><soap:Body><soap:Fault><soap:Code><soap:Value>{}</soap:Value>{}</soap:Code><soap:Reason><soap:Text xml:lang="en-US">{}</soap:Text></soap:Reason></soap:Fault></soap:Body></soap:Envelope>"#,
            constants::XML_SOAP_NAMESPACE,
            constants::XML_WSA_NAMESPACE,
            constants::WSA_ANON,
            constants::WSA_FAULT,
            Uuid::nil().urn(),
            relates_to.map_or_default(|relates_to| format!(
                "<wsa:RelatesTo>{}</wsa:RelatesTo>",
                relates_to
            )),
            extra_headers,
            code,
            subcode.map_or_default(|subcode| format!(
                "<soap:Subcode><soap:Value>{}</soap:Value></soap:Subcode>",
                subcode
            )),
            reason
        )
    }

    fn version_mismatch() -> String {
        expected_fault(
            r#"<soap:Upgrade><soap:SupportedEnvelope qname="soap:Envelope" /></soap:Upgrade>"#,
            "soap:VersionMismatch",
            None,
            "Version Mismatch",
            None,
        )
    }

    fn sender(relates_to: Option<&str>) -> String {
        expected_fault(
            "",
            "soap:Sender",
            None,
            "The message is not valid.",
            relates_to,
        )
    }

    fn invalid_message_information_header(relates_to: Option<&str>) -> String {
        expected_fault(
            "",
            "soap:Sender",
            Some("wsa:InvalidMessageInformationHeader"),
            "A message information header is not valid and the message cannot be processed.",
            relates_to,
        )
    }

    fn message_information_header_required(relates_to: Option<&str>) -> String {
        expected_fault(
            "",
            "soap:Sender",
            Some("wsa:MessageInformationHeaderRequired"),
            "A required message information header, To, MessageID, or Action, is not present.",
            relates_to,
        )
    }

    fn destination_unreachable(relates_to: Option<&str>) -> String {
        expected_fault(
            "",
            "soap:Sender",
            Some("wsa:DestinationUnreachable"),
            "No route can be determined to reach the destination role defined by the WS-Addressing To.",
            relates_to,
        )
    }

    fn endpoint_unavailable(relates_to: Option<&str>) -> String {
        expected_fault(
            "",
            "soap:Receiver",
            Some("wsa:EndpointUnavailable"),
            "The endpoint is unable to process the message at this time",
            relates_to,
        )
    }

    /// Starts a host and POSTs the request that `body` builds for its config.
    async fn post<B>(body: B) -> (StatusCode, HeaderMap, Vec<u8>)
    where
        B: FnOnce(&Config) -> String,
    {
        let host_ip = Ipv4Addr::LOCALHOST;
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let http_server = WSDHttpServer::init(
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 8).unwrap(),
                Arc::new(NetworkInterface::new_with_index(
                    "lo",
                    RT_SCOPE_SITE,
                    if_nametoindex("lo").unwrap(),
                )),
            ),
            CancellationToken::new(),
            Arc::clone(&host_config),
            SocketAddr::V4(SocketAddrV4::new(host_ip, 0)),
            Arc::new(RwLock::new(MaxSizeDeque::new(WSD_MAX_KNOWN_MESSAGES))),
        )
        .unwrap();

        let response = reqwest::ClientBuilder::new()
            .build()
            .unwrap()
            .post(format!(
                "http://{}/{}",
                http_server.http_bound_to, host_config.uuid
            ))
            .header(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)
            .header(USER_AGENT, "wsdd-rs")
            .body(body(&host_config))
            .timeout(host_config.metadata_timeout)
            .send()
            .await
            .unwrap();

        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await.unwrap().to_vec();

        http_server.teardown().await;

        (status, headers, body)
    }

    async fn assert_fault<B>(body: B, expected_status: StatusCode, expected: &str)
    where
        B: FnOnce(&Config) -> String,
    {
        let (status, headers, body) = post(body).await;

        assert_eq!(status, expected_status);
        assert_eq!(
            headers.get(CONTENT_TYPE).unwrap(),
            constants::MIME_TYPE_SOAP_XML
        );
        assert_eq!(
            to_string_pretty(&body).unwrap(),
            to_string_pretty(expected.as_bytes()).unwrap()
        );
    }

    async fn assert_not_well_formed<B>(body: B)
    where
        B: FnOnce(&Config) -> String,
    {
        let (status, headers, body) = post(body).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(headers.get(CONTENT_TYPE), None);
        assert_eq!(body, Vec::<u8>::new());
    }

    async fn assert_status<B>(body: B, expected_status: StatusCode)
    where
        B: FnOnce(&Config) -> String,
    {
        let (status, _, _) = post(body).await;

        assert_eq!(status, expected_status);
    }

    /// Asserts `wsa:InvalidMessageInformationHeader` for the request that `body` builds, with `extra_blocks` at the end of its header.
    async fn assert_repeated_block_fault<B, E>(body: B, extra_blocks: E)
    where
        B: FnOnce(&Config) -> String,
        E: FnOnce(&Config) -> String,
    {
        assert_fault(
            |config| {
                body(config).replace(
                    "</soap:Header>",
                    &format!("{}</soap:Header>", extra_blocks(config)),
                )
            },
            StatusCode::BAD_REQUEST,
            &invalid_message_information_header(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_repeated_to_with_invalid_message_information_header() {
        assert_repeated_block_fault(get_body, |config| {
            to_block(config.uuid_as_device_uri.as_ref())
        })
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_repeated_action_with_invalid_message_information_header() {
        assert_repeated_block_fault(get_body, |_| {
            format!("<wsa:Action>{}</wsa:Action>", constants::WSD_GET)
        })
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_repeated_message_id_with_invalid_message_information_header() {
        assert_repeated_block_fault(get_body, |_| {
            format!("<wsa:MessageID>{}</wsa:MessageID>", Uuid::now_v7().urn())
        })
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_repeated_reply_to_with_invalid_message_information_header() {
        assert_repeated_block_fault(get_body, |_| reply_to_block(constants::WSA_ANON)).await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn drops_get_with_repeated_relates_to() {
        assert_status(
            |config| {
                let relates_to = relates_to_block();

                get_with_relates_to(config, format!("{}{}", relates_to, relates_to))
            },
            StatusCode::ACCEPTED,
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_probe_with_repeated_message_id_with_invalid_message_information_header() {
        let message_id = Uuid::now_v7();

        assert_repeated_block_fault(
            |_| {
                format!(
                    include_str!("../../test/probe-template-no-types.xml"),
                    message_id
                )
            },
            |_| format!("<wsa:MessageID>{}</wsa:MessageID>", message_id.urn()),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_relationship_type_of_undeclared_prefix_with_invalid_message_information_header()
     {
        assert_fault(
            |config| get_with_relates_to(config, relates_to_block_with_type("y:Other")),
            StatusCode::BAD_REQUEST,
            &invalid_message_information_header(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_relates_to_with_destination_unreachable() {
        assert_fault(
            |config| get_with_relates_to(config, relates_to_block()),
            StatusCode::INTERNAL_SERVER_ERROR,
            &destination_unreachable(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn drops_get_with_suppression_relates_to() {
        assert_status(
            |config| get_with_relates_to(config, relates_to_block_with_type("wsd:Suppression")),
            StatusCode::ACCEPTED,
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_probe_with_relates_to_with_probe_matches() {
        assert_status(
            |_| probe_with_relates_to(&[relates_to_block()]),
            StatusCode::OK,
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn drops_probe_with_two_relates_to() {
        assert_status(
            |_| probe_with_relates_to(&[relates_to_block(), relates_to_block()]),
            StatusCode::ACCEPTED,
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn drops_probe_with_suppression_relates_to() {
        assert_status(
            |_| probe_with_relates_to(&[relates_to_block_with_type("wsd:Suppression")]),
            StatusCode::ACCEPTED,
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_probe_with_other_relates_to_with_destination_unreachable() {
        assert_fault(
            |_| probe_with_relates_to(&[relates_to_block_with_type("x:Other")]),
            StatusCode::INTERNAL_SERVER_ERROR,
            &destination_unreachable(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_to_another_address_with_destination_unreachable() {
        assert_fault(
            |_| {
                request(
                    constants::WSD_GET,
                    &[
                        to_block(&Uuid::now_v7().urn().to_string()),
                        message_id_block(),
                        reply_to_block(constants::WSA_ANON),
                    ],
                    "",
                )
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            &destination_unreachable(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn rejects_get_to_another_address_with_malformed_body() {
        assert_not_well_formed(|_| {
            request(
                constants::WSD_GET,
                &[
                    to_block(&Uuid::now_v7().urn().to_string()),
                    message_id_block(),
                    reply_to_block(constants::WSA_ANON),
                ],
                r#"<x:a xmlns:x="urn:x"></x:b>"#,
            )
        })
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn rejects_get_with_malformed_body() {
        assert_not_well_formed(|config| {
            request(
                constants::WSD_GET,
                &valid_get_blocks(config),
                r#"<x:a xmlns:x="urn:x"></x:b>"#,
            )
        })
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn rejects_truncated_get() {
        assert_not_well_formed(|config| {
            let get = request(constants::WSD_GET, &valid_get_blocks(config), "");

            get.strip_suffix("</soap:Envelope>").unwrap().to_owned()
        })
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn rejects_get_with_text_after_envelope() {
        assert_not_well_formed(|config| {
            format!(
                "{}x",
                request(constants::WSD_GET, &valid_get_blocks(config), "")
            )
        })
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn rejects_get_with_element_after_envelope() {
        assert_not_well_formed(|config| {
            format!(
                "{}<x />",
                request(constants::WSD_GET, &valid_get_blocks(config), "")
            )
        })
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_soap_11_envelope_with_version_mismatch() {
        assert_fault(
            |config| {
                request(constants::WSD_GET, &valid_get_blocks(config), "").replace(
                    constants::XML_SOAP_NAMESPACE,
                    "http://schemas.xmlsoap.org/soap/envelope/",
                )
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            &version_mismatch(),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_request_without_action_with_message_information_header_required() {
        assert_fault(
            |config| {
                envelope(
                    &[
                        to_block(config.uuid_as_device_uri.as_ref()),
                        message_id_block(),
                        reply_to_block(constants::WSA_ANON),
                    ]
                    .concat(),
                    "",
                )
            },
            StatusCode::BAD_REQUEST,
            &message_information_header_required(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_request_without_header_with_message_information_header_required() {
        assert_fault(
            |_| {
                format!(
                    r#"<soap:Envelope xmlns:soap="{}"><soap:Body /></soap:Envelope>"#,
                    constants::XML_SOAP_NAMESPACE
                )
            },
            StatusCode::BAD_REQUEST,
            &message_information_header_required(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_without_body_with_sender() {
        assert_fault(
            |config| {
                request(constants::WSD_GET, &valid_get_blocks(config), "")
                    .replace("<soap:Body></soap:Body>", "")
            },
            StatusCode::BAD_REQUEST,
            &sender(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_second_header_with_sender() {
        assert_fault(
            |config| {
                request(constants::WSD_GET, &valid_get_blocks(config), "").replace(
                    "</soap:Header>",
                    "</soap:Header><soap:Header></soap:Header>",
                )
            },
            StatusCode::BAD_REQUEST,
            &sender(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_unknown_envelope_child_with_sender() {
        assert_fault(
            |config| {
                request(constants::WSD_GET, &valid_get_blocks(config), "").replace(
                    "</soap:Header>",
                    r#"</soap:Header><x:Extra xmlns:x="urn:x" />"#,
                )
            },
            StatusCode::BAD_REQUEST,
            &sender(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_two_app_sequences_with_sender() {
        assert_fault(
            |config| {
                let app_sequence = r#"<wsd:AppSequence InstanceId="1" MessageNumber="1" />"#;
                let mut blocks = valid_get_blocks(config).to_vec();

                blocks.push(app_sequence.to_owned());
                blocks.push(app_sequence.to_owned());

                request(constants::WSD_GET, &blocks, "")
            },
            StatusCode::BAD_REQUEST,
            &sender(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_probe_with_invalid_types_with_sender() {
        assert_fault(
            |_| {
                request(
                    constants::WSD_PROBE,
                    &[
                        to_block(constants::WSA_DISCOVERY),
                        message_id_block(),
                        reply_to_block(constants::WSA_ANON),
                    ],
                    "<wsd:Probe><wsd:Types>y:Thing</wsd:Types></wsd:Probe>",
                )
            },
            StatusCode::BAD_REQUEST,
            &sender(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_reply_to_without_message_id_with_message_information_header_required()
    {
        assert_fault(
            |config| {
                request(
                    constants::WSD_GET,
                    &[
                        to_block(config.uuid_as_device_uri.as_ref()),
                        reply_to_block(constants::WSA_ANON),
                    ],
                    "",
                )
            },
            StatusCode::BAD_REQUEST,
            &message_information_header_required(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_another_reply_to_with_invalid_message_information_header() {
        assert_fault(
            |config| {
                request(
                    constants::WSD_GET,
                    &[
                        to_block(config.uuid_as_device_uri.as_ref()),
                        message_id_block(),
                        reply_to_block("http://192.0.2.1:5357/reply"),
                    ],
                    "",
                )
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            &invalid_message_information_header(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_without_reply_to_with_endpoint_unavailable() {
        assert_fault(
            |config| {
                request(
                    constants::WSD_GET,
                    &[
                        to_block(config.uuid_as_device_uri.as_ref()),
                        message_id_block(),
                    ],
                    "",
                )
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            &endpoint_unavailable(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_without_reply_to_and_message_id_with_message_information_header_required()
    {
        assert_fault(
            |config| {
                request(
                    constants::WSD_GET,
                    &[to_block(config.uuid_as_device_uri.as_ref())],
                    "",
                )
            },
            StatusCode::BAD_REQUEST,
            &message_information_header_required(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_with_reply_to_without_address_with_invalid_message_information_header() {
        assert_fault(
            |config| {
                request(
                    constants::WSD_GET,
                    &[
                        to_block(config.uuid_as_device_uri.as_ref()),
                        message_id_block(),
                        "<wsa:ReplyTo><wsa:ReferenceParameters /></wsa:ReplyTo>".to_owned(),
                    ],
                    "",
                )
            },
            StatusCode::BAD_REQUEST,
            &invalid_message_information_header(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_get_without_to_with_message_information_header_required() {
        assert_fault(
            |_| {
                request(
                    constants::WSD_GET,
                    &[message_id_block(), reply_to_block(constants::WSA_ANON)],
                    "",
                )
            },
            StatusCode::BAD_REQUEST,
            &message_information_header_required(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_probe_with_another_reply_to_with_invalid_message_information_header() {
        assert_fault(
            |_| {
                request(
                    constants::WSD_PROBE,
                    &[
                        to_block(constants::WSA_DISCOVERY),
                        message_id_block(),
                        reply_to_block("http://192.0.2.1:5357/reply"),
                    ],
                    "<wsd:Probe />",
                )
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            &invalid_message_information_header(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_probe_with_reply_to_without_message_id_with_message_information_header_required()
     {
        assert_fault(
            |_| {
                request(
                    constants::WSD_PROBE,
                    &[
                        to_block(constants::WSA_DISCOVERY),
                        reply_to_block(constants::WSA_ANON),
                    ],
                    "<wsd:Probe />",
                )
            },
            StatusCode::BAD_REQUEST,
            &message_information_header_required(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_probe_without_message_id_with_message_information_header_required() {
        assert_fault(
            |_| {
                request(
                    constants::WSD_PROBE,
                    &[to_block(constants::WSA_DISCOVERY)],
                    "<wsd:Probe />",
                )
            },
            StatusCode::BAD_REQUEST,
            &message_information_header_required(None),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_probe_with_reply_to_without_address_with_invalid_message_information_header() {
        assert_fault(
            |_| {
                request(
                    constants::WSD_PROBE,
                    &[
                        to_block(constants::WSA_DISCOVERY),
                        message_id_block(),
                        "<wsa:ReplyTo><wsa:ReferenceParameters /></wsa:ReplyTo>".to_owned(),
                    ],
                    "<wsd:Probe />",
                )
            },
            StatusCode::BAD_REQUEST,
            &invalid_message_information_header(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn rejects_get_with_another_reply_to_and_malformed_body() {
        assert_not_well_formed(|config| {
            request(
                constants::WSD_GET,
                &[
                    to_block(config.uuid_as_device_uri.as_ref()),
                    message_id_block(),
                    reply_to_block("http://192.0.2.1:5357/reply"),
                ],
                r#"<x:a xmlns:x="urn:x"></x:b>"#,
            )
        })
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_hello_with_destination_unreachable_before_reading_its_body() {
        // the Hello has no `wsd:AppSequence` and no body
        assert_fault(
            |_| {
                request(
                    constants::WSD_HELLO,
                    &[
                        to_block(constants::WSA_DISCOVERY),
                        message_id_block(),
                        reply_to_block(constants::WSA_ANON),
                    ],
                    "",
                )
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            &destination_unreachable(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_unknown_action_with_destination_unreachable() {
        assert_fault(
            |config| {
                request(
                    "urn:x:Unknown",
                    &[
                        to_block(config.uuid_as_device_uri.as_ref()),
                        message_id_block(),
                        reply_to_block(constants::WSA_ANON),
                    ],
                    "",
                )
            },
            StatusCode::INTERNAL_SERVER_ERROR,
            &destination_unreachable(Some(MESSAGE_ID)),
        )
        .await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn answers_unknown_action_with_reply_to_without_message_id_with_message_information_header_required()
     {
        assert_fault(
            |config| {
                request(
                    "urn:x:Unknown",
                    &[
                        to_block(config.uuid_as_device_uri.as_ref()),
                        reply_to_block(constants::WSA_ANON),
                    ],
                    "",
                )
            },
            StatusCode::BAD_REQUEST,
            &message_information_header_required(None),
        )
        .await;
    }

    fn get_body(config: &Config) -> String {
        format!(
            include_str!("../../test/get-template.xml"),
            config.uuid_as_device_uri,
            Uuid::now_v7()
        )
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_probe_wsdp_device() {
        let client_message_id = Uuid::now_v7();
        let probe = format!(
            include_str!("../../test/probe-template-wsdp-device.xml"),
            client_message_id
        );

        handles_probe_generic(client_message_id, &probe).await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_probe_pub_computer() {
        // client
        let client_message_id = Uuid::now_v7();
        let probe = format!(
            include_str!("../../test/probe-template-pub-computer.xml"),
            client_message_id
        );

        handles_probe_generic(client_message_id, &probe).await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_probe_no_types() {
        let client_message_id = Uuid::now_v7();
        let probe = format!(
            include_str!("../../test/probe-template-no-types.xml"),
            client_message_id
        );

        handles_probe_generic(client_message_id, &probe).await;
    }

    async fn handles_probe_generic(client_message_id: Uuid, probe: &str) {
        // host
        let host_ip = Ipv4Addr::LOCALHOST;
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));
        let host_http_listening_address = SocketAddr::V4(SocketAddrV4::new(host_ip, 0));

        let cancellation_token = CancellationToken::new();

        let http_server = WSDHttpServer::init(
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 8).unwrap(),
                Arc::new(NetworkInterface::new_with_index(
                    "lo",
                    RT_SCOPE_SITE,
                    if_nametoindex("lo").unwrap(),
                )),
            ),
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            host_http_listening_address,
            Arc::new(RwLock::new(MaxSizeDeque::new(WSD_MAX_KNOWN_MESSAGES))),
        )
        .unwrap_or_else(|_| panic!("Failed to launch server on {}", host_http_listening_address));

        let builder = reqwest::ClientBuilder::new()
            .build()
            .unwrap()
            .post(format!(
                "http://{}/{}",
                http_server.http_bound_to, host_config.uuid
            ))
            .header(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)
            .header(USER_AGENT, "wsdd-rs");

        let response = builder
            .body(probe.to_owned())
            .timeout(host_config.metadata_timeout)
            .send()
            .await
            .unwrap();

        let expected_message_number = 0_usize;

        let expected = format!(
            include_str!("../../test/probe-matches-without-xaddrs-template.xml"),
            client_message_id.urn(),
            host_config.app_sequence.instance_id(),
            expected_message_number,
            host_config.uuid_as_device_uri,
            host_config.app_sequence.instance_id(),
        );

        let response = to_string_pretty(response.bytes().await.unwrap().as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_probe_non_matching_type() {
        let client_message_id = Uuid::now_v7();
        let probe = format!(
            include_str!("../../test/probe-template-non-matching-type.xml"),
            client_message_id
        );

        // host
        let host_ip = Ipv4Addr::LOCALHOST;
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));
        let host_http_listening_address = SocketAddr::V4(SocketAddrV4::new(host_ip, 0));

        let cancellation_token = CancellationToken::new();

        let http_server = WSDHttpServer::init(
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 8).unwrap(),
                Arc::new(NetworkInterface::new_with_index(
                    "lo",
                    RT_SCOPE_SITE,
                    if_nametoindex("lo").unwrap(),
                )),
            ),
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            host_http_listening_address,
            Arc::new(RwLock::new(MaxSizeDeque::new(WSD_MAX_KNOWN_MESSAGES))),
        )
        .unwrap();

        let builder = reqwest::ClientBuilder::new()
            .build()
            .unwrap()
            .post(format!(
                "http://{}/{}",
                http_server.http_bound_to, host_config.uuid
            ))
            .header(CONTENT_TYPE, constants::MIME_TYPE_SOAP_XML)
            .header(USER_AGENT, "wsdd-rs");

        let response = builder
            .body(probe)
            .timeout(host_config.metadata_timeout)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::ACCEPTED);
        // no content
        assert_eq!(response.bytes().await.unwrap(), vec![]);
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn rejects_request_with_another_content_type() {
        // host
        let host_ip = Ipv4Addr::LOCALHOST;
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));
        let host_http_listening_address = SocketAddr::V4(SocketAddrV4::new(host_ip, 0));

        let cancellation_token = CancellationToken::new();

        let http_server = WSDHttpServer::init(
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 8).unwrap(),
                Arc::new(NetworkInterface::new_with_index(
                    "lo",
                    RT_SCOPE_SITE,
                    if_nametoindex("lo").unwrap(),
                )),
            ),
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            host_http_listening_address,
            Arc::new(RwLock::new(MaxSizeDeque::new(WSD_MAX_KNOWN_MESSAGES))),
        )
        .unwrap();

        let response = reqwest::ClientBuilder::new()
            .build()
            .unwrap()
            .post(format!(
                "http://{}/{}",
                http_server.http_bound_to, host_config.uuid
            ))
            .header(CONTENT_TYPE, "text/xml; charset=utf-8")
            .header(USER_AGENT, "wsdd-rs")
            .body(get_body(&host_config))
            .timeout(host_config.metadata_timeout)
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(response.headers().get(CONNECTION), None);
        assert_eq!(response.headers().get(CONTENT_TYPE), None);
        assert_eq!(response.headers().get(CONTENT_LENGTH).unwrap(), "0");
        // no content
        assert_eq!(response.bytes().await.unwrap(), vec![]);
    }
}
