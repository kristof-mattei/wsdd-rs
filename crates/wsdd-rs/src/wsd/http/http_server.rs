use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use axum::Router;
use color_eyre::eyre;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::config::Config;
use crate::network_address::NetworkAddress;
use crate::soap::parser::MessageHandler;
use crate::wsd::HANDLED_MESSAGES;
use crate::wsd::http::router::build_router;

pub struct WSDHttpServer {
    _bound_to: NetworkAddress,
    cancellation_token: CancellationToken,
    _config: Arc<Config>,
    handle: tokio::task::JoinHandle<Result<(), eyre::Error>>,
    #[cfg_attr(not(test), expect(unused, reason = "Not needed"))]
    http_bound_to: SocketAddr,
}

impl WSDHttpServer {
    pub async fn init(
        bound_to: NetworkAddress,
        cancellation_token: CancellationToken,
        config: Arc<Config>,
        messages_built: Arc<AtomicU64>,
        http_listen_address: SocketAddr,
    ) -> Result<WSDHttpServer, std::io::Error> {
        let message_handler = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES), bound_to.clone());

        event!(Level::INFO, ?http_listen_address, "Trying to bind");

        let listener = tokio::net::TcpListener::bind(http_listen_address).await?;

        let http_bound_to = listener.local_addr()?;

        event!(Level::INFO, ?listener, "Bound successfully");

        // launch axum server on http_listen_address
        // this will never fail unless shut down
        // see `axum::serve`
        let handle = tokio::task::spawn(launch_http_server(
            cancellation_token.clone(),
            listener,
            build_router(Arc::clone(&config), messages_built, message_handler),
        ));

        Ok(Self {
            _bound_to: bound_to,
            cancellation_token,
            _config: config,
            handle,
            http_bound_to,
        })
    }

    pub async fn teardown(self) {
        self.cancellation_token.cancel();

        let _r = self.handle.await;
    }
}

/// Set up server on a bound listener, with a router, and a cancellation token for graceful shutdown.
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
    use std::sync::atomic::{AtomicU64, Ordering};

    use http::StatusCode;
    use ipnet::IpNet;
    use libc::RT_SCOPE_SITE;
    use pretty_assertions::assert_eq;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::constants;
    use crate::network_address::NetworkAddress;
    use crate::network_interface::NetworkInterface;
    use crate::test_utils::build_config;
    use crate::test_utils::xml::to_string_pretty;
    use crate::wsd::http::http_server::WSDHttpServer;

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn http_server_listens() {
        // host
        let host_ip = Ipv4Addr::LOCALHOST;
        let host_config = Arc::new(build_config(Uuid::now_v7(), "host-instance-id"));
        let host_http_listening_address = SocketAddr::V4(SocketAddrV4::new(host_ip, 0));
        let host_messages_built = Arc::new(AtomicU64::new(0));

        let cancellation_token = CancellationToken::new();

        let http_server = WSDHttpServer::init(
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 8).unwrap(),
                Arc::new(NetworkInterface::new_with_index("lo", RT_SCOPE_SITE, 5)),
            ),
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            host_messages_built,
            host_http_listening_address,
        )
        .await
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
            .header("Content-Type", constants::MIME_TYPE_SOAP_XML)
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
            host_config.uuid_as_device_uri,
            host_config.uuid_as_device_uri,
            host_config.full_hostname
        );

        assert_eq!(
            to_string_pretty(expected_response.as_bytes()).unwrap(),
            to_string_pretty(&response.bytes().await.unwrap()).unwrap()
        );
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
        let host_config = Arc::new(build_config(Uuid::now_v7(), "host-instance-id"));
        let host_http_listening_address = SocketAddr::V4(SocketAddrV4::new(host_ip, 0));
        let host_messages_built = Arc::new(AtomicU64::new(0));

        let cancellation_token = CancellationToken::new();

        let http_server = WSDHttpServer::init(
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 8).unwrap(),
                Arc::new(NetworkInterface::new_with_index("lo", RT_SCOPE_SITE, 5)),
            ),
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            Arc::clone(&host_messages_built),
            host_http_listening_address,
        )
        .await
        .unwrap_or_else(|_| panic!("Failed to launch server on {}", host_http_listening_address));

        let builder = reqwest::ClientBuilder::new()
            .build()
            .unwrap()
            .post(format!(
                "http://{}/{}",
                http_server.http_bound_to, host_config.uuid
            ))
            .header("Content-Type", constants::MIME_TYPE_SOAP_XML)
            .header("User-Agent", "wsdd-rs");

        let response = builder
            .body(probe.to_owned())
            .timeout(host_config.metadata_timeout)
            .send()
            .await
            .unwrap();

        let expected = format!(
            include_str!("../../test/probe-matches-without-xaddrs-template.xml"),
            client_message_id,
            host_config.wsd_instance_id,
            host_messages_built.load(Ordering::Relaxed) - 1,
            host_config.uuid_as_device_uri,
        );

        let response = to_string_pretty(response.bytes().await.unwrap().as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(expected, response);
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
        let host_config = Arc::new(build_config(Uuid::now_v7(), "host-instance-id"));
        let host_http_listening_address = SocketAddr::V4(SocketAddrV4::new(host_ip, 0));
        let host_messages_built = Arc::new(AtomicU64::new(0));

        let cancellation_token = CancellationToken::new();

        let http_server = WSDHttpServer::init(
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 8).unwrap(),
                Arc::new(NetworkInterface::new_with_index("lo", RT_SCOPE_SITE, 5)),
            ),
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            Arc::clone(&host_messages_built),
            host_http_listening_address,
        )
        .await
        .unwrap();

        let builder = reqwest::ClientBuilder::new()
            .build()
            .unwrap()
            .post(format!(
                "http://{}/{}",
                http_server.http_bound_to, host_config.uuid
            ))
            .header("Content-Type", constants::MIME_TYPE_SOAP_XML)
            .header("User-Agent", "wsdd-rs");

        let response = builder
            .body(probe)
            .timeout(host_config.metadata_timeout)
            .send()
            .await
            .unwrap();

        assert_eq!(StatusCode::ACCEPTED, response.status());
        // no content
        assert_eq!(vec![], response.bytes().await.unwrap());
    }
}
