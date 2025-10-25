use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use color_eyre::eyre;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use uuid::fmt::Urn;
use xml::EventReader;

use super::HANDLED_MESSAGES;
use crate::config::Config;
use crate::constants;
use crate::network_address::NetworkAddress;
use crate::soap::builder::{self, Builder, MessageType};
use crate::soap::parser::{self, MessageHandler};
use crate::utils::task::spawn_with_name;

/// handles WSD requests coming from UDP datagrams.
pub struct WSDHost {
    address: IpAddr,
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    messages_built: Arc<AtomicU64>,
    mc_local_port_tx: Sender<Box<[u8]>>,
}

impl WSDHost {
    pub fn init(
        cancellation_token: &CancellationToken,
        config: Arc<Config>,
        messages_built: Arc<AtomicU64>,
        network_address: NetworkAddress,
        mc_wsd_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
        mc_local_port_tx: Sender<Box<[u8]>>,
        uc_wsd_port_tx: Sender<(SocketAddr, Box<[u8]>)>,
    ) -> Self {
        let cancellation_token = cancellation_token.child_token();

        let address = network_address.address;

        spawn_rx_loop(
            cancellation_token.clone(),
            Arc::clone(&config),
            Arc::clone(&messages_built),
            network_address,
            mc_wsd_port_rx,
            uc_wsd_port_tx,
        );

        let host = Self {
            address,
            cancellation_token,
            config,
            messages_built,
            mc_local_port_tx,
        };

        host.schedule_send_hello();

        host
    }

    // or async drop if you will?
    pub async fn teardown(self, graceful: bool) {
        // this makes us stop listeneng for probes & resolves
        // note that this is a child token, so we only cancel ourselves
        self.cancellation_token.cancel();

        if graceful && let Err(error) = self.send_bye(&self.messages_built).await {
            event!(Level::DEBUG, ?error, "Failed to schedule bye message");
        }
    }

    // WS-Discovery, Section 4.1, Hello message
    fn schedule_send_hello(&self) {
        let config = Arc::clone(&self.config);
        let address = self.address;
        let messages_built = Arc::clone(&self.messages_built);
        let mc_local_port_tx = self.mc_local_port_tx.clone();

        tokio::task::spawn(async move {
            // avoid packet storm when hosts come up by delaying initial hello
            tokio::time::sleep(Duration::from_millis(rand::random_range(
                0..=constants::APP_MAX_DELAY,
            )))
            .await;

            if let Err(error) =
                send_hello(&config, address, &messages_built, &mc_local_port_tx).await
            {
                // TODO is this fatal? What should we do?
                event!(Level::ERROR, ?error, "Failed to send hello");
            }
        });
    }

    /// WS-Discovery, Section 4.2, Bye message
    async fn send_bye(&self, messages_built: &AtomicU64) -> Result<(), eyre::Report> {
        let bye = Builder::build_bye(&self.config, messages_built)?;

        // deviation, we can't write that we're scheduling it with the same data, as we don't have the knowledge
        // TODO move event to here and write properly
        event!(Level::INFO, "scheduling {} message", MessageType::Bye);

        Ok(self.mc_local_port_tx.send(bye.into_boxed_slice()).await?)
    }
}

async fn send_hello(
    config: &Config,
    address: IpAddr,
    messages_built: &AtomicU64,
    mc_local_port_tx: &Sender<Box<[u8]>>,
) -> Result<(), eyre::Report> {
    let hello = Builder::build_hello(config, messages_built, address)?;

    // deviation, we can't write that we're scheduling it with the same data, as we don't have the knowledge
    // TODO move event to here and write properly
    event!(Level::INFO, "scheduling {} message", MessageType::Hello);

    mc_local_port_tx.send(hello.into_boxed_slice()).await?;

    Ok(())
}

fn handle_probe(
    config: &Config,
    messages_built: &AtomicU64,
    relates_to: Urn,
    mut reader: EventReader<BufReader<&[u8]>>,
) -> Result<Vec<u8>, eyre::Report> {
    parser::probe::parse_probe_body(&mut reader)?;

    Ok(builder::Builder::build_probe_matches(
        config,
        messages_built,
        relates_to,
    )?)
}

fn handle_resolve(
    config: &Config,
    address: IpAddr,
    messages_built: &AtomicU64,
    target_uuid: uuid::Uuid,
    relates_to: Urn,
    mut reader: EventReader<BufReader<&[u8]>>,
) -> Result<Vec<u8>, eyre::Report> {
    parser::resolve::parse_resolve_body(&mut reader, target_uuid)?;

    Ok(builder::Builder::build_resolve_matches(
        config,
        address,
        messages_built,
        relates_to,
    )?)
}

async fn listen_forever(
    address: IpAddr,
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    message_handler: MessageHandler,
    messages_built: Arc<AtomicU64>,
    mut mc_wsd_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
    uc_wsd_port_tx: Sender<(SocketAddr, Box<[u8]>)>,
) {
    loop {
        let message = tokio::select! {
            () = cancellation_token.cancelled() => {
                break;
            },
            message = mc_wsd_port_rx.recv() => {
                message
            }
        };

        let Some((from, buffer)) = message else {
            // the end, but we just got it before the cancellation
            break;
        };

        let (header, body_reader) = match message_handler
            .deconstruct_message(&buffer, Some(from))
            .await
        {
            Ok(pieces) => pieces,
            Err(error) => {
                error.log(&buffer);

                continue;
            },
        };

        // handle based on action
        let response = match &*header.action {
            constants::WSD_PROBE => {
                handle_probe(&config, &messages_built, header.message_id, body_reader)
            },
            constants::WSD_RESOLVE => handle_resolve(
                &config,
                address,
                &messages_built,
                config.uuid,
                header.message_id,
                body_reader,
            ),
            _ => {
                event!(
                    Level::DEBUG,
                    "unhandled action {}/{}",
                    header.action,
                    header.message_id
                );
                continue;
            },
        };

        let response = match response {
            Ok(response) => response,
            Err(error) => {
                event!(
                    Level::ERROR,
                    action = &*header.action,
                    ?error,
                    "Failure to create XML response"
                );
                continue;
            },
        };

        // return to sender
        if let Err(error) = uc_wsd_port_tx.send((from, response.into())).await {
            event!(Level::ERROR, ?error, to = ?from, "Failed to respond to message");
        }
    }
}

fn spawn_rx_loop(
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    messages_built: Arc<AtomicU64>,
    network_address: NetworkAddress,
    mc_wsd_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
    uc_wsd_port_tx: Sender<(SocketAddr, Box<[u8]>)>,
) {
    let address = network_address.address;

    let message_handler = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES), network_address);

    spawn_with_name(format!("wsd host ({})", address).as_str(), async move {
        listen_forever(
            address,
            cancellation_token,
            config,
            message_handler,
            messages_built,
            mc_wsd_port_rx,
            uc_wsd_port_tx,
        )
        .await;
    });
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    use libc::RT_SCOPE_SITE;
    use pretty_assertions::assert_eq;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::network_address::NetworkAddress;
    use crate::network_interface::NetworkInterface;
    use crate::test_utils::xml::to_string_pretty;
    use crate::test_utils::{build_config, build_message_handler};
    use crate::wsd::udp::host::{WSDHost, handle_probe, handle_resolve};

    #[tokio::test]
    async fn sends_hello() {
        // host
        let host_endpoint_uuid = Uuid::new_v4();
        let host_instance_id = "host-instance-id";
        let host_config = Arc::new(build_config(host_endpoint_uuid, host_instance_id));
        let host_messages_built = Arc::new(AtomicU64::new(0));
        let host_ip = Ipv4Addr::new(192, 168, 100, 1);

        let cancellation_token = CancellationToken::new();
        let (_mc_wsd_port_tx, mc_wsd_port_rx) = tokio::sync::mpsc::channel(10);
        let (mc_local_port_tx, mut mc_local_port_rx) = tokio::sync::mpsc::channel(10);
        let (uc_wsd_port_tx, _uc_wsd_port_rx) = tokio::sync::mpsc::channel(10);

        let _wsd_host = WSDHost::init(
            &cancellation_token,
            Arc::clone(&host_config),
            Arc::clone(&host_messages_built),
            NetworkAddress::new(
                host_ip.into(),
                Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
            ),
            mc_wsd_port_rx,
            mc_local_port_tx,
            uc_wsd_port_tx,
        );

        let hello = mc_local_port_rx.recv().await.unwrap();

        let expected = format!(
            include_str!("../../test/hello-template.xml"),
            Uuid::nil(),
            host_instance_id,
            Uuid::nil(),
            host_endpoint_uuid,
            host_ip,
            5357,
            host_endpoint_uuid
        );

        let response = to_string_pretty(&hello).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn sends_bye() {
        // host
        let host_endpoint_uuid = Uuid::new_v4();
        let host_instance_id = "host-instance-id";
        let host_config = Arc::new(build_config(host_endpoint_uuid, host_instance_id));
        let host_messages_built = Arc::new(AtomicU64::new(0));
        let host_ip = Ipv4Addr::new(192, 168, 100, 1);

        let cancellation_token = CancellationToken::new();
        let (_mc_wsd_port_tx, mc_wsd_port_rx) = tokio::sync::mpsc::channel(10);
        let (mc_local_port_tx, mut mc_local_port_rx) = tokio::sync::mpsc::channel(10);
        let (uc_wsd_port_tx, _uc_wsd_port_rx) = tokio::sync::mpsc::channel(10);

        let wsd_host = WSDHost::init(
            &cancellation_token,
            Arc::clone(&host_config),
            Arc::clone(&host_messages_built),
            NetworkAddress::new(
                host_ip.into(),
                Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
            ),
            mc_wsd_port_rx,
            mc_local_port_tx,
            uc_wsd_port_tx,
        );

        let _hello = mc_local_port_rx.recv().await.unwrap();

        wsd_host.teardown(true).await;

        let bye = mc_local_port_rx.recv().await.unwrap();

        let expected_message_number = 1_usize;

        let expected = format!(
            include_str!("../../test/bye-template.xml"),
            Uuid::nil(),
            host_instance_id,
            Uuid::nil(),
            expected_message_number,
            host_endpoint_uuid,
        );

        let response = to_string_pretty(&bye).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn handles_resolve() {
        let host_message_handler = build_message_handler();

        // host
        let host_endpoint_uuid = Uuid::new_v4();
        let host_instance_id = "host-instance-id";
        let host_config = Arc::new(build_config(host_endpoint_uuid, host_instance_id));
        let host_messages_built = AtomicU64::new(0);

        // client
        let client_ip = Ipv4Addr::new(192, 168, 100, 5);
        let client_message_id = Uuid::new_v4();
        let resolve = format!(
            include_str!("../../test/resolve-template.xml"),
            client_message_id, host_endpoint_uuid,
        );

        // host receives client's probe
        let (header, reader) = host_message_handler
            .deconstruct_message(
                resolve.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(client_ip, 5000))),
            )
            .await
            .unwrap();

        // host produces answer
        let response = handle_resolve(
            &host_config,
            IpAddr::V4(client_ip),
            &host_messages_built,
            host_config.uuid,
            header.message_id,
            reader,
        )
        .unwrap();

        let expected = format!(
            include_str!("../../test/resolve-matches-template.xml"),
            client_message_id,
            host_instance_id,
            host_messages_built.load(Ordering::Relaxed) - 1,
            host_endpoint_uuid,
            client_ip,
            host_endpoint_uuid
        );

        let response = to_string_pretty(&response).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn handles_probe() {
        let message_handler = build_message_handler();

        // host
        let host_endpoint_uuid = Uuid::new_v4();
        let host_instance_id = "host-instance-id";
        let host_config = Arc::new(build_config(host_endpoint_uuid, host_instance_id));
        let host_messages_built = AtomicU64::new(0);

        // client
        let client_ip = Ipv4Addr::new(192, 168, 100, 5);
        let client_message_id = Uuid::new_v4();
        let probe = format!(
            include_str!("../../test/probe-template.xml"),
            client_message_id
        );

        // host receives client's probe
        let (header, reader) = message_handler
            .deconstruct_message(
                probe.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(client_ip, 5000))),
            )
            .await
            .unwrap();

        // host produces answer
        let response = handle_probe(
            &host_config,
            &host_messages_built,
            header.message_id,
            reader,
        )
        .unwrap();

        let expected = format!(
            include_str!("../../test/probe-matches-template.xml"),
            client_message_id,
            host_instance_id,
            host_messages_built.load(Ordering::Relaxed) - 1,
            host_endpoint_uuid
        );

        let response = to_string_pretty(&response).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }
}
