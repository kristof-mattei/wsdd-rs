use std::net::IpAddr;
use std::sync::Arc;

use color_eyre::eyre;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::config::Config;
use crate::multicast_handler::{IncomingHostMessage, OutgoingMessage, OutgoingMulticastMessage};
use crate::network_address::NetworkAddress;
use crate::soap::builder::{self, Builder};
use crate::soap::parser::probe::Probe;
use crate::soap::parser::resolve::Resolve;
use crate::soap::{HostMessage, MessageId, UnicastMessage};
use crate::utils::task::spawn_with_name;

/// handles WSD requests coming from UDP datagrams.
pub struct WSDHost {
    address: IpAddr,
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    mc_local_port_tx: Sender<OutgoingMulticastMessage>,
}

impl WSDHost {
    pub fn init(
        cancellation_token: CancellationToken,
        config: Arc<Config>,
        bound_to: NetworkAddress,
        incoming_rx: Receiver<IncomingHostMessage>,
        mc_local_port_tx: Sender<OutgoingMulticastMessage>,
        uc_wsd_port_tx: Sender<OutgoingMessage>,
    ) -> Self {
        let address = bound_to.address;

        {
            let cancellation_token = cancellation_token.clone();
            let config = Arc::clone(&config);

            spawn_with_name(
                format!("wsd host ({})", bound_to.address).as_str(),
                async move {
                    listen_forever(
                        bound_to,
                        cancellation_token,
                        config,
                        incoming_rx,
                        uc_wsd_port_tx,
                    )
                    .await;
                },
            );
        };

        let host = Self {
            address: address.addr(),
            cancellation_token,
            config,
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

        if graceful {
            if let Err(error) = self.send_bye().await {
                event!(Level::DEBUG, ?error, "Failed to schedule bye message");
            }
        } else {
            // in the case the address dropped from the interface, there is nowhere to send the bye to
        }
    }

    // WS-Discovery, Section 4.1, Hello message
    fn schedule_send_hello(&self) {
        let cancellation_token = self.cancellation_token.clone();
        let config = Arc::clone(&self.config);
        let address = self.address;
        let mc_local_port_tx = self.mc_local_port_tx.clone();

        tokio::task::spawn(async move {
            if let Err(error) =
                send_hello(&cancellation_token, &config, address, &mc_local_port_tx).await
            {
                if cancellation_token.is_cancelled() {
                    // we're being cancelled, no need to pollute the shutdown log
                } else {
                    event!(
                        Level::TRACE,
                        ?error,
                        "Failed to send hello, receiver gone. WSDHost being torn down (network address gone) or application shutting down."
                    );
                }
            }
        });
    }

    /// WS-Discovery, Section 4.2, Bye message.
    async fn send_bye(&self) -> Result<(), eyre::Report> {
        let bye = Builder::build_bye(&self.config)?;

        Ok(self.mc_local_port_tx.send(bye.into()).await?)
    }
}

async fn send_hello(
    cancellation_token: &CancellationToken,
    config: &Config,
    address: IpAddr,
    mc_local_port_tx: &Sender<OutgoingMulticastMessage>,
) -> Result<(), eyre::Report> {
    let future = async move {
        let hello = Builder::build_hello(config, address)?;

        mc_local_port_tx
            .send(hello.into())
            .await
            .map_err(|_| eyre::Report::msg("Receiver gone, failed to send hello"))
    };

    cancellation_token
        .run_until_cancelled(future)
        .await
        .unwrap_or(Ok(()))
}

pub fn handle_probe(
    config: &Config,
    relates_to: &MessageId,
    probe: &Probe,
) -> Result<Option<UnicastMessage>, eyre::Report> {
    if probe.matches() {
        Ok(Some(builder::Builder::build_probe_matches(
            config, relates_to,
        )?))
    } else {
        event!(
            Level::DEBUG,
            ?probe.types,
            "client requests types we don't offer"
        );

        Ok(None)
    }
}

fn handle_resolve(
    address: IpAddr,
    config: &Config,
    target_uuid: uuid::Uuid,
    relates_to: &MessageId,
    resolve: &Resolve,
) -> Result<Option<UnicastMessage>, eyre::Report> {
    if resolve.addr_urn == target_uuid.urn() {
        Ok(Some(builder::Builder::build_resolve_matches(
            config, address, relates_to,
        )?))
    } else {
        event!(
            Level::DEBUG,
            addr_urn = %resolve.addr_urn,
            expected = %target_uuid.urn(),
            "invalid resolve request: address does not match own one"
        );

        Ok(None)
    }
}

async fn listen_forever(
    bound_to: NetworkAddress,
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    mut incoming_rx: Receiver<IncomingHostMessage>,
    uc_wsd_port_tx: Sender<OutgoingMessage>,
) {
    let address = bound_to.address.addr();

    loop {
        let message = tokio::select! {
            () = cancellation_token.cancelled() => {
                break;
            },
            message = incoming_rx.recv() => {
                message
            }
        };

        let Some(IncomingHostMessage {
            from,
            header,
            message,
        }) = message
        else {
            // the end, but we just got it before the cancellation
            break;
        };

        // dispatch based on the SOAP Action header
        let response = match message {
            HostMessage::Probe(probe) => handle_probe(&config, &header.message_id, &probe),
            HostMessage::Resolve(resolve) => {
                handle_resolve(address, &config, config.uuid, &header.message_id, &resolve)
            },
            HostMessage::Get(_) => {
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
            Ok(Some(response)) => response,
            Ok(None) => continue,
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
        if let Err(error) = uc_wsd_port_tx
            .send(OutgoingMessage {
                to: from,
                message: response,
            })
            .await
        {
            event!(Level::ERROR, ?error, to = ?from, "Failed to respond to message");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use ipnet::IpNet;
    use libc::RT_SCOPE_SITE;
    use pretty_assertions::assert_eq;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::constants;
    use crate::network_address::NetworkAddress;
    use crate::network_interface::NetworkInterface;
    use crate::test_utils::xml::to_string_pretty;
    use crate::test_utils::{build_config, build_message_handler};
    use crate::wsd::udp::host::{WSDHost, handle_probe, handle_resolve};

    #[tokio::test]
    async fn sends_hello() {
        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let cancellation_token = CancellationToken::new();
        let (_incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(10);
        let (mc_local_port_tx, mut mc_local_port_rx) = tokio::sync::mpsc::channel(10);
        let (uc_wsd_port_tx, _uc_wsd_port_rx) = tokio::sync::mpsc::channel(10);

        let _wsd_host = WSDHost::init(
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 24).unwrap(),
                Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
            ),
            incoming_rx,
            mc_local_port_tx,
            uc_wsd_port_tx,
        );

        let hello = mc_local_port_rx.recv().await.unwrap();

        let expected = format!(
            include_str!("../../test/hello-with-xaddrs-template.xml"),
            Uuid::nil(),
            host_config.app_sequence.instance_id(),
            Uuid::nil(),
            0,
            host_config.uuid_as_device_uri,
            host_ip,
            5357,
            host_config.uuid,
            1,
        );

        let response = to_string_pretty(hello.message.as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn hellos_on_two_addresses_get_distinct_message_numbers() {
        fn message_number(message: &[u8]) -> u64 {
            let message = std::str::from_utf8(message).unwrap();
            let (_, rest) = message.split_once("MessageNumber=\"").unwrap();
            let (message_number, _) = rest.split_once('"').unwrap();

            message_number.parse().unwrap()
        }

        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let cancellation_token = CancellationToken::new();
        let (_eth0_incoming_tx, eth0_incoming_rx) = tokio::sync::mpsc::channel(10);
        let (_eth1_incoming_tx, eth1_incoming_rx) = tokio::sync::mpsc::channel(10);
        let (mc_local_port_tx, mut mc_local_port_rx) = tokio::sync::mpsc::channel(10);
        let (uc_wsd_port_tx, _uc_wsd_port_rx) = tokio::sync::mpsc::channel(10);

        let _eth0_wsd_host = WSDHost::init(
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            NetworkAddress::new(
                IpNet::new(Ipv4Addr::new(192, 168, 100, 5).into(), 24).unwrap(),
                Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
            ),
            eth0_incoming_rx,
            mc_local_port_tx.clone(),
            uc_wsd_port_tx.clone(),
        );

        let _eth1_wsd_host = WSDHost::init(
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            NetworkAddress::new(
                IpNet::new(Ipv4Addr::new(10, 0, 0, 5).into(), 24).unwrap(),
                Arc::new(NetworkInterface::new_with_index("eth1", RT_SCOPE_SITE, 6)),
            ),
            eth1_incoming_rx,
            mc_local_port_tx,
            uc_wsd_port_tx,
        );

        let first = mc_local_port_rx.recv().await.unwrap();
        let second = mc_local_port_rx.recv().await.unwrap();

        let mut message_numbers = [
            message_number(first.message.as_ref()),
            message_number(second.message.as_ref()),
        ];
        message_numbers.sort_unstable();

        assert_eq!(message_numbers, [0, 1]);
    }

    #[tokio::test]
    async fn sends_bye() {
        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let cancellation_token = CancellationToken::new();
        let (_incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(10);
        let (mc_local_port_tx, mut mc_local_port_rx) = tokio::sync::mpsc::channel(10);
        let (uc_wsd_port_tx, _uc_wsd_port_rx) = tokio::sync::mpsc::channel(10);

        let wsd_host = WSDHost::init(
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 24).unwrap(),
                Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
            ),
            incoming_rx,
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
            host_config.app_sequence.instance_id(),
            Uuid::nil(),
            expected_message_number,
            host_config.uuid_as_device_uri,
        );

        let response = to_string_pretty(bye.message.as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn handles_resolve() {
        let host_message_handler = build_message_handler();

        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        // client
        let client_message_id = Uuid::now_v7();
        let resolve = format!(
            include_str!("../../test/resolve-template.xml"),
            client_message_id, host_config.uuid_as_device_uri,
        );

        // host receives client's probe
        let (header, message) = host_message_handler
            .deconstruct_message(&resolve, SocketAddr::V4(SocketAddrV4::new(host_ip, 5000)))
            .await
            .unwrap();

        let resolve = message.into_resolve().unwrap();

        // host produces answer
        let response = handle_resolve(
            IpAddr::from(host_ip),
            &host_config,
            host_config.uuid,
            &header.message_id,
            &resolve,
        )
        .unwrap()
        .unwrap();

        let expected_message_number = 0_usize;

        let expected = format!(
            include_str!("../../test/resolve-matches-template.xml"),
            client_message_id.urn(),
            host_config.app_sequence.instance_id(),
            expected_message_number,
            host_config.uuid_as_device_uri,
            host_ip,
            constants::WSD_HTTP_PORT,
            host_config.uuid
        );

        let response = to_string_pretty(response.as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn handles_probe_wsdp_device() {
        let client_message_id = Uuid::now_v7();
        let probe = format!(
            include_str!("../../test/probe-template-wsdp-device.xml"),
            client_message_id
        );

        handles_probe_generic(client_message_id.urn(), &probe).await;
    }

    #[tokio::test]
    async fn handles_probe_pub_computer() {
        // client
        let client_message_id = Uuid::now_v7();
        let probe = format!(
            include_str!("../../test/probe-template-pub-computer.xml"),
            client_message_id
        );

        handles_probe_generic(client_message_id.urn(), &probe).await;
    }

    #[tokio::test]
    async fn handles_probe_no_types() {
        let client_message_id = Uuid::now_v7();
        let probe = format!(
            include_str!("../../test/probe-template-no-types.xml"),
            client_message_id
        );

        handles_probe_generic(client_message_id.urn(), &probe).await;
    }

    #[tokio::test]
    async fn handles_probe_with_non_urn_message_id() {
        // the WS-Discovery spec's own example Probe uses this form, MessageID is `xs:anyURI`
        const MESSAGE_ID: &str = "uuid:0a6dc791-2be6-4991-9af1-454778a1917a";

        let probe = format!(
            include_str!("../../test/probe-template-any-uri-message-id.xml"),
            MESSAGE_ID
        );

        handles_probe_generic(MESSAGE_ID, &probe).await;
    }

    async fn handles_probe_generic(client_message_id: impl std::fmt::Display, probe: &str) {
        let host_message_handler = build_message_handler();

        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        // host receives client's probe
        let (header, message) = host_message_handler
            .deconstruct_message(&probe, SocketAddr::V4(SocketAddrV4::new(host_ip, 5000)))
            .await
            .unwrap();

        let probe = message.into_probe().unwrap();

        // host produces answer
        let response = handle_probe(&host_config, &header.message_id, &probe)
            .unwrap()
            .unwrap();

        let expected_message_number = 0_usize;

        let expected = format!(
            include_str!("../../test/probe-matches-without-xaddrs-template.xml"),
            client_message_id,
            host_config.app_sequence.instance_id(),
            expected_message_number,
            host_config.uuid_as_device_uri,
        );

        let response = to_string_pretty(response.as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }
}
