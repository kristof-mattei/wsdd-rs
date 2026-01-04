use std::io::Read;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use color_eyre::eyre;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use uuid::fmt::Urn;

use crate::config::Config;
use crate::constants;
use crate::multicast_handler::{IncomingUnicastMessage, OutgoingUnicastMessage};
use crate::network_address::NetworkAddress;
use crate::soap::builder::{self, Builder};
use crate::soap::parser::MessageHandler;
use crate::soap::{MulticastMessage, UnicastMessage, parser};
use crate::utils::task::spawn_with_name;
use crate::wsd::HANDLED_MESSAGES;
use crate::xml::Wrapper;

/// handles WSD requests coming from UDP datagrams.
pub struct WSDHost {
    address: IpAddr,
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    messages_built: Arc<AtomicU64>,
    mc_local_port_tx: Sender<MulticastMessage>,
}

impl WSDHost {
    pub fn init(
        cancellation_token: CancellationToken,
        config: Arc<Config>,
        messages_built: Arc<AtomicU64>,
        bound_to: NetworkAddress,
        mc_wsd_port_rx: Receiver<IncomingUnicastMessage>,
        mc_local_port_tx: Sender<MulticastMessage>,
        uc_wsd_port_tx: Sender<OutgoingUnicastMessage>,
    ) -> Self {
        let address = bound_to.address;

        {
            let cancellation_token = cancellation_token.clone();
            let config = Arc::clone(&config);
            let messages_built = Arc::clone(&messages_built);

            spawn_with_name(
                format!("wsd host ({})", bound_to.address).as_str(),
                async move {
                    listen_forever(
                        bound_to,
                        cancellation_token,
                        config,
                        messages_built,
                        mc_wsd_port_rx,
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

        if graceful {
            if let Err(error) = self.send_bye(&self.messages_built).await {
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
        let messages_built = Arc::clone(&self.messages_built);
        let mc_local_port_tx = self.mc_local_port_tx.clone();

        tokio::task::spawn(async move {
            if let Err(error) = send_hello(
                &cancellation_token,
                &config,
                address,
                &messages_built,
                &mc_local_port_tx,
            )
            .await
            {
                // TODO is this fatal? What should we do?
                event!(Level::ERROR, ?error, "Failed to send hello");
            }
        });
    }

    /// WS-Discovery, Section 4.2, Bye message
    async fn send_bye(&self, messages_built: &AtomicU64) -> Result<(), eyre::Report> {
        let bye = Builder::build_bye(&self.config, messages_built)?;

        Ok(self.mc_local_port_tx.send(bye).await?)
    }
}

async fn send_hello(
    cancellation_token: &CancellationToken,
    config: &Config,
    address: IpAddr,
    messages_built: &AtomicU64,
    mc_local_port_tx: &Sender<MulticastMessage>,
) -> Result<(), eyre::Report> {
    let future = async move {
        let hello = Builder::build_hello(config, messages_built, address)?;

        mc_local_port_tx
            .send(hello)
            .await
            .map_err(|_| eyre::Report::msg("Receiver gone, failed to send hello"))
    };

    cancellation_token
        .run_until_cancelled(future)
        .await
        .unwrap_or(Ok(()))
}

pub fn handle_probe<R>(
    config: &Config,
    messages_built: &AtomicU64,
    relates_to: Urn,
    reader: &mut Wrapper<R>,
) -> Result<Option<UnicastMessage>, eyre::Report>
where
    R: Read,
{
    let probe = parser::probe::parse_probe(reader)?;

    if probe.types.is_empty() || probe.requested_type_match() {
        Ok(Some(builder::Builder::build_probe_matches(
            config,
            messages_built,
            relates_to,
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

fn handle_resolve<R>(
    address: IpAddr,
    config: &Config,
    messages_built: &AtomicU64,
    target_uuid: uuid::Uuid,
    relates_to: Urn,
    reader: &mut Wrapper<R>,
) -> Result<Option<UnicastMessage>, eyre::Report>
where
    R: Read,
{
    let resolve = parser::resolve::parse_resolve(reader)?;

    if resolve.addr_urn == target_uuid.urn() {
        Ok(Some(builder::Builder::build_resolve_matches(
            config,
            address,
            messages_built,
            relates_to,
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
    messages_built: Arc<AtomicU64>,
    mut mc_wsd_port_rx: Receiver<IncomingUnicastMessage>,
    uc_wsd_port_tx: Sender<OutgoingUnicastMessage>,
) {
    let address = bound_to.address.addr();

    let message_handler = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES), bound_to);

    loop {
        let message = tokio::select! {
            () = cancellation_token.cancelled() => {
                break;
            },
            message = mc_wsd_port_rx.recv() => {
                message
            }
        };

        let Some(IncomingUnicastMessage { from, buffer }) = message else {
            // the end, but we just got it before the cancellation
            break;
        };

        let (header, mut body_reader) =
            match message_handler.deconstruct_message(&buffer, from).await {
                Ok(pieces) => pieces,
                Err(error) => {
                    error.log(&buffer);

                    continue;
                },
            };

        // dispatch based on the SOAP Action header
        let response = match &*header.action {
            constants::WSD_PROBE => handle_probe(
                &config,
                &messages_built,
                header.message_id,
                &mut body_reader,
            ),
            constants::WSD_RESOLVE => handle_resolve(
                address,
                &config,
                &messages_built,
                config.uuid,
                header.message_id,
                &mut body_reader,
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
            .send(OutgoingUnicastMessage {
                to: from,
                buffer: response,
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
    use std::sync::atomic::{AtomicU64, Ordering};

    use ipnet::IpNet;
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
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), "host-instance-id"));
        let host_messages_built = Arc::new(AtomicU64::new(0));

        let cancellation_token = CancellationToken::new();
        let (_mc_wsd_port_tx, mc_wsd_port_rx) = tokio::sync::mpsc::channel(10);
        let (mc_local_port_tx, mut mc_local_port_rx) = tokio::sync::mpsc::channel(10);
        let (uc_wsd_port_tx, _uc_wsd_port_rx) = tokio::sync::mpsc::channel(10);

        let _wsd_host = WSDHost::init(
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            Arc::clone(&host_messages_built),
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 24).unwrap(),
                Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
            ),
            mc_wsd_port_rx,
            mc_local_port_tx,
            uc_wsd_port_tx,
        );

        let hello = mc_local_port_rx.recv().await.unwrap();

        let expected = format!(
            include_str!("../../test/hello-with-xaddrs-template.xml"),
            Uuid::nil(),
            host_config.wsd_instance_id,
            Uuid::nil(),
            host_config.uuid_as_device_uri,
            host_ip,
            5357,
            host_config.uuid,
        );

        let response = to_string_pretty(hello.as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(expected, response);
    }

    #[tokio::test]
    async fn sends_bye() {
        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), "host-instance-id"));
        let host_messages_built = Arc::new(AtomicU64::new(0));

        let cancellation_token = CancellationToken::new();
        let (_mc_wsd_port_tx, mc_wsd_port_rx) = tokio::sync::mpsc::channel(10);
        let (mc_local_port_tx, mut mc_local_port_rx) = tokio::sync::mpsc::channel(10);
        let (uc_wsd_port_tx, _uc_wsd_port_rx) = tokio::sync::mpsc::channel(10);

        let wsd_host = WSDHost::init(
            cancellation_token.child_token(),
            Arc::clone(&host_config),
            Arc::clone(&host_messages_built),
            NetworkAddress::new(
                IpNet::new(host_ip.into(), 24).unwrap(),
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
            host_config.wsd_instance_id,
            Uuid::nil(),
            expected_message_number,
            host_config.uuid_as_device_uri,
        );

        let response = to_string_pretty(bye.as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(expected, response);
    }

    #[tokio::test]
    async fn handles_resolve() {
        let host_message_handler = build_message_handler();

        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), "host-instance-id"));
        let host_messages_built = Arc::new(AtomicU64::new(0));

        // client
        let client_message_id = Uuid::now_v7();
        let resolve = format!(
            include_str!("../../test/resolve-template.xml"),
            client_message_id, host_config.uuid_as_device_uri,
        );

        // host receives client's probe
        let (header, mut body_reader) = host_message_handler
            .deconstruct_message(
                resolve.as_bytes(),
                SocketAddr::V4(SocketAddrV4::new(host_ip, 5000)),
            )
            .await
            .unwrap();

        // host produces answer
        let response = handle_resolve(
            IpAddr::from(host_ip),
            &host_config,
            &host_messages_built,
            host_config.uuid,
            header.message_id,
            &mut body_reader,
        )
        .unwrap()
        .unwrap();

        let expected = format!(
            include_str!("../../test/resolve-matches-template.xml"),
            client_message_id,
            host_config.wsd_instance_id,
            host_messages_built.load(Ordering::Relaxed) - 1,
            host_config.uuid_as_device_uri,
            host_ip,
            host_config.uuid
        );

        let response = to_string_pretty(response.as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(expected, response);
    }

    #[tokio::test]
    async fn handles_probe_wsdp_device() {
        let client_message_id = Uuid::now_v7();
        let probe = format!(
            include_str!("../../test/probe-template-wsdp-device.xml"),
            client_message_id
        );

        handles_probe_generic(client_message_id, &probe).await;
    }

    #[tokio::test]
    async fn handles_probe_pub_computer() {
        // client
        let client_message_id = Uuid::now_v7();
        let probe = format!(
            include_str!("../../test/probe-template-pub-computer.xml"),
            client_message_id
        );

        handles_probe_generic(client_message_id, &probe).await;
    }

    #[tokio::test]
    async fn handles_probe_no_types() {
        let client_message_id = Uuid::now_v7();
        let probe = format!(
            include_str!("../../test/probe-template-no-types.xml"),
            client_message_id
        );

        handles_probe_generic(client_message_id, &probe).await;
    }

    async fn handles_probe_generic(client_message_id: Uuid, probe: &str) {
        let host_message_handler = build_message_handler();

        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), "host-instance-id"));
        let host_messages_built = Arc::new(AtomicU64::new(0));

        // host receives client's probe
        let (header, mut body_reader) = host_message_handler
            .deconstruct_message(
                probe.as_bytes(),
                SocketAddr::V4(SocketAddrV4::new(host_ip, 5000)),
            )
            .await
            .unwrap();

        // host produces answer
        let response = handle_probe(
            &host_config,
            &host_messages_built,
            header.message_id,
            &mut body_reader,
        )
        .unwrap()
        .unwrap();

        let expected = format!(
            include_str!("../../test/probe-matches-without-xaddrs-template.xml"),
            client_message_id,
            host_config.wsd_instance_id,
            host_messages_built.load(Ordering::Relaxed) - 1,
            host_config.uuid_as_device_uri,
        );

        let response = to_string_pretty(response.as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(expected, response);
    }
}
