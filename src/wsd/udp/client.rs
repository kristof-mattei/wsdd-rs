use std::io::BufReader;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use bytes::Bytes;
use color_eyre::eyre;
use hashbrown::HashMap;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use url::{Host, Url};
use uuid::Uuid;
use uuid::fmt::Urn;
use xml::EventReader;

use super::HANDLED_MESSAGES;
use crate::config::Config;
use crate::constants::{self, APP_MAX_DELAY, PROBE_TIMEOUT, XML_WSD_NAMESPACE};
use crate::network_address::NetworkAddress;
use crate::soap::builder::{Builder, MessageType};
use crate::soap::parser::generic::extract_endpoint_metadata;
use crate::soap::parser::{self, MessageHandler};
use crate::utils::task::spawn_with_name;
use crate::wsd::device::WSDDiscoveredDevice;

#[expect(unused, reason = "WIP")]
pub(crate) struct WSDClient {
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    address: IpAddr,
    mc_local_port_tx: Sender<Box<[u8]>>,
    probes: Arc<RwLock<HashMap<Urn, u128>>>,
}

/// Parameters:
///
/// * `mc_wsd_port_rx`: used to receive multicast messages on `WSD_PORT`
/// * `mc_local_port_rx`: used to receive multicast messages sent to the local port
/// * `mc_local_port_tx`: use to send multicast messages, from the local port to `WSD_PORT`
impl WSDClient {
    pub async fn init(
        cancellation_token: &CancellationToken,
        config: Arc<Config>,
        devices: Arc<RwLock<HashMap<Uuid, WSDDiscoveredDevice>>>,
        bound_to: NetworkAddress,
        mc_wsd_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
        mc_local_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
        mc_local_port_tx: Sender<Box<[u8]>>,
    ) -> Self {
        let cancellation_token = cancellation_token.child_token();

        let address = bound_to.address;

        let probes = Arc::new(RwLock::new(HashMap::<Urn, u128>::new()));

        spawn_rx_loop(
            cancellation_token.clone(),
            Arc::clone(&config),
            devices,
            bound_to,
            mc_wsd_port_rx,
            mc_local_port_rx,
            mc_local_port_tx.clone(),
            Arc::clone(&probes),
        );

        let mut client = Self {
            cancellation_token,
            config,
            address,
            mc_local_port_tx,
            probes,
        };

        // avoid packet storm when hosts come up by delaying initial probe
        tokio::time::sleep(Duration::from_millis(rand::random_range(0..=APP_MAX_DELAY))).await;

        if let Err(error) = client.send_probe().await {
            event!(Level::ERROR, ?error, "Failed to send probe");
        }

        client
    }

    #[expect(clippy::unused_async, reason = "WIP")]
    pub async fn teardown(self, graceful: bool) {
        self.cancellation_token.cancel();

        if graceful {
            // ??
        }
    }

    // WS-Discovery, Section 4.3, Probe message
    async fn send_probe(&mut self) -> Result<(), eyre::Report> {
        self.remove_outdated_probes().await;

        let (probe, message_id) = Builder::build_probe(&self.config)?;

        self.probes.write().await.insert(message_id, now());

        // deviation, we can't write that we're scheduling it with the same data, as we don't have the knowledge
        // TODO move event to here and write properly
        event!(Level::INFO, "scheduling {} message", MessageType::Probe);

        self.mc_local_port_tx.send(probe.into_boxed_slice()).await?;

        Ok(())
    }

    async fn remove_outdated_probes(&mut self) {
        let now = now();

        self.probes
            .write()
            .await
            .retain(|_, value| *value + (PROBE_TIMEOUT * 2) > now);
    }
}

fn now() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Before epoch?")
        .as_millis()
}

//         self.probes = {}

//     def cleanup(self) -> None:
//         super().cleanup()
//         WSDClient.instances.remove(self)

//         self.mch.remove_handler(self.mch.mc_send_socket, self)
//         self.mch.remove_handler(self.mch.recv_socket, self)

//     def teardown(self) -> None:
//         super().teardown()
//         self.remove_outdated_probes()

fn __extract_xaddr(bound_to: IpAddr, xaddrs: &str) -> Option<url::Url> {
    for addr in xaddrs.trim().split(' ') {
        let Ok(addr) = Url::parse(addr) else {
            continue;
        };

        match bound_to {
            IpAddr::V6(_) => {
                //      if (self.mch.address.family == socket.AF_INET6) and ('//[fe80::' in addr):
                //          # use first link-local address for IPv6
                match addr.host() {
                    Some(Host::Ipv6(ipv6)) if ipv6.is_unicast_link_local() => {
                        return Some(addr);
                    },
                    _ => continue,
                }
            },
            IpAddr::V4(_) => {
                //  use first (and very likely the only) IPv4 address
                return Some(addr);
            },
        }
    }

    None
}

async fn handle_hello(
    config: &Config,
    devices: Arc<RwLock<HashMap<Uuid, WSDDiscoveredDevice>>>,
    bound_to: &NetworkAddress,
    multicast: &Sender<Box<[u8]>>,
    mut reader: EventReader<BufReader<&[u8]>>,
) -> Result<(), eyre::Report> {
    parser::generic::parse_generic_body(&mut reader, XML_WSD_NAMESPACE, "Hello")?;

    let (endpoint, xaddrs) = parser::generic::extract_endpoint_metadata(&mut reader)?;

    let Some(xaddrs) = xaddrs else {
        event!(Level::INFO, "Hello without XAddrs, sending resolve");

        let (message, _) = Builder::build_resolve(config, endpoint)?;

        multicast.send(message.into_boxed_slice()).await?;

        return Ok(());
    };

    let Some(xaddr) = __extract_xaddr(bound_to.address, &xaddrs) else {
        return Ok(());
    };

    // TODO serve variables and static text
    event!(Level::INFO, "Hello from {} on {}", endpoint, xaddr);

    perform_metadata_exchange(config, devices, bound_to, endpoint, xaddr).await?;

    Ok(())
}

async fn handle_bye(
    devices: Arc<RwLock<HashMap<Uuid, WSDDiscoveredDevice>>>,
    mut reader: EventReader<BufReader<&[u8]>>,
) -> Result<(), eyre::Report> {
    parser::generic::parse_generic_body(&mut reader, XML_WSD_NAMESPACE, "Bye")?;

    let (endpoint, _) = parser::generic::extract_endpoint_metadata(&mut reader)?;

    let mut guard = devices.write().await;

    if guard.remove(&endpoint).is_none() {
        event!(
            Level::INFO,
            ?endpoint,
            "Received bye, but not record of that endpoint"
        );
    }

    Ok(())
}

async fn handle_probe_match(
    config: &Config,
    devices: Arc<RwLock<HashMap<Uuid, WSDDiscoveredDevice>>>,
    bound_to: &NetworkAddress,
    relates_to: Option<Urn>,
    probes: Arc<RwLock<HashMap<Urn, u128>>>,
    mc_local_port_tx: &Sender<Box<[u8]>>,
    mut reader: EventReader<BufReader<&[u8]>>,
) -> Result<(), eyre::Report> {
    let Some(relates_to) = relates_to else {
        event!(Level::DEBUG, "missing `RelatesTo`");
        return Ok(());
    };

    parser::generic::parse_generic_body_paths(
        &mut reader,
        &[
            (XML_WSD_NAMESPACE, "ProbeMatches"),
            (XML_WSD_NAMESPACE, "ProbeMatch"),
        ],
    )?;

    // do not handle to probematches issued not sent by ourself
    if probes.read().await.get(&relates_to).is_none() {
        event!(Level::DEBUG, %relates_to, "unknown probe");
        return Ok(());
    }

    let (endpoint, xaddrs) = extract_endpoint_metadata(&mut reader)?;

    //  If no XAddrs are included in the ProbeMatches message, then the client may send a
    //  Resolve message by UDP multicast to port 3702.
    let Some(xaddrs) = xaddrs else {
        event!(Level::INFO, "probe match without XAddrs, sending resolve");

        let (message, _) = Builder::build_resolve(config, endpoint)?;

        mc_local_port_tx.send(message.into_boxed_slice()).await?;

        return Ok(());
    };

    let Some(xaddr) = __extract_xaddr(bound_to.address, &xaddrs) else {
        return Ok(());
    };

    event!(Level::DEBUG, %endpoint, %xaddr, "Probe match");

    perform_metadata_exchange(config, Arc::clone(&devices), bound_to, endpoint, xaddr).await?;

    Ok(())
}

async fn handle_resolve_match(
    config: &Config,
    devices: Arc<RwLock<HashMap<Uuid, WSDDiscoveredDevice>>>,
    bound_to: &NetworkAddress,
    mut reader: EventReader<BufReader<&[u8]>>,
) -> Result<(), eyre::Report> {
    parser::generic::parse_generic_body_paths(
        &mut reader,
        &[
            (XML_WSD_NAMESPACE, "ResolveMatches"),
            (XML_WSD_NAMESPACE, "ResolveMatch"),
        ],
    )?;

    let (endpoint, xaddrs) = extract_endpoint_metadata(&mut reader)?;

    let Some(xaddrs) = xaddrs else {
        event!(Level::DEBUG, "Resolve match without xaddr");

        return Ok(());
    };

    let Some(xaddr) = __extract_xaddr(bound_to.address, &xaddrs) else {
        event!(
            Level::ERROR,
            "No valid URL in xaddr, but this is a bug in xaddr, where we're too strict"
        );

        return Ok(());
    };

    event!(Level::DEBUG, %endpoint, ?xaddr, "Resolve match");

    perform_metadata_exchange(config, devices, bound_to, endpoint, xaddr).await?;

    Ok(())
}

async fn perform_metadata_exchange(
    config: &Config,
    devices: Arc<RwLock<HashMap<Uuid, WSDDiscoveredDevice>>>,
    bound_to: &NetworkAddress,
    endpoint: Uuid,
    xaddr: Url,
) -> Result<(), eyre::Report> {
    let scheme = xaddr.scheme();

    if !matches!(scheme, "http" | "https") {
        event!(Level::DEBUG, %xaddr, "invalid XAddr");
        return Ok(());
    }

    let body = build_getmetadata_message(config, endpoint)?;

    let client_builder = reqwest::ClientBuilder::new().local_address(bound_to.address);

    let builder = client_builder
        .build()?
        .post(xaddr.clone())
        .header("Content-Type", "application/soap+xml")
        .header("User-Agent", "wsdd-rs");

    let response = builder
        .body(body)
        .timeout(config.metadata_timeout)
        .send()
        .await;

    match response {
        Ok(response) => {
            let response = response.bytes().await?;

            handle_metadata(devices, &response, endpoint, xaddr, bound_to).await?;
        },
        Err(error) => {
            let url = error.url().map(ToString::to_string);
            let url = url.as_deref().unwrap_or("Failed to get URL from error");

            if error.is_timeout() {
                event!(Level::WARN, url, "metadata exchange timed out");
            } else {
                event!(Level::WARN, ?error, url, "could not fetch metadata");
            }
        },
    }

    Ok(())
}

fn build_getmetadata_message(
    config: &Config,
    endpoint: Uuid,
) -> Result<Vec<u8>, xml::writer::Error> {
    let message = Builder::build_get(config, endpoint)?;

    Ok(message)
}

async fn handle_metadata(
    devices: Arc<RwLock<hashbrown::HashMap<Uuid, WSDDiscoveredDevice>>>,
    meta: &Bytes,
    endpoint: Uuid,
    xaddr: Url,
    bound_to: &NetworkAddress,
) -> Result<(), eyre::Report> {
    let device_uuid = endpoint;

    match devices.write().await.entry(device_uuid) {
        hashbrown::hash_map::Entry::Occupied(mut occupied_entry) => {
            occupied_entry.get_mut().update(meta, xaddr, bound_to)?;
        },
        hashbrown::hash_map::Entry::Vacant(vacant_entry) => {
            vacant_entry.insert(WSDDiscoveredDevice::new(meta, xaddr, bound_to)?);
        },
    }

    Ok(())
}

#[expect(clippy::too_many_arguments, reason = "WIP")]
async fn listen_forever(
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    devices: Arc<RwLock<HashMap<Uuid, WSDDiscoveredDevice>>>,
    message_handler: MessageHandler,
    bound_to: NetworkAddress,
    mut mc_wsd_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
    mut mc_local_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
    mc_local_port_tx: Sender<Box<[u8]>>,
    probes: Arc<RwLock<HashMap<Urn, u128>>>,
) {
    loop {
        let message = tokio::select! {
            () = cancellation_token.cancelled() => {
                break;
            },
            message = mc_wsd_port_rx.recv() => {
                message
            }
            message = mc_local_port_rx.recv() => {
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
        if let Err(error) = match &*header.action {
            constants::WSD_HELLO => {
                handle_hello(
                    &config,
                    Arc::clone(&devices),
                    &bound_to,
                    &mc_local_port_tx,
                    body_reader,
                )
                .await
            },
            constants::WSD_BYE => handle_bye(Arc::clone(&devices), body_reader).await,
            constants::WSD_PROBE_MATCH => {
                handle_probe_match(
                    &config,
                    Arc::clone(&devices),
                    &bound_to,
                    header.relates_to,
                    Arc::clone(&probes),
                    &mc_local_port_tx,
                    body_reader,
                )
                .await
            },
            constants::WSD_RESOLVE_MATCH => {
                handle_resolve_match(&config, Arc::clone(&devices), &bound_to, body_reader).await
            },
            _ => {
                event!(
                    Level::DEBUG,
                    "unhandled action {}/{}",
                    header.action,
                    header.message_id
                );
                continue;
            },
        } {
            event!(
                Level::ERROR,
                action = &*header.action,
                ?error,
                "Failure to parse XML"
            );
            continue;
        }
    }
}

#[expect(clippy::too_many_arguments, reason = "WIP")]
fn spawn_rx_loop(
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    devices: Arc<RwLock<HashMap<Uuid, WSDDiscoveredDevice>>>,
    bound_to: NetworkAddress,
    mc_wsd_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
    mc_local_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
    mc_local_port_tx: Sender<Box<[u8]>>,
    probes: Arc<RwLock<HashMap<Urn, u128>>>,
) {
    let message_handler = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES), bound_to.clone());

    spawn_with_name(
        format!("wsd client ({})", bound_to.address).as_str(),
        async move {
            listen_forever(
                cancellation_token,
                config,
                devices,
                message_handler,
                bound_to,
                mc_wsd_port_rx,
                mc_local_port_rx,
                mc_local_port_tx,
                probes,
            )
            .await;
        },
    );
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;

    use hashbrown::HashMap;
    use libc::RT_SCOPE_SITE;
    use mockito::ServerOpts;
    use pretty_assertions::assert_eq;
    use tokio::sync::RwLock;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;

    use crate::network_interface::NetworkInterface;
    use crate::test_utils::xml::to_string_pretty;
    use crate::test_utils::{build_config, build_message_handler_with_network_address};
    use crate::wsd::udp::client::{WSDClient, handle_bye, handle_hello};

    #[tokio::test]
    async fn handles_hello_without_xaddr() {
        let (message_handler, client_network_address) =
            build_message_handler_with_network_address(IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)));

        // client
        let client_endpoint_uuid = Uuid::new_v4();
        let client_instance_id = "client-instance-id";
        let client_devices = Arc::new(RwLock::new(HashMap::new()));
        let client_config = Arc::new(build_config(client_endpoint_uuid, client_instance_id));

        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_endpoint_uuid = Uuid::new_v4();
        let hello_without_xaddrs = format!(
            include_str!("../../test/hello-without-xaddrs-template.xml"),
            Uuid::new_v4(),
            host_endpoint_uuid
        );

        let (multicast_sender, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (_, reader) = message_handler
            .deconstruct_message(
                hello_without_xaddrs.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_hello(
            &client_config,
            Arc::clone(&client_devices),
            &client_network_address,
            &multicast_sender,
            reader,
        )
        .await
        .unwrap();

        let expected = format!(
            include_str!("../../test/resolve-template.xml"),
            Uuid::nil(),
            host_endpoint_uuid,
        );

        let response = {
            let response = multicast_rx.try_recv().unwrap();

            to_string_pretty(&response).unwrap()
        };

        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn handles_hello_with_xaddr() {
        let (message_handler, bound_to) =
            build_message_handler_with_network_address(IpAddr::V4(Ipv4Addr::LOCALHOST));

        // client
        let client_endpoint_id = Uuid::new_v4();
        let client_instance_id = "client-instance-id";
        let client_devices = Arc::new(RwLock::new(HashMap::new()));

        // host
        let mut server = mockito::Server::new_with_opts_async(ServerOpts {
            // a host in IPv4 form ensures we bind to an IPv4 address
            host: "127.0.0.1",
            // random port
            port: 0,
            assert_on_drop: true,
        })
        .await;

        let IpAddr::V4(host_ip) = server.socket_address().ip() else {
            panic!("Invalid test setup");
        };
        let host_port = server.socket_address().port();
        let host_message_id = Uuid::new_v4();
        let host_instance_id = "host-instance-id";
        let host_endpoint_uuid = Uuid::new_v4();

        let expected_get = format!(
            include_str!("../../test/get-template.xml"),
            host_endpoint_uuid, client_endpoint_id
        );

        let mock = server
            .mock("POST", &*format!("/{}", host_endpoint_uuid))
            .with_status(200)
            .with_body_from_request(move |request| {
                let metadata: String = format!(
                    include_str!("../../test/get-response-template.xml"),
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                );

                assert_eq!(
                    to_string_pretty(expected_get.as_bytes()).unwrap(),
                    to_string_pretty(request.body().unwrap()).unwrap()
                );

                metadata.into()
            })
            .create_async()
            .await;

        let hello = format!(
            include_str!("../../test/hello-template.xml"),
            host_message_id,
            host_instance_id,
            Uuid::new_v4(),
            host_endpoint_uuid,
            host_ip,
            host_port,
            host_endpoint_uuid
        );

        let (multicast_sender, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let config = Arc::new(build_config(client_endpoint_id, client_instance_id));

        let (_, reader) = message_handler
            .deconstruct_message(
                hello.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_hello(
            &config,
            Arc::clone(&client_devices),
            &bound_to,
            &multicast_sender,
            reader,
        )
        .await
        .unwrap();

        // we expect no resolve to be sent
        multicast_rx.try_recv().unwrap_err();

        // ensure the mock is hit
        mock.assert_async().await;

        let client_devices = client_devices.read().await;

        let device = client_devices.get(&host_endpoint_uuid);

        assert!(device.is_some());

        let device = device.unwrap();

        let expected_props = HashMap::<_, _>::from_iter([
            ("Manufacturer", "Synology Inc"),
            ("FirmwareVersion", "6"),
            ("FriendlyName", "Synology DiskStation"),
            ("ModelUrl", "http://www.synology.com"),
            ("PresentationUrl", "http://www.synology.com"),
            ("ModelName", "Synology DiskStation"),
            ("SerialNumber", "6"),
            ("ModelNumber", "1"),
            ("ManufacturerUrl", "http://www.synology.com"),
        ]);

        let device_props = device
            .props()
            .iter()
            .map(|(key, value)| (&**key, &**value))
            .collect::<HashMap<_, _>>();

        assert_eq!(device_props, expected_props);
    }

    #[tokio::test]
    async fn handles_bye() {
        let (message_handler, _client_network_address) =
            build_message_handler_with_network_address(IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)));

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));

        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_endpoint_uuid = Uuid::new_v4();
        let host_instance_id = "host-instance-id";
        let bye = format!(
            include_str!("../../test/bye-template.xml"),
            Uuid::new_v4(),
            host_instance_id,
            Uuid::new_v4(),
            0,
            host_endpoint_uuid
        );

        let (_, reader) = message_handler
            .deconstruct_message(
                bye.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_bye(Arc::clone(&client_devices), reader)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn handles_hello_bye() {
        let (message_handler, network_address) =
            build_message_handler_with_network_address(IpAddr::V4(Ipv4Addr::LOCALHOST));

        // client
        let client_endpoint_id = Uuid::new_v4();
        let client_instance_id = "client-instance-id";
        let client_devices = Arc::new(RwLock::new(HashMap::new()));

        // host
        let mut server = mockito::Server::new_with_opts_async(ServerOpts {
            // a host in IPv4 form ensures we bind to an IPv4 address
            host: "127.0.0.1",
            // random port
            port: 0,
            assert_on_drop: true,
        })
        .await;

        let IpAddr::V4(host_ip) = server.socket_address().ip() else {
            panic!("Invalid test setup");
        };
        let host_port = server.socket_address().port();
        let host_instance_id = "host-instance-id";
        let host_endpoint_uuid = Uuid::new_v4();

        let expected_get = format!(
            include_str!("../../test/get-template.xml"),
            host_endpoint_uuid, client_endpoint_id
        );

        let mock = server
            .mock("POST", &*format!("/{}", host_endpoint_uuid))
            .with_status(200)
            .with_body_from_request(move |request| {
                let metadata: String = format!(
                    include_str!("../../test/get-response-template.xml"),
                    Uuid::new_v4(),
                    Uuid::new_v4(),
                );

                assert_eq!(
                    to_string_pretty(expected_get.as_bytes()).unwrap(),
                    to_string_pretty(request.body().unwrap()).unwrap()
                );

                metadata.into()
            })
            .create_async()
            .await;

        let hello = format!(
            include_str!("../../test/hello-template.xml"),
            Uuid::new_v4(),
            host_instance_id,
            Uuid::new_v4(),
            host_endpoint_uuid,
            host_ip,
            host_port,
            host_endpoint_uuid
        );

        let (multicast_sender, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let config = Arc::new(build_config(client_endpoint_id, client_instance_id));

        let (_, reader) = message_handler
            .deconstruct_message(
                hello.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_hello(
            &config,
            Arc::clone(&client_devices),
            &network_address,
            &multicast_sender,
            reader,
        )
        .await
        .unwrap();

        // we expect no resolve to be sent
        multicast_rx.try_recv().unwrap_err();

        // ensure the mock is hit
        mock.assert_async().await;

        assert!(
            client_devices
                .read()
                .await
                .contains_key(&host_endpoint_uuid)
        );

        // and now the bye
        let bye = format!(
            include_str!("../../test/bye-template.xml"),
            Uuid::new_v4(),
            host_instance_id,
            Uuid::new_v4(),
            0,
            host_endpoint_uuid
        );

        let (_, reader) = message_handler
            .deconstruct_message(
                bye.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_bye(Arc::clone(&client_devices), reader)
            .await
            .unwrap();

        // ensure the host is no longer present
        assert!(
            !client_devices
                .read()
                .await
                .contains_key(&host_endpoint_uuid)
        );
    }

    #[tokio::test]
    async fn sends_probe() {
        let cancellation_token = CancellationToken::new();
        let client_endpoint_id = Uuid::new_v4();
        let client_instance_id = "client-instance-id";
        let config = Arc::new(build_config(client_endpoint_id, client_instance_id));
        let client_devices = Arc::new(RwLock::new(HashMap::new()));

        let (_mc_wsd_port_tx, mc_wsd_port_rx) = tokio::sync::mpsc::channel(10);
        let (_mc_local_port_tx, mc_local_port_rx) = tokio::sync::mpsc::channel(10);
        let (uc_wsd_port_tx, mut uc_wsd_port_rx) = tokio::sync::mpsc::channel(10);

        let bound_to = crate::network_address::NetworkAddress::new(
            IpAddr::V4(Ipv4Addr::new(192, 168, 100, 5)),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        let _client = WSDClient::init(
            &cancellation_token,
            config,
            client_devices,
            bound_to,
            mc_wsd_port_rx,
            mc_local_port_rx,
            uc_wsd_port_tx,
        )
        .await;

        let probe = uc_wsd_port_rx.recv().await.unwrap();

        let expected = format!(include_str!("../../test/probe-template.xml"), Uuid::nil());

        let response = to_string_pretty(&probe).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }
}
