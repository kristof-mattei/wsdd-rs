use std::cmp::Reverse;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use color_eyre::eyre;
use hashbrown::HashMap;
use ipnet::IpNet;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use url::{Host, Url};
use uuid::fmt::Urn;

use crate::config::Config;
use crate::constants::{
    APP_MAX_DELAY, MIME_TYPE_SOAP_XML, PROBE_TIMEOUT_MILLISECONDS, WSD_BYE, WSD_HELLO,
    WSD_PROBE_MATCH, WSD_RESOLVE_MATCH, XML_WSD_NAMESPACE,
};
use crate::network_address::NetworkAddress;
use crate::soap::builder::{Builder, MessageType};
use crate::soap::parser::MessageHandler;
use crate::soap::parser::generic::extract_endpoint_metadata;
use crate::soap::parser::xaddrs::XAddr;
use crate::utils::SliceDisplay;
use crate::utils::task::spawn_with_name;
use crate::wsd::HANDLED_MESSAGES;
use crate::wsd::device::{DeviceUri, WSDDiscoveredDevice};
use crate::xml::{Wrapper, find_descendant, find_descendants};

pub(crate) struct WSDClient {
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    _bound_to: NetworkAddress,
    _devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,
    handle: tokio::task::JoinHandle<()>,
    mc_local_port_tx: Sender<Box<[u8]>>,
    probes: Arc<RwLock<HashMap<Urn, Duration>>>,
}

impl WSDClient {
    /// Parameters:
    ///
    /// * `mc_wsd_port_rx`: used to receive multicast messages on `WSD_PORT`
    /// * `mc_local_port_rx`: used to receive multicast messages sent to the local port
    /// * `mc_local_port_tx`: use to send multicast messages, from the local port to `WSD_PORT`
    pub fn init(
        cancellation_token: CancellationToken,
        config: Arc<Config>,
        devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,
        bound_to: NetworkAddress,
        mc_wsd_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
        mc_local_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
        mc_local_port_tx: Sender<Box<[u8]>>,
    ) -> Self {
        let probes = Arc::new(RwLock::new(HashMap::<Urn, Duration>::new()));

        let handle = {
            let cancellation_token = cancellation_token.clone();
            let config = Arc::clone(&config);
            let bound_to = bound_to.clone();
            let devices = Arc::clone(&devices);
            let mc_local_port_tx = mc_local_port_tx.clone();
            let probes = Arc::clone(&probes);

            spawn_with_name(
                format!("wsd client ({})", bound_to.address).as_str(),
                listen_forever(
                    bound_to,
                    cancellation_token,
                    config,
                    devices,
                    mc_wsd_port_rx,
                    mc_local_port_rx,
                    mc_local_port_tx,
                    probes,
                ),
            )
        };

        let client = Self {
            cancellation_token,
            config,
            _bound_to: bound_to,
            _devices: devices,
            handle,
            mc_local_port_tx,
            probes,
        };

        client.schedule_send_probe();

        client
    }

    pub async fn teardown(self) {
        self.cancellation_token.cancel();

        self.remove_outdated_probes().await;

        let _r = self.handle.await;
    }

    // WS-Discovery, Section 4.3, Probe message
    fn schedule_send_probe(&self) {
        let cancellation_token = self.cancellation_token.clone();
        let config = Arc::clone(&self.config);
        let probes = Arc::clone(&self.probes);
        let mc_local_port_tx = self.mc_local_port_tx.clone();

        tokio::task::spawn(async move {
            // avoid packet storm when hosts come up by delaying initial probe
            tokio::select! {
                biased;
                () = cancellation_token.cancelled() => { return; },
                () = tokio::time::sleep(Duration::from_millis(rand::random_range(0..=APP_MAX_DELAY))) => { }
            }

            if let Err(error) =
                send_probe(&cancellation_token, &config, &probes, &mc_local_port_tx).await
            {
                event!(Level::ERROR, ?error, "Failed to send probe");
            }
        });
    }

    pub async fn send_probe(&self) -> Result<(), eyre::Report> {
        send_probe(
            &self.cancellation_token,
            &self.config,
            &self.probes,
            &self.mc_local_port_tx,
        )
        .await
    }

    async fn remove_outdated_probes(&self) {
        remove_outdated_probes(&self.probes).await;
    }
}

async fn send_probe(
    cancellation_token: &CancellationToken,
    config: &Arc<Config>,
    probes: &Arc<RwLock<HashMap<Urn, Duration>>>,
    mc_local_port_tx: &Sender<Box<[u8]>>,
) -> Result<(), eyre::Report> {
    let future = async move {
        remove_outdated_probes(probes).await;

        let (probe, message_id) = Builder::build_probe(config)?;

        probes.write().await.insert(message_id, now());

        // deviation, we can't write that we're scheduling it with the same data, as we don't have the knowledge
        // TODO move event to here and write properly
        event!(Level::INFO, "scheduling {} message", MessageType::Probe);

        mc_local_port_tx
            .send(probe.into_boxed_slice())
            .await
            .map_err(|_| eyre::Report::msg("Receiver gone, failed to send probe"))
    };

    cancellation_token
        .run_until_cancelled(future)
        .await
        .unwrap_or(Ok(()))
}

async fn remove_outdated_probes(probes: &Arc<RwLock<HashMap<Urn, Duration>>>) {
    const PROBE_TIMEOUT: Duration = const { Duration::from_millis(PROBE_TIMEOUT_MILLISECONDS) };

    let now = now();

    probes
        .write()
        .await
        .retain(|_, value| *value + (PROBE_TIMEOUT * 2) > now);
}

fn now() -> Duration {
    #[cfg(miri)]
    {
        Duration::from_secs(1_762_802_693)
    }

    #[cfg(not(miri))]
    {
        use std::time::SystemTime;

        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Before epoch? Time travel?")
    }
}

//     def cleanup(self) -> None:
//         super().cleanup()
//         WSDClient.instances.remove(self)

//         self.mch.remove_handler(self.mch.mc_send_socket, self)
//         self.mch.remove_handler(self.mch.recv_socket, self)

fn parse_xaddrs(bound_to: IpNet, raw_xaddrs: &str) -> Vec<XAddr> {
    #[derive(Ord, PartialOrd, PartialEq, Eq)]
    enum XAddrPriority {
        Medium = 0,
        High = 1,
    }

    // discard invalid URLs
    let mut xaddrs = raw_xaddrs
        .split_whitespace()
        .filter_map(|raw_xaddr| match XAddr::try_from(raw_xaddr) {
            Ok(xaddr) => Some(xaddr),
            Err(err) => {
                event!(
                    Level::INFO,
                    ?err,
                    %raw_xaddr,
                    "Message sent with invalid/non-http/https xaddr or no host, ignoring"
                );

                None
            },
        })
        .collect::<Vec<_>>();

    xaddrs.sort_unstable_by_key(|parsed_url| {
        match bound_to {
            IpNet::V6(_) => {
                // prefer link-local address for IPv6
                if let Some(Host::Ipv6(ipv6)) = parsed_url.get_url().host()
                    && ipv6.is_unicast_link_local()
                {
                    Reverse(XAddrPriority::High)
                } else {
                    Reverse(XAddrPriority::Medium)
                }
            },
            IpNet::V4(_) => {
                // use first (and very likely the only) IPv4 address
                Reverse(XAddrPriority::High)
            },
        }
    });

    event!(Level::TRACE, xaddrs = %SliceDisplay(&xaddrs));

    xaddrs
}

async fn handle_hello(
    client: &reqwest::Client,
    config: &Config,
    devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,
    bound_to: &NetworkAddress,
    multicast: &Sender<Box<[u8]>>,
    reader: &mut Wrapper<'_>,
) -> Result<(), eyre::Report> {
    find_descendant(reader, Some(XML_WSD_NAMESPACE), "Hello")?;

    let (endpoint, raw_xaddrs) = extract_endpoint_metadata(reader)?;

    let Some(raw_xaddrs) = raw_xaddrs else {
        event!(Level::INFO, "Hello without XAddrs, sending resolve");

        let (message, _) = Builder::build_resolve(config, &endpoint)?;

        multicast.send(message.into_boxed_slice()).await?;

        return Ok(());
    };

    let xaddrs = parse_xaddrs(bound_to.address, &raw_xaddrs);

    if xaddrs.is_empty() {
        event!(Level::ERROR, "No valid URL in xaddrs");

        return Ok(());
    }

    event!(Level::INFO, %endpoint, xaddrs = %SliceDisplay(&xaddrs), "Hello");

    perform_metadata_exchange(
        client,
        config,
        devices,
        bound_to,
        endpoint,
        xaddrs.into_iter().map(Into::into).collect(),
    )
    .await?;

    Ok(())
}

async fn handle_bye(
    devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,
    reader: &mut Wrapper<'_>,
) -> Result<(), eyre::Report> {
    find_descendant(reader, Some(XML_WSD_NAMESPACE), "Bye")?;

    let (endpoint, _) = extract_endpoint_metadata(reader)?;

    let mut guard = devices.write().await;

    if guard.remove(&endpoint).is_none() {
        event!(
            Level::INFO,
            endpoint = &*endpoint,
            "Received bye, but not record of that endpoint"
        );
    }

    Ok(())
}

#[expect(clippy::too_many_arguments, reason = "WIP")]
async fn handle_probe_match(
    client: &reqwest::Client,
    config: &Config,
    devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,
    bound_to: &NetworkAddress,
    relates_to: Option<Urn>,
    probes: Arc<RwLock<HashMap<Urn, Duration>>>,
    mc_local_port_tx: &Sender<Box<[u8]>>,
    reader: &mut Wrapper<'_>,
) -> Result<(), eyre::Report> {
    let Some(relates_to) = relates_to else {
        event!(Level::DEBUG, "missing `RelatesTo`");
        return Ok(());
    };

    find_descendants(
        reader,
        &[
            (Some(XML_WSD_NAMESPACE), "ProbeMatches"),
            (Some(XML_WSD_NAMESPACE), "ProbeMatch"),
        ],
    )?;

    // do not handle to probematches issued not sent by ourself
    if probes.read().await.get(&relates_to).is_none() {
        event!(Level::DEBUG, %relates_to, "unknown probe");
        return Ok(());
    }

    let (endpoint, raw_xaddrs) = extract_endpoint_metadata(reader)?;

    //  If no XAddrs are included in the ProbeMatches message, then the client may send a
    //  Resolve message by UDP multicast to port 3702.
    let Some(raw_xaddrs) = raw_xaddrs else {
        event!(Level::INFO, "ProbeMatch without XAddrs, sending resolve");

        let (message, _) = Builder::build_resolve(config, &endpoint)?;

        mc_local_port_tx.send(message.into_boxed_slice()).await?;

        return Ok(());
    };

    let xaddrs = parse_xaddrs(bound_to.address, &raw_xaddrs);

    if xaddrs.is_empty() {
        event!(Level::ERROR, "No valid URL in xaddrs");

        return Ok(());
    }

    event!(Level::INFO, %endpoint, xaddrs = %SliceDisplay(&xaddrs), "ProbeMatch");

    perform_metadata_exchange(
        client,
        config,
        devices,
        bound_to,
        endpoint,
        xaddrs.into_iter().map(Into::into).collect(),
    )
    .await?;

    Ok(())
}

async fn handle_resolve_match(
    client: &reqwest::Client,
    config: &Config,
    devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,
    bound_to: &NetworkAddress,
    reader: &mut Wrapper<'_>,
) -> Result<(), eyre::Report> {
    find_descendants(
        reader,
        &[
            (Some(XML_WSD_NAMESPACE), "ResolveMatches"),
            (Some(XML_WSD_NAMESPACE), "ResolveMatch"),
        ],
    )?;

    let (endpoint, raw_xaddrs) = extract_endpoint_metadata(reader)?;

    let Some(raw_xaddrs) = raw_xaddrs else {
        event!(Level::DEBUG, "ResolveMatch without xaddr, nothing to do");

        return Ok(());
    };

    let xaddrs = parse_xaddrs(bound_to.address, &raw_xaddrs);

    if xaddrs.is_empty() {
        event!(Level::ERROR, "No valid URL in xaddrs");

        return Ok(());
    }

    event!(Level::INFO, %endpoint, xaddrs = %SliceDisplay(&xaddrs), "ResolveMatch");

    perform_metadata_exchange(
        client,
        config,
        devices,
        bound_to,
        endpoint,
        xaddrs.into_iter().map(Into::into).collect(),
    )
    .await?;

    Ok(())
}

async fn perform_metadata_exchange(
    client: &reqwest::Client,
    config: &Config,
    devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,
    bound_to: &NetworkAddress,
    endpoint: DeviceUri,
    xaddrs: Vec<Url>,
) -> Result<(), eyre::Report> {
    let body = Bytes::from_owner(build_getmetadata_message(config, &endpoint)?);

    for xaddr in xaddrs {
        let builder = client
            .post(xaddr.clone())
            .header("Content-Type", MIME_TYPE_SOAP_XML)
            .header("User-Agent", "wsdd-rs");

        let response = builder
            .body(body.clone())
            .timeout(config.metadata_timeout)
            .send()
            .await;

        let response = match response {
            Ok(response) => response.bytes().await,
            Err(error) => Err(error),
        };

        match response {
            Ok(response) => {
                return handle_metadata(devices, &response, endpoint, xaddr, bound_to).await;
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
    }

    Ok(())
}

fn build_getmetadata_message(
    config: &Config,
    endpoint: &DeviceUri,
) -> Result<Vec<u8>, xml::writer::Error> {
    let message = Builder::build_get(config, endpoint)?;

    Ok(message)
}

async fn handle_metadata(
    devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,
    meta: &[u8],
    endpoint: DeviceUri,
    xaddr: Url,
    bound_to: &NetworkAddress,
) -> Result<(), eyre::Report> {
    let device_uuid = endpoint;

    match devices.write().await.entry(device_uuid) {
        hashbrown::hash_map::Entry::Occupied(mut occupied_entry) => {
            occupied_entry.get_mut().update(meta, &xaddr, bound_to)?;
        },
        hashbrown::hash_map::Entry::Vacant(vacant_entry) => {
            vacant_entry.insert(WSDDiscoveredDevice::new(meta, &xaddr, bound_to)?);
        },
    }

    Ok(())
}

#[expect(clippy::too_many_arguments, reason = "WIP")]
async fn listen_forever(
    bound_to: NetworkAddress,
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,
    mut mc_wsd_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
    mut mc_local_port_rx: Receiver<(SocketAddr, Arc<[u8]>)>,
    mc_local_port_tx: Sender<Box<[u8]>>,
    probes: Arc<RwLock<HashMap<Urn, Duration>>>,
) {
    // Note: we bind on the interface's name.
    // This is to ensure we send out requests via the interface that we received the XML message on
    // This is especially important when using IPv6 and resolving `fe80::` addresses which are local to the interface.
    // Using `.local_address()` didn't work with IPv6, because `fe80::` addresses (the ones we bind on) don't specify
    // to which interface they belong
    let client = reqwest::ClientBuilder::new()
        .interface(bound_to.interface.name())
        .build()
        .expect("WSD Client cannot operate without HTTP Client");

    let message_handler = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES), bound_to.clone());

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

        let (header, mut body_reader) = match message_handler
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
            WSD_HELLO => {
                handle_hello(
                    &client,
                    &config,
                    Arc::clone(&devices),
                    &bound_to,
                    &mc_local_port_tx,
                    &mut body_reader,
                )
                .await
            },
            WSD_BYE => handle_bye(Arc::clone(&devices), &mut body_reader).await,
            WSD_PROBE_MATCH => {
                handle_probe_match(
                    &client,
                    &config,
                    Arc::clone(&devices),
                    &bound_to,
                    header.relates_to,
                    Arc::clone(&probes),
                    &mc_local_port_tx,
                    &mut body_reader,
                )
                .await
            },
            WSD_RESOLVE_MATCH => {
                handle_resolve_match(
                    &client,
                    &config,
                    Arc::clone(&devices),
                    &bound_to,
                    &mut body_reader,
                )
                .await
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

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
    use std::sync::Arc;
    use std::time::Duration;

    use hashbrown::HashMap;
    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use libc::RT_SCOPE_SITE;
    use mockito::ServerOpts;
    use pretty_assertions::{assert_eq, assert_matches};
    use tokio::sync::RwLock;
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio_util::sync::CancellationToken;
    use tracing_test::traced_test;
    use url::Url;
    use uuid::Uuid;

    use crate::network_interface::NetworkInterface;
    use crate::test_utils::xml::to_string_pretty;
    use crate::test_utils::{build_config, build_message_handler_with_network_address};
    use crate::wsd::device::DeviceUri;
    use crate::wsd::udp::client::{
        WSDClient, handle_bye, handle_hello, handle_metadata, handle_probe_match,
        handle_resolve_match, parse_xaddrs,
    };

    #[tokio::test]
    async fn handles_hello_without_xaddr() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));
        let client_config = Arc::new(build_config(Uuid::now_v7(), "client-instance-id"));

        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);

        let host_endpoint_device_uri =
            DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());
        let hello_without_xaddrs = format!(
            include_str!("../../test/hello-without-xaddrs-template.xml"),
            Uuid::now_v7(),
            host_endpoint_device_uri
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (_, mut reader) = message_handler
            .deconstruct_message(
                hello_without_xaddrs.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_hello(
            &reqwest::ClientBuilder::new().build().unwrap(),
            &client_config,
            Arc::clone(&client_devices),
            &client_network_address,
            &multicast_tx,
            &mut reader,
        )
        .await
        .unwrap();

        let expected = format!(
            include_str!("../../test/resolve-template.xml"),
            Uuid::nil(),
            &host_endpoint_device_uri,
        );

        let response = {
            let response = multicast_rx.try_recv().unwrap();

            to_string_pretty(&response).unwrap()
        };

        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(expected, response);
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_hello_with_xaddr() {
        let (message_handler, bound_to) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::LOCALHOST).into(), 8).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));
        let client_config = Arc::new(build_config(Uuid::now_v7(), "client-instance-id"));

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
        let host_message_id = Uuid::now_v7();
        let host_instance_id = "host-instance-id";
        let host_endpoint_uuid = Uuid::now_v7();
        let host_endpoint_device_uri =
            DeviceUri::new(host_endpoint_uuid.as_urn().to_string().into_boxed_str());

        let expected_get = format!(
            include_str!("../../test/get-template.xml"),
            host_endpoint_device_uri, client_config.uuid_as_device_uri
        );

        let mock = server
            .mock("POST", &*format!("/{}", host_endpoint_uuid))
            .with_status(200)
            .with_body_from_request(move |request| {
                let metadata: String = format!(
                    include_str!("../../test/get-response-synology.xml"),
                    Uuid::now_v7(),
                    Uuid::now_v7(),
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
            include_str!("../../test/hello-with-xaddrs-template.xml"),
            host_message_id,
            host_instance_id,
            Uuid::now_v7(),
            host_endpoint_device_uri,
            host_ip,
            host_port,
            host_endpoint_uuid
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (_, mut reader) = message_handler
            .deconstruct_message(
                hello.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_hello(
            &reqwest::ClientBuilder::new().build().unwrap(),
            &client_config,
            Arc::clone(&client_devices),
            &bound_to,
            &multicast_tx,
            &mut reader,
        )
        .await
        .unwrap();

        // we expect no resolve to be sent
        multicast_rx.try_recv().unwrap_err();

        // ensure the mock is hit
        mock.assert_async().await;

        let client_devices = client_devices.read().await;

        let device = client_devices.get(&host_endpoint_device_uri);

        assert!(device.is_some());

        let device = device.unwrap();

        let expected_props = HashMap::from_iter([
            ("BelongsTo", "Workgroup:WORKGROUP"),
            ("DisplayName", "diskstation"),
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

        assert_eq!(expected_props, device_props);
    }

    #[tokio::test]
    async fn handles_bye() {
        let (message_handler, _client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));

        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);

        let host_endpoint_uuid =
            DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());
        let host_instance_id = "host-instance-id";
        let bye = format!(
            include_str!("../../test/bye-template.xml"),
            Uuid::now_v7(),
            host_instance_id,
            Uuid::now_v7(),
            0,
            host_endpoint_uuid
        );

        let (_, mut reader) = message_handler
            .deconstruct_message(
                bye.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_bye(Arc::clone(&client_devices), &mut reader)
            .await
            .unwrap();
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    #[expect(
        clippy::too_many_lines,
        reason = "End to end test of `handles_hello` & `handles_bye`"
    )]
    async fn handles_hello_bye() {
        let (message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::LOCALHOST).into(), 8).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));
        let client_config = Arc::new(build_config(Uuid::now_v7(), "client-instance-id"));

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
        let _host_message_id = Uuid::now_v7();
        let host_instance_id = "host-instance-id";
        let host_endpoint_uuid = Uuid::now_v7();
        let host_endpoint_device_uri =
            DeviceUri::new(host_endpoint_uuid.as_urn().to_string().into_boxed_str());

        let expected_get = format!(
            include_str!("../../test/get-template.xml"),
            host_endpoint_device_uri, client_config.uuid_as_device_uri
        );

        let mock = server
            .mock("POST", &*format!("/{}", host_endpoint_uuid))
            .with_status(200)
            .with_body_from_request(move |request| {
                let metadata: String = format!(
                    include_str!("../../test/get-response-synology.xml"),
                    Uuid::now_v7(),
                    Uuid::now_v7(),
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
            include_str!("../../test/hello-with-xaddrs-template.xml"),
            Uuid::now_v7(),
            host_instance_id,
            Uuid::now_v7(),
            host_endpoint_device_uri,
            host_ip,
            host_port,
            host_endpoint_uuid
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (_, mut reader) = message_handler
            .deconstruct_message(
                hello.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_hello(
            &reqwest::ClientBuilder::new().build().unwrap(),
            &client_config,
            Arc::clone(&client_devices),
            &network_address,
            &multicast_tx,
            &mut reader,
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
                .contains_key(&host_endpoint_device_uri)
        );

        // and now the bye
        let bye = format!(
            include_str!("../../test/bye-template.xml"),
            Uuid::now_v7(),
            host_instance_id,
            Uuid::now_v7(),
            0,
            host_endpoint_device_uri
        );

        let (_, mut reader) = message_handler
            .deconstruct_message(
                bye.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_bye(Arc::clone(&client_devices), &mut reader)
            .await
            .unwrap();

        // ensure the host is no longer present
        assert!(
            !client_devices
                .read()
                .await
                .contains_key(&host_endpoint_device_uri)
        );
    }

    #[tokio::test]
    async fn sends_probe() {
        let cancellation_token = CancellationToken::new();

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));
        let client_config = Arc::new(build_config(Uuid::now_v7(), "client-instance-id"));

        let (_mc_wsd_port_tx, mc_wsd_port_rx) = tokio::sync::mpsc::channel(10);
        let (_mc_local_port_tx, mc_local_port_rx) = tokio::sync::mpsc::channel(10);
        let (uc_wsd_port_tx, mut uc_wsd_port_rx) = tokio::sync::mpsc::channel(10);

        let bound_to = crate::network_address::NetworkAddress::new(
            Ipv4Net::new(Ipv4Addr::new(192, 168, 100, 5), 24)
                .unwrap()
                .into(),
            Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
        );

        let _client = WSDClient::init(
            cancellation_token.child_token(),
            client_config,
            client_devices,
            bound_to,
            mc_wsd_port_rx,
            mc_local_port_rx,
            uc_wsd_port_tx,
        );

        let probe = uc_wsd_port_rx.recv().await.unwrap();

        let expected = format!(
            include_str!("../../test/probe-template-wsdp-device.xml"),
            Uuid::nil()
        );

        let response = to_string_pretty(&probe).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(expected, response);
    }

    #[tokio::test]
    async fn handles_metadata_synology() {
        let (_message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));

        let metadata: String = format!(
            include_str!("../../test/get-response-synology.xml"),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );

        let device_uri = DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());

        let result = handle_metadata(
            Arc::clone(&client_devices),
            metadata.as_bytes(),
            device_uri.clone(),
            Url::parse("http://diskstation:5357/2e91b960-d258-43d6-989b-a24f108f1721").unwrap(),
            &client_network_address,
        )
        .await;

        assert_matches!(result, Ok(()));

        let client_devices = client_devices.read().await;

        let device = client_devices.get(&device_uri);

        assert!(device.is_some());

        let device = device.unwrap();

        let expected_props = HashMap::from_iter([
            ("BelongsTo", "Workgroup:WORKGROUP"),
            ("DisplayName", "diskstation"),
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

        assert_eq!(expected_props, device_props);
    }

    #[tokio::test]
    async fn handles_metadata_samsung_printer() {
        let (_message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));

        let metadata: String = format!(
            include_str!("../../test/get-response-samsung-printer.xml"),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );

        let device_uri = DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());

        let result = handle_metadata(
            Arc::clone(&client_devices),
            metadata.as_bytes(),
            device_uri.clone(),
            Url::parse("http://192.168.100.50:8018/wsd").unwrap(),
            &client_network_address,
        )
        .await;

        assert_matches!(result, Ok(()));

        let client_devices = client_devices.read().await;

        let device = client_devices.get(&device_uri);

        assert!(device.is_some());

        let device = device.unwrap();

        let expected_props = HashMap::from_iter([
            ("SerialNumber", "123456789101112"),
            ("PresentationUrl", "http://192.168.100.50"),
            ("Manufacturer", "Samsung Electronics Co., Ltd."),
            ("FriendlyName", "Samsung M2020W"),
            ("ModelNumber", "M2020 Series"),
            ("ManufacturerUrl", "http://www.samsungprinter.com"),
            ("FirmwareVersion", "V3.00.01.23 AUG-16-2018"),
            ("ModelName", "M2020 Series"),
            ("ModelUrl", "http://www.samsungprinter.com"),
        ]);

        let device_props = device
            .props()
            .iter()
            .map(|(key, value)| (&**key, &**value))
            .collect::<HashMap<_, _>>();

        assert_eq!(expected_props, device_props);
    }

    #[tokio::test]
    async fn handles_metadata_windows() {
        let (_message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));

        let metadata: String = format!(
            include_str!("../../test/get-response-windows.xml"),
            Uuid::now_v7(),
            Uuid::now_v7(),
        );

        let device_uri = DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());

        let result = handle_metadata(
            Arc::clone(&client_devices),
            metadata.as_bytes(),
            device_uri.clone(),
            Url::parse("http://192.168.100.71:5357/18de7c97-6277-43fe-9552-cac98a7610f5/").unwrap(),
            &client_network_address,
        )
        .await;

        assert_matches!(result, Ok(()));

        let client_devices = client_devices.read().await;

        let device = client_devices.get(&device_uri);

        assert!(device.is_some());

        let device = device.unwrap();

        let expected_props = HashMap::from_iter([
            ("BelongsTo", "Workgroup:WORKGROUP"),
            ("DisplayName", "LAPTOP-TEST"),
            ("FirmwareVersion", "1.0"),
            ("FriendlyName", "Microsoft Publication Service Device Host"),
            ("Manufacturer", "Microsoft Corporation"),
            ("ManufacturerUrl", "http://www.microsoft.com"),
            ("ModelName", "Microsoft Publication Service"),
            ("ModelNumber", "1"),
            ("ModelUrl", "http://www.microsoft.com"),
            ("PresentationUrl", "http://www.microsoft.com"),
            ("SerialNumber", "20050718"),
        ]);

        let device_props = device
            .props()
            .iter()
            .map(|(key, value)| (&**key, &**value))
            .collect::<HashMap<_, _>>();

        assert_eq!(expected_props, device_props);
    }

    #[tokio::test]
    async fn handles_probe_matches_without_xaddrs() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));
        let client_config = Arc::new(build_config(Uuid::now_v7(), "client-instance-id"));

        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_endpoint_uuid = Uuid::now_v7();
        let host_endpoint_device_uri =
            DeviceUri::new(host_endpoint_uuid.as_urn().to_string().into_boxed_str());
        let host_instance_id = "host-instance-id";
        let host_message_id = Uuid::now_v7();

        let probe_matches = format!(
            include_str!("../../test/probe-matches-without-xaddrs-template.xml"),
            host_message_id, host_instance_id, 0, host_endpoint_device_uri
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (header, mut reader) = message_handler
            .deconstruct_message(
                probe_matches.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        let probes = {
            let mut hash_map = HashMap::new();

            hash_map.insert(host_message_id.urn(), Duration::from_secs(100));

            Arc::new(RwLock::new(hash_map))
        };

        handle_probe_match(
            &reqwest::ClientBuilder::new().build().unwrap(),
            &client_config,
            Arc::clone(&client_devices),
            &client_network_address,
            header.relates_to,
            probes,
            &multicast_tx,
            &mut reader,
        )
        .await
        .unwrap();

        let expected = format!(
            include_str!("../../test/resolve-template.xml"),
            Uuid::nil(),
            &host_endpoint_device_uri,
        );

        let response = {
            let response = multicast_rx.try_recv().unwrap();

            to_string_pretty(&response).unwrap()
        };

        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(expected, response);
    }

    #[tokio::test]
    async fn handles_probe_matches_with_xaddrs() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));
        let client_config = Arc::new(build_config(Uuid::now_v7(), "client-instance-id"));

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
        let host_message_id = Uuid::now_v7();
        let host_instance_id = "host-instance-id";
        let host_endpoint_uuid = Uuid::now_v7();
        let host_endpoint_device_uri =
            DeviceUri::new(host_endpoint_uuid.as_urn().to_string().into_boxed_str());

        let expected_get = format!(
            include_str!("../../test/get-template.xml"),
            host_endpoint_device_uri, client_config.uuid_as_device_uri
        );

        let mock = server
            .mock("POST", &*format!("/{}", host_endpoint_uuid))
            .with_status(200)
            .with_body_from_request(move |request| {
                let metadata: String = format!(
                    include_str!("../../test/get-response-synology.xml"),
                    Uuid::now_v7(),
                    Uuid::now_v7(),
                );

                assert_eq!(
                    to_string_pretty(expected_get.as_bytes()).unwrap(),
                    to_string_pretty(request.body().unwrap()).unwrap()
                );

                metadata.into()
            })
            .create_async()
            .await;

        let probe_matches = format!(
            include_str!("../../test/probe-matches-with-xaddrs-template.xml"),
            host_message_id,
            host_instance_id,
            0,
            host_endpoint_device_uri,
            host_ip,
            host_port,
            host_endpoint_uuid
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (header, mut reader) = message_handler
            .deconstruct_message(
                probe_matches.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        let probes = {
            let mut hash_map = HashMap::new();

            hash_map.insert(host_message_id.urn(), Duration::from_secs(100));

            Arc::new(RwLock::new(hash_map))
        };

        handle_probe_match(
            &reqwest::ClientBuilder::new().build().unwrap(),
            &client_config,
            Arc::clone(&client_devices),
            &client_network_address,
            header.relates_to,
            probes,
            &multicast_tx,
            &mut reader,
        )
        .await
        .unwrap();

        // ensure the mock is hit
        mock.assert_async().await;

        assert_matches!(multicast_rx.try_recv(), Err(TryRecvError::Empty));

        let client_devices = client_devices.read().await;

        assert_matches!(client_devices.get(&host_endpoint_device_uri), Some(_));
    }

    #[tokio::test]
    async fn handles_resolve_matches() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(HashMap::new()));
        let client_config = Arc::new(build_config(Uuid::now_v7(), "client-instance-id"));

        // host
        let mut server = mockito::Server::new_with_opts_async(ServerOpts {
            // a host in IPv4 form ensures we bind to an IPv4 address
            host: "127.0.0.1",
            port: 5357,
            assert_on_drop: true,
        })
        .await;

        let IpAddr::V4(host_ip) = server.socket_address().ip() else {
            panic!("Invalid test setup");
        };
        let _host_port = server.socket_address().port();
        let host_message_id = Uuid::now_v7();
        let host_instance_id = "host-instance-id";
        let host_endpoint_uuid = Uuid::now_v7();
        let host_endpoint_device_uri =
            DeviceUri::new(host_endpoint_uuid.as_urn().to_string().into_boxed_str());

        let expected_get = format!(
            include_str!("../../test/get-template.xml"),
            host_endpoint_device_uri, client_config.uuid_as_device_uri
        );

        let mock = server
            .mock("POST", &*format!("/{}", host_endpoint_uuid))
            .with_status(200)
            .with_body_from_request(move |request| {
                let metadata: String = format!(
                    include_str!("../../test/get-response-synology.xml"),
                    Uuid::now_v7(),
                    Uuid::now_v7(),
                );

                assert_eq!(
                    to_string_pretty(expected_get.as_bytes()).unwrap(),
                    to_string_pretty(request.body().unwrap()).unwrap()
                );

                metadata.into()
            })
            .create_async()
            .await;

        let resolve_matches = format!(
            include_str!("../../test/resolve-matches-template.xml"),
            host_message_id,
            host_instance_id,
            0,
            host_endpoint_device_uri,
            host_ip,
            host_endpoint_uuid
        );

        let (_, mut reader) = message_handler
            .deconstruct_message(
                resolve_matches.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(host_ip, 5000))),
            )
            .await
            .unwrap();

        handle_resolve_match(
            &reqwest::ClientBuilder::new().build().unwrap(),
            &client_config,
            Arc::clone(&client_devices),
            &client_network_address,
            &mut reader,
        )
        .await
        .unwrap();

        // ensure the mock is hit
        mock.assert_async().await;

        let client_devices = client_devices.read().await;

        assert_matches!(client_devices.get(&host_endpoint_device_uri), Some(_));
    }

    #[test]
    #[traced_test]
    fn filters_invalid_and_non_http_https() {
        let bound = IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 10), 24).unwrap());

        let result = parse_xaddrs(
            bound,
            "http://valid.example.com https://also.valid ftp://ignored https:///#nohost",
        );

        let raws = result
            .iter()
            .map(|xaddr| xaddr.get_url().as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            ["http://valid.example.com/", "https://also.valid/"][..],
            raws
        );
    }

    #[test]
    #[traced_test]
    fn rejects_missing_host() {
        let bound = IpNet::V4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 24).unwrap());

        let result = parse_xaddrs(
            bound,
            "http:////?missinghost=missing https://example.com/path",
        );

        let raws = result
            .iter()
            .map(|xaddr| xaddr.get_url().as_str())
            .collect::<Vec<_>>();

        assert_eq!(["https://example.com/path"][..], raws);
    }

    #[test]
    #[traced_test]
    fn prefers_link_local_ipv6_first() {
        let bound =
            IpNet::V6(Ipv6Net::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64).unwrap());

        let result = parse_xaddrs(
            bound,
            "https://[2001:db8::1]/global https://[fe80::abcd]/local",
        );

        let raws = result
            .iter()
            .map(|xaddr| xaddr.get_url().as_str())
            .collect::<Vec<_>>();

        // link-local must be sorted first
        assert_eq!(Some("https://[fe80::abcd]/local"), raws.first().copied());
    }
}
