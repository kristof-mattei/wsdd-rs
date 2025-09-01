use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use color_eyre::eyre;
use hashbrown::HashMap;
use quick_xml::NsReader;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use url::{Host, Url};
use uuid::Uuid;
use uuid::fmt::Urn;

use super::HANDLED_MESSAGES;
use crate::config::Config;
use crate::constants::{self, APP_MAX_DELAY, PROBE_TIMEOUT};
use crate::network_address::NetworkAddress;
use crate::soap::builder::{Builder, MessageType};
use crate::soap::parser::generic::extract_endpoint_metadata;
use crate::soap::parser::{self, HeaderError, MessageHandler, MessageHandlerError};
use crate::utils::task::spawn_with_name;
use crate::wsd::device;
use crate::wsd::device::WSDDiscoveredDevice;

#[expect(unused, reason = "WIP")]
pub(crate) struct WSDClient {
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    address: IpAddr,
    multicast: Sender<Box<[u8]>>,
    probes: Arc<RwLock<HashMap<Urn, u128>>>,
}

/// * `recv_socket_receiver`: used to receive multicast messages on `WSD_PORT`
/// * `mc_send_socket_receiver`: used to receive unicast messages sent directly to us
/// * `multicast`: use to send multicast messages, from a random port to `WSD_PORT`
/// * `unicast`: used to send unicast messages FROM `WSD_PORT` to ...
impl WSDClient {
    pub async fn init(
        cancellation_token: &CancellationToken,
        config: Arc<Config>,
        network_address: NetworkAddress,
        recv_socket_receiver: Receiver<(SocketAddr, Arc<[u8]>)>,
        mc_send_socket_receiver: Receiver<(SocketAddr, Arc<[u8]>)>,
        multicast: Sender<Box<[u8]>>,
        unicast: Sender<(SocketAddr, Box<[u8]>)>,
    ) -> Self {
        let cancellation_token = cancellation_token.child_token();

        let address = network_address.address;

        let probes = Arc::new(RwLock::new(HashMap::<Urn, u128>::new()));

        spawn_receiver_loop(
            cancellation_token.clone(),
            Arc::clone(&config),
            network_address,
            recv_socket_receiver,
            mc_send_socket_receiver,
            multicast.clone(),
            unicast,
            Arc::clone(&probes),
        );

        let mut client = Self {
            cancellation_token,
            config,
            address,
            multicast,
            probes: Arc::clone(&probes),
        };

        // avoid packet storm when hosts come up by delaying initial probe
        tokio::time::sleep(Duration::from_millis(rand::random_range(0..=APP_MAX_DELAY))).await;

        if let Err(err) = client.send_probe().await {
            event!(Level::ERROR, ?err, "Failed to send probe");
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

        self.multicast.send(probe.into_boxed_slice()).await?;

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
    network_address: &NetworkAddress,
    multicast: &Sender<Box<[u8]>>,
    mut reader: NsReader<&[u8]>,
) -> Result<(), eyre::Report> {
    parser::generic::parse_generic_body(&mut reader, "Hello")?;

    let (endpoint, xaddrs) = parser::generic::extract_endpoint_metadata(&mut reader)?;

    let xaddrs = if let Some(xaddrs) = xaddrs {
        xaddrs
    } else {
        event!(Level::INFO, "Hello without XAddrs, sending resolve");

        let (message, _) = Builder::build_resolve(config, endpoint)?;

        multicast.send(message.into_boxed_slice()).await?;

        return Ok(());
    };

    let Some(xaddr) = __extract_xaddr(network_address.address, &xaddrs) else {
        return Ok(());
    };

    event!(Level::INFO, "Hello from {} on {}", endpoint, xaddr);

    perform_metadata_exchange(config, network_address, endpoint, xaddr).await?;

    Ok(())
}

async fn handle_bye(mut reader: NsReader<&[u8]>) -> Result<(), eyre::Report> {
    parser::generic::parse_generic_body(&mut reader, "Bye")?;

    let (endpoint, _) = parser::generic::extract_endpoint_metadata(&mut reader)?;

    let mut guard = device::INSTANCES.write().await;

    guard.remove(&endpoint);

    Ok(())
}

async fn handle_probe_match(
    config: &Config,
    network_address: &NetworkAddress,
    relates_to: Option<Urn>,
    probes: Arc<RwLock<HashMap<Urn, u128>>>,
    multicast: &Sender<Box<[u8]>>,
    mut reader: NsReader<&[u8]>,
) -> Result<(), eyre::Report> {
    let Some(relates_to) = relates_to else {
        event!(Level::DEBUG, "missing `RelatesTo`");
        return Ok(());
    };

    parser::generic::parse_generic_body_paths(&mut reader, &["ProbeMatches", "ProbeMatch"])?;

    // do not handle to probematches issued not sent by ourself
    if probes.read().await.get(&relates_to).is_none() {
        event!(Level::DEBUG, %relates_to, "unknown probe");
        return Ok(());
    }

    let (endpoint, xaddrs) = extract_endpoint_metadata(&mut reader)?;

    let Some(xaddrs) = xaddrs else {
        event!(Level::INFO, "probe match without XAddrs, sending resolve");

        let (message, _) = Builder::build_resolve(config, endpoint)?;

        multicast.send(message.into_boxed_slice()).await?;

        return Ok(());
    };

    let Some(xaddr) = __extract_xaddr(network_address.address, &xaddrs) else {
        return Ok(());
    };

    event!(Level::DEBUG, %endpoint, ?xaddr, "Probe match");

    perform_metadata_exchange(config, network_address, endpoint, xaddr).await?;

    Ok(())
}

async fn handle_resolve_match(
    config: &Config,
    network_address: &NetworkAddress,
    mut reader: NsReader<&[u8]>,
) -> Result<(), eyre::Report> {
    parser::generic::parse_generic_body_paths(&mut reader, &["ResolveMatches", "ResolveMatch"])?;

    let (endpoint, xaddrs) = extract_endpoint_metadata(&mut reader)?;

    let Some(xaddrs) = xaddrs else {
        event!(Level::DEBUG, "Resolve match without xaddr");

        return Ok(());
    };

    let Some(xaddr) = __extract_xaddr(network_address.address, &xaddrs) else {
        event!(
            Level::ERROR,
            "No valid URL in xaddr, but this is a bug in xaddr, where we're too strict"
        );

        return Ok(());
    };

    event!(Level::DEBUG, %endpoint, ?xaddr, "Resolve match");

    perform_metadata_exchange(config, network_address, endpoint, xaddr).await?;

    Ok(())
}

async fn perform_metadata_exchange(
    config: &Config,
    network_address: &NetworkAddress,
    endpoint: Uuid,
    xaddr: Url,
) -> Result<(), eyre::Report> {
    let scheme = xaddr.scheme();

    if !matches!(scheme, "http" | "https") {
        event!(Level::DEBUG, "invalid XAddr: {}", xaddr);
        return Ok(());
    }

    let body = build_getmetadata_message(config, endpoint)?;

    let client_builder = reqwest::ClientBuilder::new().local_address(network_address.address);

    let builder = client_builder
        .build()?
        .post(xaddr.clone())
        .header("Content-Type", "application/soap+xml")
        .header("User-Agent", "wsdd");

    let timeout = config.metadata_timeout;

    let response = builder
        .body(body)
        .timeout(Duration::from_secs_f32(timeout))
        .send()
        .await;

    match response {
        Ok(response) => {
            let response = response.text().await?;

            handle_metadata(response, endpoint, xaddr).await?;
        },
        Err(error) => {
            let url = error.url().map(ToString::to_string);
            let url = url.as_deref().unwrap_or("Failed to get URL from error");

            if error.is_timeout() {
                event!(Level::WARN, "metadata exchange with {} timed out", url);
            } else {
                event!(
                    Level::WARN,
                    "could not fetch metadata from: {} {:?}",
                    url,
                    error
                );
            }
        },
    }

    Ok(())
}

fn build_getmetadata_message(
    config: &Config,
    endpoint: Uuid,
) -> Result<Vec<u8>, quick_xml::errors::Error> {
    let message = Builder::build_get(config, endpoint)?;

    Ok(message)
}

//     def handle_metadata(self, meta: str, endpoint: str, xaddr: str) -> None:
async fn handle_metadata(meta: String, endpoint: Uuid, xaddr: Url) -> Result<(), eyre::Report> {
    let device_uuid = endpoint;

    match device::INSTANCES.write().await.entry(device_uuid) {
        hashbrown::hash_map::Entry::Occupied(mut occupied_entry) => {
            occupied_entry.get_mut().update(meta, xaddr);
        },
        hashbrown::hash_map::Entry::Vacant(vacant_entry) => {
            vacant_entry.insert(WSDDiscoveredDevice::new(meta, xaddr));
        },
    }

    Ok(())
}

#[expect(clippy::too_many_arguments, reason = "WIP")]
#[expect(clippy::too_many_lines, reason = "WIP")]
fn spawn_receiver_loop(
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    network_address: NetworkAddress,
    mut recv_socket_receiver: Receiver<(SocketAddr, Arc<[u8]>)>,
    mut mc_send_socket_receiver: Receiver<(SocketAddr, Arc<[u8]>)>,
    multicast: Sender<Box<[u8]>>,
    _unicast: Sender<(SocketAddr, Box<[u8]>)>,
    probes: Arc<RwLock<HashMap<Urn, u128>>>,
) {
    let message_handler =
        MessageHandler::new(Arc::clone(&HANDLED_MESSAGES), network_address.clone());

    spawn_with_name(
        format!("wsd host ({})", network_address.address).as_str(),
        async move {
            loop {
                #[expect(clippy::pattern_type_mismatch, reason = "Tokio")]
                let message = {
                    tokio::select! {
                        () = cancellation_token.cancelled() => {
                            break;
                        },
                        message = recv_socket_receiver.recv() => {
                            message
                        }
                        message = mc_send_socket_receiver.recv() => {
                            message
                        }
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
                        match error {
                            MessageHandlerError::DuplicateMessage => {
                                // nothing
                            },
                            missing @ (MessageHandlerError::MissingHeader
                            | MessageHandlerError::MissingBody) => {
                                event!(
                                    Level::TRACE,
                                    ?missing,
                                    "XML Message did not have required elements: {}",
                                    String::from_utf8_lossy(&buffer)
                                );
                            },
                            MessageHandlerError::HeaderError(
                                HeaderError::InvalidMessageId(uuid_error)
                                | HeaderError::InvalidRelatesTo(uuid_error),
                            ) => {
                                event!(
                                    Level::TRACE,
                                    ?uuid_error,
                                    "XML Message Header was malformed: {}",
                                    String::from_utf8_lossy(&buffer)
                                );
                            },
                            MessageHandlerError::HeaderError(
                                error
                                @ (HeaderError::MissingAction | HeaderError::MissingMessageId),
                            ) => {
                                event!(
                                    Level::TRACE,
                                    %error,
                                    "XML Message Header is missing pieces: {}",
                                    String::from_utf8_lossy(&buffer)
                                );
                            },
                            MessageHandlerError::HeaderError(HeaderError::XmlError(error))
                            | MessageHandlerError::XmlError(error) => {
                                event!(
                                    Level::ERROR,
                                    ?error,
                                    "Error while decoding XML: {}",
                                    String::from_utf8_lossy(&buffer)
                                );
                            },
                        }

                        continue;
                    },
                };

                // handle based on action
                if let Err(err) = match &*header.action {
                    constants::WSD_HELLO => {
                        handle_hello(&config, &network_address, &multicast, body_reader).await
                    },
                    constants::WSD_BYE => handle_bye(body_reader).await,
                    constants::WSD_PROBE_MATCH => {
                        handle_probe_match(
                            &config,
                            &network_address,
                            header.relates_to,
                            Arc::clone(&probes),
                            &multicast,
                            body_reader,
                        )
                        .await
                    },
                    constants::WSD_RESOLVE_MATCH => {
                        handle_resolve_match(&config, &network_address, body_reader).await
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
                        ?err,
                        "Failure to parse XML"
                    );
                    continue;
                }
            }
        },
    );
}
