use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use color_eyre::eyre;
use hashbrown::HashMap;
use quick_xml::NsReader;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use url::{Host, Url};
use uuid::Uuid;
use uuid::fmt::Urn;

use super::HANDLED_MESSAGES;
use crate::config::Config;
use crate::constants::{self, APP_MAX_DELAY, PROBE_TIMEOUT};
use crate::soap::builder::{Builder, MessageType};
use crate::soap::parser::{self, MessageHandler, MessageHandlerError};
use crate::utils::task::spawn_with_name;
use crate::wsd::device;
use crate::wsd::device::WSDDiscoveredDevice;

#[expect(dead_code)]
pub(crate) struct WSDClient {
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    address: IpAddr,
    multicast: Sender<Box<[u8]>>,
    probes: HashMap<Urn, u128>,
}

///
/// * `recv_socket_receiver`: used to receive multicast messages on `WSD_PORT`
/// * `mc_send_socket_receiver`: used to receive unicast messages sent directly to us
/// * `multicast`: use to send multicast messages, from a random port to `WSD_PORT`
/// * `unicast`: used to send unicast messages FROM `WSD_PORT` to ...
impl WSDClient {
    pub async fn init(
        cancellation_token: &CancellationToken,
        config: Arc<Config>,
        address: IpAddr,
        mc_send_socket_receiver: Receiver<(SocketAddr, Arc<[u8]>)>,
        multicast: Sender<Box<[u8]>>,
        unicast: Sender<(SocketAddr, Box<[u8]>)>,
    ) -> Self {
        let cancellation_token = cancellation_token.child_token();

        spawn_receiver_loop(
            cancellation_token.clone(),
            Arc::clone(&config),
            address,
            mc_send_socket_receiver,
            multicast.clone(),
            unicast,
        );

        let mut client = Self {
            cancellation_token,
            config,
            address,
            multicast: multicast.clone(),
            probes: HashMap::new(),
        };

        // avoid packet storm when hosts come up by delaying initial probe
        tokio::time::sleep(Duration::from_millis(rand::random_range(0..=APP_MAX_DELAY))).await;

        if let Err(err) = client.send_probe().await {
            event!(Level::ERROR, ?err, "Failed to send probe");
        }

        client
    }

    #[expect(clippy::unused_async)]
    pub async fn teardown(self, graceful: bool) {
        self.cancellation_token.cancel();

        if graceful {
            // ??
        }
    }

    // WS-Discovery, Section 4.3, Probe message
    async fn send_probe(&mut self) -> Result<(), eyre::Report> {
        self.remove_outdated_probes();

        let (probe, message_id) = Builder::build_probe(&self.config)?;

        self.probes.insert(message_id, now());

        // deviation, we can't write that we're scheduling it with the same data, as we don't have the knowledge
        // TODO move event to here and write properly
        event!(Level::INFO, "scheduling {} message", MessageType::Probe);

        self.multicast.send(probe.into_boxed_slice()).await?;

        Ok(())
    }

    fn remove_outdated_probes(&mut self) {
        let now = now();

        self.probes
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

        if bound_to.is_ipv6() {
            //      if (self.mch.address.family == socket.AF_INET6) and ('//[fe80::' in addr):
            //          # use first link-local address for IPv6
            match addr.host() {
                Some(Host::Ipv6(ipv6)) if ipv6.is_unicast_link_local() => {
                    return Some(addr);
                },
                _ => continue,
            }
        } else if bound_to.is_ipv4() {
            //  use first (and very likely the only) IPv4 address
            return Some(addr);
        }
    }

    None
}

async fn handle_hello<'reader>(
    config: &Config,
    bound_to: IpAddr,
    multicast: &Sender<Box<[u8]>>,
    mut reader: NsReader<&'reader [u8]>,
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

    let Some(xaddr) = __extract_xaddr(bound_to, &xaddrs) else {
        return Ok(());
    };

    event!(Level::INFO, "Hello from {} on {}", endpoint, xaddr);

    perform_metadata_exchange(config, endpoint, xaddr).await?;

    Ok(())
}

//     def handle_bye(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
//         bye_path = 'wsd:Bye'
//         endpoint, _ = self.extract_endpoint_metadata(body, bye_path)
//         device_uuid = str(uuid.UUID(endpoint))
//         if device_uuid in WSDDiscoveredDevice.instances:
//             del WSDDiscoveredDevice.instances[device_uuid]

//         return None

//     def handle_probe_match(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
//         # do not handle to probematches issued not sent by ourself
//         rel_msg = header.findtext('wsa:RelatesTo', None, namespaces)
//         if rel_msg not in self.probes:
//             logger.debug("unknown probe {}".format(rel_msg))
//             return None

//         # if XAddrs are missing, issue resolve request
//         pm_path = 'wsd:ProbeMatches/wsd:ProbeMatch'
//         endpoint, xaddrs = self.extract_endpoint_metadata(body, pm_path)
//         if not xaddrs:
//             logger.debug('probe match without XAddrs, sending resolve')
//             msg = self.build_resolve_message(str(endpoint))
//             self.enqueue_datagram(msg, self.mch.multicast_address)
//             return None

//         xaddr = self.__extract_xaddr(xaddrs)
//         if xaddr is None:
//             return None

//         logger.debug('probe match for {} on {}'.format(endpoint, xaddr))
//         self.perform_metadata_exchange(endpoint, xaddr)

//         return None

//     def build_resolve_message(self, endpoint: str) -> str:
//         resolve = ElementTree.Element('wsd:Resolve')
//         self.add_endpoint_reference(resolve, endpoint)

//         return self.build_message(WSA_DISCOVERY, WSD_RESOLVE, None, resolve)

//     def handle_resolve_match(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
//         rm_path = 'wsd:ResolveMatches/wsd:ResolveMatch'
//         endpoint, xaddrs = self.extract_endpoint_metadata(body, rm_path)
//         if not endpoint or not xaddrs:
//             logger.debug('resolve match without endpoint/xaddr')
//             return None

//         xaddr = self.__extract_xaddr(xaddrs)
//         if xaddr is None:
//             return None

//         logger.debug('resolve match for {} on {}'.format(endpoint, xaddr))
//         self.perform_metadata_exchange(endpoint, xaddr)

//         return None

//     def extract_endpoint_metadata(self, body: ElementTree.Element, prefix: str) -> Tuple[Optional[str], Optional[str]]:
//         prefix = prefix + '/'
//         addr_path = 'wsa:EndpointReference/wsa:Address'

//         endpoint = body.findtext(prefix + addr_path, namespaces=namespaces)
//         xaddrs = body.findtext(prefix + 'wsd:XAddrs', namespaces=namespaces)

//         return endpoint, xaddrs

//     def perform_metadata_exchange(self, endpoint, xaddr: str):
async fn perform_metadata_exchange(
    config: &Config,
    endpoint: Uuid,
    xaddr: Url,
) -> Result<(), eyre::Report> {
    let scheme = xaddr.scheme();

    if !matches!(scheme, "http" | "https") {
        event!(Level::DEBUG, "invalid XAddr: {}", xaddr);
        return Ok(());
    }

    //         host = None
    //         url = xaddr
    //         if self.mch.address.family == socket.AF_INET6:
    //             host = '[{}]'.format(url.partition('[')[2].partition(']')[0])
    //             url = url.replace(']', '%{}]'.format(self.mch.address.interface))

    let body = build_getmetadata_message(config, endpoint)?;

    let client = reqwest::Client::new();
    let builder = client
        .post(xaddr.clone())
        .header("Content-Type", "application/soap+xml")
        .header("User-Agent", "wsdd");

    //         if host is not None:
    //             request.add_header('Host', host)

    #[expect(clippy::cast_possible_truncation)]
    #[expect(clippy::cast_sign_loss)]
    let timeout = (config.metadata_timeout * 1000f32) as u64;

    let response = builder
        .body(body)
        .timeout(Duration::from_millis(timeout))
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

//     def add_header_elements(self, header: ElementTree.Element, extra: Any) -> None:
//         action_str = extra
//         if action_str == WSD_GET:
//             reply_to = ElementTree.SubElement(header, 'wsa:ReplyTo')
//             addr = ElementTree.SubElement(reply_to, 'wsa:Address')
//             addr.text = WSA_ANON

//             wsa_from = ElementTree.SubElement(header, 'wsa:From')
//             addr = ElementTree.SubElement(wsa_from, 'wsa:Address')
//             addr.text = args.uuid.urn

fn spawn_receiver_loop(
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    bound_to: IpAddr,
    mut multicast_receiver: Receiver<(SocketAddr, Arc<[u8]>)>,
    multicast: Sender<Box<[u8]>>,
    _unicast: Sender<(SocketAddr, Box<[u8]>)>,
) {
    let message_handler = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES));

    spawn_with_name(format!("wsd host ({})", bound_to).as_str(), async move {
        loop {
            let message = tokio::select! {
                () = cancellation_token.cancelled() => {
                    break;
                },
                message = multicast_receiver.recv() => {
                    message
                }
            };

            let Some((_from, buffer)) = message else {
                // the end, but we just got it before the cancellation
                break;
            };

            let (message_id, action, body_reader) =
                match message_handler.deconstruct_message(&buffer).await {
                    Ok(pieces) => pieces,
                    Err(error) => {
                        match error {
                            MessageHandlerError::DuplicateMessage => {
                                // nothing
                            },
                            missing @ (MessageHandlerError::MissingAction
                            | MessageHandlerError::MissingBody
                            | MessageHandlerError::MissingMessageId) => {
                                event!(
                                    Level::TRACE,
                                    ?missing,
                                    "XML Message did not have required elements: {}",
                                    String::from_utf8_lossy(&buffer)
                                );
                            },
                            MessageHandlerError::XmlError(error) => {
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
            if let Err(err) = match action.as_ref() {
                constants::WSD_HELLO => {
                    handle_hello(&config, bound_to, &multicast, body_reader).await
                },
                // constants::WSD_BYE => handle_bye(&config, &message_id, body_reader),
                // constants::WSD_PROBE_MATCH => handle_probe_match(&config, &message_id, body_reader),
                // constants::WSD_RESOLVE_MATCH => {
                //     handle_resolve_match(&config, &message_id, body_reader)
                // },
                _ => {
                    event!(Level::DEBUG, "unhandled action {}/{}", action, message_id);
                    continue;
                },
            } {
                event!(Level::ERROR, ?action, ?err, "Failure to parse XML");
                continue;
            }
        }
    });
}
