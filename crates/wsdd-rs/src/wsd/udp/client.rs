use std::cmp::Reverse;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use color_eyre::eyre;
use hashbrown::HashMap;
use ipnet::IpNet;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::oneshot::error::TryRecvError;
use tokio::sync::{RwLock, oneshot};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{Instrument as _, Level, event, span};
use url::Host;
use uuid::fmt::Urn;
use vec1::Vec1;

use crate::config::Config;
use crate::constants;
use crate::multicast_handler::{IncomingClientMessage, OutgoingMulticastMessage};
use crate::network_address::NetworkAddress;
use crate::soap::builder::Builder;
use crate::soap::parser::app_sequence::AppSequence;
use crate::soap::parser::bye::Bye;
use crate::soap::parser::hello::Hello;
use crate::soap::parser::probe_match::{ProbeMatch, ProbeMatches};
use crate::soap::parser::resolve_match::{ResolveMatch, ResolveMatches};
use crate::soap::parser::xaddrs::XAddr;
use crate::soap::{ClientMessage, MessageId, MulticastMessage};
use crate::task_tracker_ext::TaskTrackerExt as _;
use crate::utils::SliceDisplay;
use crate::utils::task::spawn_with_name;
use crate::wsd::device::DeviceUri;
use crate::wsd::devices::{Devices, Exchange, Fetch};

pub(crate) struct WSDClient {
    cancellation_token: CancellationToken,
    _bound_to: NetworkAddress,
    _devices: Arc<RwLock<Devices>>,
    handle: tokio::task::JoinHandle<()>,
    probe_tx: Sender<()>,
}

/// The send time of the last copy of a repeated `Probe` or `Resolve`.
enum LastCopy {
    Sending(oneshot::Receiver<Instant>),
    Sent(Instant),
}

impl LastCopy {
    fn track(message: MulticastMessage) -> (OutgoingMulticastMessage, Self) {
        let (last_copy_tx, last_copy_rx) = oneshot::channel();

        let message = OutgoingMulticastMessage {
            message,
            last_copy_tx: Some(last_copy_tx),
        };

        (message, LastCopy::Sending(last_copy_rx))
    }

    /// A match received `MATCH_TIMEOUT` or more after the last copy is discarded, see WS-Discovery, Section 7.
    fn accepts(&mut self, received_at: Instant) -> bool {
        let sent_at = match *self {
            LastCopy::Sent(sent_at) => sent_at,
            LastCopy::Sending(ref mut last_copy_rx) => match last_copy_rx.try_recv() {
                Ok(sent_at) => {
                    *self = LastCopy::Sent(sent_at);

                    sent_at
                },
                // the last copy is not sent yet
                Err(TryRecvError::Empty) => return true,
                // the last copy was never sent
                Err(TryRecvError::Closed) => return false,
            },
        };

        received_at < sent_at + constants::MATCH_TIMEOUT
    }
}

impl WSDClient {
    /// Parameters:
    ///
    /// * `incoming_rx`: used to receive client messages from every subscribed socket
    /// * `mc_local_port_tx`: use to send multicast messages, from the local port to `WSD_PORT`
    pub fn init(
        cancellation_token: CancellationToken,
        config: Arc<Config>,
        devices: Arc<RwLock<Devices>>,
        bound_to: NetworkAddress,
        incoming_rx: Receiver<IncomingClientMessage>,
        mc_local_port_tx: Sender<OutgoingMulticastMessage>,
    ) -> Self {
        let (probe_tx, probe_rx) = tokio::sync::mpsc::channel(1);

        let handle = {
            let cancellation_token = cancellation_token.clone();
            let bound_to = bound_to.clone();
            let devices = Arc::clone(&devices);

            spawn_with_name(
                format!("wsd client ({})", bound_to.address).as_str(),
                listen_forever(
                    bound_to,
                    cancellation_token,
                    config,
                    devices,
                    incoming_rx,
                    mc_local_port_tx,
                    probe_rx,
                ),
            )
        };

        let client = Self {
            cancellation_token,
            _bound_to: bound_to,
            _devices: devices,
            handle,
            probe_tx,
        };

        client.schedule_send_probe();

        client
    }

    pub async fn teardown(self) {
        self.cancellation_token.cancel();

        let _r = self.handle.await;
    }

    // WS-Discovery, Section 4.3, Probe message
    fn schedule_send_probe(&self) {
        let cancellation_token = self.cancellation_token.clone();
        let probe_tx = self.probe_tx.clone();

        tokio::task::spawn(async move {
            // avoid packet storm when hosts come up by delaying initial probe
            tokio::select! {
                biased;
                () = cancellation_token.cancelled() => { return; },
                () = tokio::time::sleep(rand::random_range(Duration::from_millis(0)..=constants::APP_MAX_DELAY)) => { }
            }

            // fails only once the client loop has ended
            let _r = probe_tx.send(()).await;
        });
    }

    /// Asks the client loop to send a Probe.
    pub async fn send_probe(&self) -> Result<(), eyre::Report> {
        self.probe_tx
            .send(())
            .await
            .map_err(|_| eyre::Report::msg("Client loop gone, failed to send probe"))
    }
}

/// Sends a Probe, and records it in `probes` to accept its matches.
async fn send_probe(
    config: &Config,
    probes: &mut HashMap<MessageId, LastCopy>,
    mc_local_port_tx: &Sender<OutgoingMulticastMessage>,
) -> Result<(), eyre::Report> {
    let (probe, message_id) = Builder::build_probe(config)?;

    let probe = record(probes, message_id, probe);

    mc_local_port_tx
        .send(probe)
        .await
        .map_err(|_| eyre::Report::msg("Receiver gone, failed to send probe"))
}

/// Records a `Probe` or `Resolve` in `sent` to accept its matches, after dropping the ones whose matches are no longer accepted.
fn record(
    sent: &mut HashMap<MessageId, LastCopy>,
    message_id: Urn,
    message: MulticastMessage,
) -> OutgoingMulticastMessage {
    let now = Instant::now();

    sent.retain(|_, last_copy| last_copy.accepts(now));

    let (message, last_copy) = LastCopy::track(message);

    sent.insert(message_id.into(), last_copy);

    message
}

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
            Err(error) => {
                event!(
                    Level::DEBUG,
                    ?error,
                    %raw_xaddr,
                    "Message sent with invalid/non-http/https xaddr or no host, ignoring"
                );

                None
            },
        })
        .collect::<Vec<_>>();

    // a stable sort keeps XAddrs of equal priority in the order the device listed them
    xaddrs.sort_by_key(|parsed_url| {
        match bound_to {
            IpNet::V6(_) => {
                // prefer link-local address for IPv6
                if let Some(Host::Ipv6(ipv6)) = parsed_url.url().host()
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

    xaddrs
}

/// The result of checking the `XAddrs` of a Hello, `ProbeMatch` or `ResolveMatch`.
#[derive(Debug)]
enum XAddrsCheck {
    /// The message has no `XAddrs`.
    Missing,
    /// None of the `XAddrs` is an HTTP or HTTPS URL with a host.
    Unusable,
    Usable(Vec1<XAddr>),
}

/// The work left after the ordering lock is released.
enum Next {
    Resolve,
    Fetch(Fetch),
    /// An exchange already runs, and it runs once more when it ends.
    Rerun,
}

fn check_xaddrs(
    bound_to: IpNet,
    kind: &str,
    endpoint: &DeviceUri,
    raw_xaddrs: Option<Box<str>>,
) -> XAddrsCheck {
    let Some(raw_xaddrs) = raw_xaddrs else {
        return XAddrsCheck::Missing;
    };

    let Ok(xaddrs) = Vec1::try_from_vec(parse_xaddrs(bound_to, &raw_xaddrs)) else {
        event!(Level::ERROR, %endpoint, kind, "No valid URL in xaddrs");

        return XAddrsCheck::Unusable;
    };

    XAddrsCheck::Usable(xaddrs)
}

/// Runs metadata exchanges on tasks of their own, so the client loop never waits for HTTP.
#[derive(Clone)]
struct ExchangeRunner {
    client: reqwest::Client,
    config: Arc<Config>,
    devices: Arc<RwLock<Devices>>,
    bound_to: NetworkAddress,
    cancellation_token: CancellationToken,
    tracker: TaskTracker,
}

impl ExchangeRunner {
    fn new(
        client: reqwest::Client,
        config: Arc<Config>,
        devices: Arc<RwLock<Devices>>,
        bound_to: NetworkAddress,
        cancellation_token: CancellationToken,
    ) -> Self {
        Self {
            client,
            config,
            devices,
            bound_to,
            cancellation_token,
            tracker: TaskTracker::new(),
        }
    }

    fn spawn(&self, fetch: Fetch) {
        let runner = self.clone();

        self.tracker.spawn_with_name(
            format!("metadata exchange ({})", fetch.exchange.endpoint()).as_str(),
            async move {
                let mut next = Some(fetch);

                while let Some(fetch) = next {
                    next = runner.perform(fetch).await;
                }
            },
        );
    }

    async fn wait(&self) {
        self.tracker.close();
        self.tracker.wait().await;
    }

    /// Fetches the metadata of the Target Service from the first `XAddr` that answers, and returns the exchange to run next.
    async fn perform(&self, Fetch { exchange, xaddrs }: Fetch) -> Option<Fetch> {
        let endpoint = exchange.endpoint();

        let body = match build_getmetadata_message(&self.config, endpoint) {
            Ok(body) => Bytes::from_owner(body),
            Err(error) => {
                event!(Level::ERROR, %endpoint, ?error, "Failed to build the metadata request");

                return self.devices.write().await.finish_exchange(exchange);
            },
        };

        for xaddr in xaddrs {
            let builder = self
                .client
                .post(xaddr.url().clone())
                .header("Content-Type", constants::MIME_TYPE_SOAP_XML)
                .header("User-Agent", "wsdd-rs");

            let request = async {
                let response = builder
                    .body(body.clone())
                    .timeout(self.config.metadata_timeout)
                    .send()
                    .instrument(span!(Level::DEBUG, "http", host = %xaddr.host_str()))
                    .await?;

                response.error_for_status()?.bytes().await
            };

            let Some(response) = self
                .cancellation_token
                .run_until_cancelled(exchange.run_until_bye(request))
                .await
            else {
                self.devices.write().await.cancel_exchange(exchange);

                return None;
            };

            let Some(response) = response else {
                event!(Level::DEBUG, %endpoint, "Bye received during the metadata exchange, aborting it");

                return self.devices.write().await.finish_exchange(exchange);
            };

            match response {
                Ok(response) => {
                    return handle_metadata(
                        &self.devices,
                        &response,
                        exchange,
                        &xaddr,
                        &self.bound_to,
                    )
                    .await;
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

        event!(Level::WARN, %endpoint, "could not fetch metadata from any XAddr");

        self.devices.write().await.finish_exchange(exchange)
    }
}

async fn handle_hello(
    exchanges: &ExchangeRunner,
    config: &Config,
    devices: Arc<RwLock<Devices>>,
    bound_to: &NetworkAddress,
    multicast: &Sender<OutgoingMulticastMessage>,
    resolves: &mut HashMap<MessageId, LastCopy>,
    Hello {
        app_sequence,
        endpoint,
        raw_xaddrs,
        metadata_version,
    }: Hello,
) -> Result<(), eyre::Report> {
    let next = {
        let mut guard = devices.write().await;

        let Some(current) = guard.observe(&endpoint, &app_sequence) else {
            event!(Level::DEBUG, %endpoint, ?app_sequence, "stale Hello, ignoring");

            return Ok(());
        };

        match check_xaddrs(bound_to.address, "Hello", &endpoint, raw_xaddrs) {
            XAddrsCheck::Unusable => return Ok(()),
            XAddrsCheck::Missing => Next::Resolve,
            XAddrsCheck::Usable(xaddrs) => {
                event!(Level::INFO, %bound_to, %endpoint, xaddrs = %SliceDisplay(&xaddrs), metadata_version, "Hello");

                match current.start_exchange(bound_to.interface.index(), xaddrs) {
                    Some(fetch) => Next::Fetch(fetch),
                    None => Next::Rerun,
                }
            },
        }
    };

    match next {
        Next::Resolve => {
            event!(Level::INFO, %endpoint, metadata_version, "Hello without XAddrs, sending resolve");

            let (message, message_id) = Builder::build_resolve(config, &endpoint)?;

            let message = record(resolves, message_id, message);

            multicast.send(message).await?;

            Ok(())
        },
        Next::Fetch(fetch) => {
            exchanges.spawn(fetch);

            Ok(())
        },
        Next::Rerun => {
            event!(Level::DEBUG, %endpoint, "metadata exchange running, rerun queued");

            Ok(())
        },
    }
}

async fn handle_bye(
    devices: Arc<RwLock<Devices>>,
    Bye {
        app_sequence,
        endpoint,
    }: Bye,
) -> Result<(), eyre::Report> {
    let mut guard = devices.write().await;

    let Some(current) = guard.observe(&endpoint, &app_sequence) else {
        event!(Level::DEBUG, %endpoint, ?app_sequence, "stale Bye, ignoring");

        return Ok(());
    };

    if current.depart().is_none() {
        event!(
            Level::DEBUG,
            endpoint = &*endpoint,
            "Received bye, but not record of that endpoint"
        );
    }

    Ok(())
}

#[expect(clippy::too_many_arguments, reason = "WIP")]
async fn handle_probe_matches(
    exchanges: &ExchangeRunner,
    config: &Config,
    devices: Arc<RwLock<Devices>>,
    bound_to: &NetworkAddress,
    received_at: Instant,
    probes: &mut HashMap<MessageId, LastCopy>,
    mc_local_port_tx: &Sender<OutgoingMulticastMessage>,
    resolves: &mut HashMap<MessageId, LastCopy>,
    ProbeMatches {
        relates_to,
        app_sequence,
        matches,
    }: ProbeMatches,
) -> Result<(), eyre::Report> {
    // only accept probe matches for probes we sent recently
    let fresh = probes
        .get_mut(&relates_to)
        .is_some_and(|last_copy| last_copy.accepts(received_at));

    if !fresh {
        event!(Level::DEBUG, %relates_to, "unknown or outdated probe");
        return Ok(());
    }

    for probe_match in matches {
        // one failed match must not drop the others in the same message
        if let Err(error) = handle_probe_match(
            exchanges,
            config,
            Arc::clone(&devices),
            bound_to,
            mc_local_port_tx,
            resolves,
            &app_sequence,
            probe_match,
        )
        .await
        {
            event!(Level::ERROR, ?error, "Failure to handle ProbeMatch");
        }
    }

    Ok(())
}

#[expect(clippy::too_many_arguments, reason = "WIP")]
async fn handle_probe_match(
    exchanges: &ExchangeRunner,
    config: &Config,
    devices: Arc<RwLock<Devices>>,
    bound_to: &NetworkAddress,
    mc_local_port_tx: &Sender<OutgoingMulticastMessage>,
    resolves: &mut HashMap<MessageId, LastCopy>,
    app_sequence: &AppSequence,
    ProbeMatch {
        endpoint,
        raw_xaddrs,
        metadata_version,
    }: ProbeMatch,
) -> Result<(), eyre::Report> {
    let next = {
        let mut guard = devices.write().await;

        let current = guard.observe_match(&endpoint, app_sequence);

        match check_xaddrs(bound_to.address, "ProbeMatch", &endpoint, raw_xaddrs) {
            XAddrsCheck::Unusable => return Ok(()),
            XAddrsCheck::Missing => Next::Resolve,
            XAddrsCheck::Usable(xaddrs) => {
                event!(Level::INFO, %bound_to, %endpoint, xaddrs = %SliceDisplay(&xaddrs), metadata_version, "ProbeMatch");

                match current.start_exchange(bound_to.interface.index(), xaddrs) {
                    Some(fetch) => Next::Fetch(fetch),
                    None => Next::Rerun,
                }
            },
        }
    };

    match next {
        //  If no XAddrs are included in the ProbeMatches message, then the client may send a
        //  Resolve message by UDP multicast to port 3702.
        Next::Resolve => {
            event!(Level::INFO, %endpoint, metadata_version, "ProbeMatch without XAddrs, sending resolve");

            let (message, message_id) = Builder::build_resolve(config, &endpoint)?;

            let message = record(resolves, message_id, message);

            mc_local_port_tx.send(message).await?;

            Ok(())
        },
        Next::Fetch(fetch) => {
            exchanges.spawn(fetch);

            Ok(())
        },
        Next::Rerun => {
            event!(Level::DEBUG, %endpoint, "metadata exchange running, rerun queued");

            Ok(())
        },
    }
}

async fn handle_resolve_matches(
    exchanges: &ExchangeRunner,
    devices: Arc<RwLock<Devices>>,
    bound_to: &NetworkAddress,
    received_at: Instant,
    resolves: &mut HashMap<MessageId, LastCopy>,
    ResolveMatches {
        relates_to,
        app_sequence,
        resolve_match,
    }: ResolveMatches,
) -> Result<(), eyre::Report> {
    // only accept resolve matches for resolves we sent recently
    let fresh = resolves
        .get_mut(&relates_to)
        .is_some_and(|last_copy| last_copy.accepts(received_at));

    if !fresh {
        event!(Level::DEBUG, %relates_to, "unknown or outdated resolve");
        return Ok(());
    }

    let Some(ResolveMatch {
        endpoint,
        raw_xaddrs,
        metadata_version,
    }) = resolve_match
    else {
        event!(Level::DEBUG, %relates_to, "ResolveMatches without a match, nothing to do");

        return Ok(());
    };

    let started = {
        let mut guard = devices.write().await;

        let current = guard.observe_match(&endpoint, &app_sequence);

        match check_xaddrs(bound_to.address, "ResolveMatch", &endpoint, raw_xaddrs) {
            XAddrsCheck::Unusable => return Ok(()),
            XAddrsCheck::Missing => {
                event!(Level::DEBUG, "ResolveMatch without xaddr, nothing to do");

                return Ok(());
            },
            XAddrsCheck::Usable(xaddrs) => {
                event!(Level::INFO, %bound_to, %endpoint, xaddrs = %SliceDisplay(&xaddrs), metadata_version, "ResolveMatch");

                current.start_exchange(bound_to.interface.index(), xaddrs)
            },
        }
    };

    match started {
        Some(fetch) => exchanges.spawn(fetch),
        None => {
            event!(Level::DEBUG, %endpoint, "metadata exchange running, rerun queued");
        },
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

/// Stores `meta` unless the Target Service sent a Bye while the exchange ran, ends `exchange`, and returns the exchange to run next.
async fn handle_metadata(
    devices: &RwLock<Devices>,
    meta: &[u8],
    exchange: Exchange,
    xaddr: &XAddr,
    bound_to: &NetworkAddress,
) -> Option<Fetch> {
    let mut devices = devices.write().await;

    let endpoint = exchange.endpoint();

    if exchange.departed() {
        event!(Level::DEBUG, %endpoint, "Bye received during the metadata exchange, discarding the metadata");

        return devices.finish_exchange(exchange);
    }

    if let Err(error) = devices.store(endpoint, meta, xaddr, bound_to) {
        event!(Level::ERROR, %endpoint, ?error, "Failed to store the metadata");
    }

    devices.finish_exchange(exchange)
}

async fn listen_forever(
    bound_to: NetworkAddress,
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    devices: Arc<RwLock<Devices>>,
    mut incoming_rx: Receiver<IncomingClientMessage>,
    mc_local_port_tx: Sender<OutgoingMulticastMessage>,
    mut probe_rx: Receiver<()>,
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

    let exchanges = ExchangeRunner::new(
        client,
        Arc::clone(&config),
        Arc::clone(&devices),
        bound_to.clone(),
        cancellation_token.child_token(),
    );

    let mut probes = HashMap::new();
    let mut resolves = HashMap::new();

    loop {
        let IncomingClientMessage {
            from: _from,
            received_at,
            header,
            message,
        } = tokio::select! {
            biased;
            () = cancellation_token.cancelled() => {
                break;
            },
            Some(()) = probe_rx.recv() => {
                if let Err(error) = send_probe(&config, &mut probes, &mc_local_port_tx).await {
                    event!(Level::ERROR, ?error, "Failed to send probe");
                }

                continue;
            },
            message = incoming_rx.recv() => {
                let Some(message) = message else {
                    // the end, but we just got it before the cancellation
                    break;
                };

                message
            },
        };

        // dispatch based on the SOAP Action header
        let response = match message {
            ClientMessage::Hello(hello) => {
                handle_hello(
                    &exchanges,
                    &config,
                    Arc::clone(&devices),
                    &bound_to,
                    &mc_local_port_tx,
                    &mut resolves,
                    hello,
                )
                .await
            },
            ClientMessage::Bye(bye) => handle_bye(Arc::clone(&devices), bye).await,
            ClientMessage::ProbeMatches(probe_matches) => {
                handle_probe_matches(
                    &exchanges,
                    &config,
                    Arc::clone(&devices),
                    &bound_to,
                    received_at,
                    &mut probes,
                    &mc_local_port_tx,
                    &mut resolves,
                    probe_matches,
                )
                .await
            },
            ClientMessage::ResolveMatches(resolve_matches) => {
                handle_resolve_matches(
                    &exchanges,
                    Arc::clone(&devices),
                    &bound_to,
                    received_at,
                    &mut resolves,
                    resolve_matches,
                )
                .await
            },
        };

        match response {
            Ok(()) => {},
            Err(error) => {
                event!(
                    Level::ERROR,
                    action = &*header.action,
                    ?error,
                    "Failure to handle message"
                );

                continue;
            },
        }
    }

    exchanges.wait().await;
}

#[cfg(test)]
mod tests {
    use std::future::poll_fn;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4};
    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::Poll;
    use std::time::Duration;

    use color_eyre::eyre;
    use hashbrown::{HashMap, HashSet};
    use ipnet::{IpNet, Ipv4Net, Ipv6Net};
    use libc::RT_SCOPE_SITE;
    use mockito::{Mock, Server, ServerOpts};
    use pretty_assertions::{assert_eq, assert_matches};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::mpsc::error::TryRecvError;
    use tokio::sync::{RwLock, oneshot};
    use tokio::time::Instant;
    use tokio_util::sync::CancellationToken;
    use uuid::Uuid;
    use vec1::{Vec1, vec1};

    use crate::constants;
    use crate::max_size_deque::MaxSizeDeque;
    use crate::network_address::NetworkAddress;
    use crate::network_interface::NetworkInterface;
    use crate::soap::MessageId;
    use crate::soap::parser::MessageHandler;
    use crate::soap::parser::app_sequence::AppSequence;
    use crate::soap::parser::bye::Bye;
    use crate::soap::parser::hello::Hello;
    use crate::soap::parser::probe_match::ProbeMatch;
    use crate::soap::parser::resolve_match::{ResolveMatch, ResolveMatches};
    use crate::soap::parser::xaddrs::XAddr;
    use crate::test_utils::xml::to_string_pretty;
    use crate::test_utils::{build_config, build_message_handler_with_network_address};
    use crate::wsd::device::DeviceUri;
    use crate::wsd::devices::{Devices, Exchange, Fetch};
    use crate::wsd::http::http_server::WSDHttpServer;
    use crate::wsd::udp::client::{
        ExchangeRunner, LastCopy, WSDClient, XAddrsCheck, check_xaddrs, handle_bye, handle_hello,
        handle_metadata, handle_probe_match, handle_probe_matches, handle_resolve_matches,
        parse_xaddrs,
    };

    #[test]
    fn last_copy_accepts_match_until_match_timeout() {
        let sent_at = Instant::now();

        let mut last_copy = LastCopy::Sent(sent_at);

        assert!(last_copy.accepts(sent_at + constants::MATCH_TIMEOUT - Duration::from_millis(1)));
        assert!(!last_copy.accepts(sent_at + constants::MATCH_TIMEOUT));
    }

    #[test]
    fn last_copy_accepts_match_while_sending() {
        let (_last_copy_tx, last_copy_rx) = oneshot::channel();

        let mut last_copy = LastCopy::Sending(last_copy_rx);

        assert!(last_copy.accepts(Instant::now() + Duration::from_secs(10)));
    }

    #[test]
    fn last_copy_measures_from_reported_send_time() {
        let (last_copy_tx, last_copy_rx) = oneshot::channel();

        let mut last_copy = LastCopy::Sending(last_copy_rx);

        let sent_at = Instant::now() + constants::MATCH_TIMEOUT * 2;

        last_copy_tx.send(sent_at).unwrap();

        assert!(last_copy.accepts(sent_at + constants::MATCH_TIMEOUT - Duration::from_millis(1)));
        assert!(!last_copy.accepts(sent_at + constants::MATCH_TIMEOUT));
    }

    #[test]
    fn last_copy_rejects_match_when_message_was_dropped() {
        let (last_copy_tx, last_copy_rx) = oneshot::channel();

        let mut last_copy = LastCopy::Sending(last_copy_rx);

        drop(last_copy_tx);

        assert!(!last_copy.accepts(Instant::now()));
    }

    fn setup_client() -> (Arc<crate::config::Config>, Arc<RwLock<Devices>>) {
        let client_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_335));
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        (client_config, client_devices)
    }

    fn exchange_runner(
        config: &Arc<crate::config::Config>,
        devices: &Arc<RwLock<Devices>>,
        bound_to: &NetworkAddress,
    ) -> ExchangeRunner {
        ExchangeRunner::new(
            reqwest::ClientBuilder::new().build().unwrap(),
            Arc::clone(config),
            Arc::clone(devices),
            bound_to.clone(),
            CancellationToken::new(),
        )
    }

    async fn start_exchange(
        devices: &RwLock<Devices>,
        endpoint: &DeviceUri,
        app_sequence: &AppSequence,
        bound_to: &NetworkAddress,
    ) -> Exchange {
        let Fetch { exchange, .. } = devices
            .write()
            .await
            .observe(endpoint, app_sequence)
            .expect("the Hello is current")
            .start_exchange(
                bound_to.interface.index(),
                vec1![XAddr::try_from("http://192.168.100.5:5357/").unwrap()],
            )
            .expect("no exchange runs for a new endpoint");

        exchange
    }

    async fn mock_server() -> Server {
        Server::new_with_opts_async(ServerOpts {
            // a host in IPv4 form ensures we bind to an IPv4 address
            host: "127.0.0.1",
            // random port
            port: 0,
            assert_on_drop: true,
        })
        .await
    }

    fn synology_metadata() -> String {
        format!(
            include_str!("../../test/get-response-synology.xml"),
            Uuid::now_v7().urn(),
            Uuid::now_v7().urn(),
        )
    }

    /// Answers exactly `hits` requests with the Synology metadata.
    async fn metadata_server(hits: usize) -> (Server, Mock) {
        let mut server = mock_server().await;

        let metadata_exchange = server
            .mock("POST", mockito::Matcher::Any)
            .with_status(200)
            .with_body(synology_metadata())
            .expect(hits)
            .create_async()
            .await;

        (server, metadata_exchange)
    }

    fn xaddrs_of(server: &Server) -> Box<str> {
        format!("http://{}/", server.socket_address()).into_boxed_str()
    }

    /// Returns whether the Hello sent a Resolve.
    async fn hello(
        config: &Arc<crate::config::Config>,
        devices: &Arc<RwLock<Devices>>,
        bound_to: &NetworkAddress,
        endpoint: &DeviceUri,
        app_sequence: AppSequence,
        raw_xaddrs: Option<Box<str>>,
    ) -> Result<bool, eyre::Report> {
        receive_hello(
            config,
            devices,
            bound_to,
            Hello {
                app_sequence,
                endpoint: endpoint.clone(),
                raw_xaddrs,
                metadata_version: 1,
            },
        )
        .await
    }

    /// Returns whether `hello` sent a Resolve.
    async fn receive_hello(
        config: &Arc<crate::config::Config>,
        devices: &Arc<RwLock<Devices>>,
        bound_to: &NetworkAddress,
        hello: Hello,
    ) -> Result<bool, eyre::Report> {
        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let exchanges = exchange_runner(config, devices, bound_to);

        let result = handle_hello(
            &exchanges,
            config,
            Arc::clone(devices),
            bound_to,
            &multicast_tx,
            &mut HashMap::new(),
            hello,
        )
        .await;

        exchanges.wait().await;

        result?;

        Ok(multicast_rx.try_recv().is_ok())
    }

    /// Parses a Hello with `XAddrs` at `server`.
    async fn parse_hello(
        message_handler: &MessageHandler,
        server: &Server,
        endpoint: &DeviceUri,
        instance_id: u64,
        message_number: u64,
        metadata_version: u64,
    ) -> Hello {
        let hello = format!(
            include_str!("../../test/hello-with-xaddrs-template.xml"),
            Uuid::now_v7(),
            instance_id,
            Uuid::nil(),
            message_number,
            endpoint,
            server.socket_address().ip(),
            server.socket_address().port(),
            Uuid::now_v7(),
            metadata_version
        );

        let (_, message) = message_handler
            .deconstruct_message(&hello, SocketAddr::new(server.socket_address().ip(), 5000))
            .await
            .unwrap();

        message.into_hello().unwrap()
    }

    async fn bye(
        devices: &Arc<RwLock<Devices>>,
        endpoint: &DeviceUri,
        app_sequence: AppSequence,
    ) -> Result<(), eyre::Report> {
        handle_bye(
            Arc::clone(devices),
            Bye {
                app_sequence,
                endpoint: endpoint.clone(),
            },
        )
        .await
    }

    async fn finish_exchange_with_synology(
        devices: &RwLock<Devices>,
        exchange: Exchange,
        bound_to: &NetworkAddress,
    ) -> Option<Fetch> {
        handle_metadata(
            devices,
            synology_metadata().as_bytes(),
            exchange,
            &XAddr::try_from("http://diskstation:5357/2e91b960-d258-43d6-989b-a24f108f1721")
                .unwrap(),
            bound_to,
        )
        .await
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_hello_without_xaddr() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

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

        let (_, message) = message_handler
            .deconstruct_message(
                &hello_without_xaddrs,
                SocketAddr::V4(SocketAddrV4::new(host_ip, 5000)),
            )
            .await
            .unwrap();

        let hello = message.into_hello().unwrap();

        let mut resolves = HashMap::new();

        let exchanges = exchange_runner(&client_config, &client_devices, &client_network_address);

        let result = handle_hello(
            &exchanges,
            &client_config,
            Arc::clone(&client_devices),
            &client_network_address,
            &multicast_tx,
            &mut resolves,
            hello,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        // the resolve's message id must be recorded to accept the future ResolveMatches
        assert!(resolves.contains_key(&MessageId::from(Uuid::nil().urn())));

        let expected = format!(
            include_str!("../../test/resolve-template.xml"),
            Uuid::nil(),
            host_endpoint_device_uri,
        );

        let response = {
            let response = multicast_rx.try_recv().unwrap();

            to_string_pretty(response.message.as_ref()).unwrap()
        };

        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_hello_with_xaddr() {
        let (message_handler, bound_to) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::LOCALHOST).into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let mut server = mock_server().await;

        let host_message_id = Uuid::now_v7();
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let expected_get = format!(
            include_str!("../../test/get-template.xml"),
            host_config.uuid_as_device_uri, client_config.uuid_as_device_uri
        );

        let mock = server
            .mock("POST", &*format!("/{}", host_config.uuid))
            .with_status(200)
            .with_body_from_request(move |request| {
                let metadata = synology_metadata();

                assert_eq!(
                    to_string_pretty(request.body().unwrap()).unwrap(),
                    to_string_pretty(expected_get.as_bytes()).unwrap()
                );

                metadata.into()
            })
            .create_async()
            .await;

        let hello = format!(
            include_str!("../../test/hello-with-xaddrs-template.xml"),
            host_message_id.urn(),
            host_config.app_sequence.instance_id(),
            Uuid::now_v7(),
            0,
            host_config.uuid_as_device_uri,
            server.socket_address().ip(),
            server.socket_address().port(),
            host_config.uuid,
            1
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (_, message) = message_handler
            .deconstruct_message(&hello, SocketAddr::new(server.socket_address().ip(), 5000))
            .await
            .unwrap();

        let hello = message.into_hello().unwrap();

        let mut resolves = HashMap::new();

        let exchanges = exchange_runner(&client_config, &client_devices, &bound_to);

        let result = handle_hello(
            &exchanges,
            &client_config,
            Arc::clone(&client_devices),
            &bound_to,
            &multicast_tx,
            &mut resolves,
            hello,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        // we expect no resolve to be sent
        assert_matches!(multicast_rx.try_recv(), Err(TryRecvError::Empty));
        assert!(resolves.is_empty());

        // ensure the mock is hit
        mock.assert_async().await;

        let client_devices = client_devices.read().await;

        let device = client_devices.get(&host_config.uuid_as_device_uri);

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

        assert_eq!(device_props, expected_props);
    }

    #[tokio::test]
    async fn handles_bye() {
        let (message_handler, _client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        // host
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let bye = format!(
            include_str!("../../test/bye-template.xml"),
            Uuid::now_v7(),
            host_config.app_sequence.instance_id(),
            Uuid::now_v7(),
            0,
            host_config.uuid_as_device_uri,
        );

        let (_, message) = message_handler
            .deconstruct_message(&bye, SocketAddr::V4(SocketAddrV4::new(host_ip, 5000)))
            .await
            .unwrap();

        let bye = message.into_bye().unwrap();

        let result = handle_bye(Arc::clone(&client_devices), bye).await;

        assert_matches!(result, Ok(()));
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_hello_bye() {
        let (message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::LOCALHOST).into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let mut server = mock_server().await;

        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let expected_get = format!(
            include_str!("../../test/get-template.xml"),
            host_config.uuid_as_device_uri, client_config.uuid_as_device_uri
        );

        let mock = server
            .mock("POST", &*format!("/{}", host_config.uuid))
            .with_status(200)
            .with_body_from_request(move |request| {
                let metadata = synology_metadata();

                assert_eq!(
                    to_string_pretty(request.body().unwrap()).unwrap(),
                    to_string_pretty(expected_get.as_bytes()).unwrap()
                );

                metadata.into()
            })
            .create_async()
            .await;

        let hello = format!(
            include_str!("../../test/hello-with-xaddrs-template.xml"),
            Uuid::now_v7(),
            host_config.app_sequence.instance_id(),
            Uuid::now_v7(),
            0,
            host_config.uuid_as_device_uri,
            server.socket_address().ip(),
            server.socket_address().port(),
            host_config.uuid,
            1
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (_, message) = message_handler
            .deconstruct_message(&hello, SocketAddr::new(server.socket_address().ip(), 5000))
            .await
            .unwrap();

        let hello = message.into_hello().unwrap();

        let mut resolves = HashMap::new();

        let exchanges = exchange_runner(&client_config, &client_devices, &network_address);

        let result = handle_hello(
            &exchanges,
            &client_config,
            Arc::clone(&client_devices),
            &network_address,
            &multicast_tx,
            &mut resolves,
            hello,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        // we expect no resolve to be sent
        assert_matches!(multicast_rx.try_recv(), Err(TryRecvError::Empty));
        assert!(resolves.is_empty());

        // ensure the mock is hit
        mock.assert_async().await;

        assert!(
            client_devices
                .read()
                .await
                .contains_key(&host_config.uuid_as_device_uri)
        );

        // and now the bye
        let bye = format!(
            include_str!("../../test/bye-template.xml"),
            Uuid::now_v7(),
            host_config.app_sequence.instance_id(),
            Uuid::now_v7(),
            0,
            host_config.uuid_as_device_uri
        );

        let (_, message) = message_handler
            .deconstruct_message(&bye, SocketAddr::new(server.socket_address().ip(), 5000))
            .await
            .unwrap();

        let bye = message.into_bye().unwrap();

        let result = handle_bye(Arc::clone(&client_devices), bye).await;

        assert_matches!(result, Ok(()));

        // ensure the host is no longer present
        assert!(
            !client_devices
                .read()
                .await
                .contains_key(&host_config.uuid_as_device_uri)
        );
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn ignores_hello_older_than_the_last_bye() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let (server, metadata_exchange) = metadata_server(0).await;

        let endpoint = new_endpoint();

        let result = bye(&client_devices, &endpoint, AppSequence::new(1, None, 6)).await;

        assert_matches!(result, Ok(()));

        let result = hello(
            &client_config,
            &client_devices,
            &network_address,
            &endpoint,
            AppSequence::new(1, None, 5),
            Some(xaddrs_of(&server)),
        )
        .await;

        assert_matches!(result, Ok(false));

        metadata_exchange.assert_async().await;

        assert!(client_devices.read().await.is_empty());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn hello_with_unusable_xaddrs_advances_the_order() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        let endpoint = new_endpoint();

        let result = hello(
            &client_config,
            &client_devices,
            &network_address,
            &endpoint,
            AppSequence::new(1, None, 6),
            Some(Box::from("ftp://192.168.100.5/")),
        )
        .await;

        assert_matches!(result, Ok(false));

        assert!(
            client_devices
                .write()
                .await
                .observe(&endpoint, &AppSequence::new(1, None, 5))
                .is_none()
        );
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn fetches_metadata_of_a_hello_with_a_lower_metadata_version() {
        let (message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let (server, metadata_exchange) = metadata_server(3).await;

        let endpoint = new_endpoint();

        for (message_number, metadata_version) in [(1, 2), (2, 1), (3, 2)] {
            let hello = parse_hello(
                &message_handler,
                &server,
                &endpoint,
                1,
                message_number,
                metadata_version,
            )
            .await;

            assert_eq!(hello.metadata_version, metadata_version);

            let result =
                receive_hello(&client_config, &client_devices, &network_address, hello).await;

            assert_matches!(result, Ok(false));
        }

        metadata_exchange.assert_async().await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn fetches_metadata_of_a_newer_instance_with_a_lower_metadata_version() {
        let (message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let (server, metadata_exchange) = metadata_server(2).await;

        let endpoint = new_endpoint();

        for (instance_id, metadata_version) in [(1, 5), (11, 1)] {
            let hello = parse_hello(
                &message_handler,
                &server,
                &endpoint,
                instance_id,
                1,
                metadata_version,
            )
            .await;

            assert_eq!(hello.metadata_version, metadata_version);

            let result =
                receive_hello(&client_config, &client_devices, &network_address, hello).await;

            assert_matches!(result, Ok(false));
        }

        metadata_exchange.assert_async().await;
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn adds_device_again_with_a_hello_in_another_sequence_after_a_bye() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let (server, metadata_exchange) = metadata_server(1).await;

        let endpoint = new_endpoint();

        client_devices
            .write()
            .await
            .observe(&endpoint, &AppSequence::new(1, Some("urn:uuid:a"), 5));

        let result = bye(
            &client_devices,
            &endpoint,
            AppSequence::new(1, Some("urn:uuid:a"), 6),
        )
        .await;

        assert_matches!(result, Ok(()));

        let result = hello(
            &client_config,
            &client_devices,
            &network_address,
            &endpoint,
            AppSequence::new(1, Some("urn:uuid:b"), 1),
            Some(xaddrs_of(&server)),
        )
        .await;

        assert_matches!(result, Ok(false));

        metadata_exchange.assert_async().await;

        assert!(client_devices.read().await.contains_key(&endpoint));
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn adds_device_again_with_a_probe_match_older_than_the_last_bye() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let (server, metadata_exchange) = metadata_server(1).await;

        let endpoint = new_endpoint();

        let result = bye(&client_devices, &endpoint, AppSequence::new(1, None, 7)).await;

        assert_matches!(result, Ok(()));

        let (multicast_tx, _multicast_rx) = tokio::sync::mpsc::channel(1);

        let exchanges = exchange_runner(&client_config, &client_devices, &network_address);

        let result = handle_probe_match(
            &exchanges,
            &client_config,
            Arc::clone(&client_devices),
            &network_address,
            &multicast_tx,
            &mut HashMap::new(),
            &AppSequence::new(1, None, 6),
            ProbeMatch {
                endpoint: endpoint.clone(),
                raw_xaddrs: Some(xaddrs_of(&server)),
                metadata_version: 1,
            },
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        metadata_exchange.assert_async().await;

        assert!(client_devices.read().await.contains_key(&endpoint));
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn adds_device_again_with_a_resolve_match_older_than_the_last_bye() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let (server, metadata_exchange) = metadata_server(1).await;

        let endpoint = new_endpoint();

        let result = bye(&client_devices, &endpoint, AppSequence::new(1, None, 7)).await;

        assert_matches!(result, Ok(()));

        let resolve_message_id = MessageId::from(Uuid::now_v7().urn());

        let mut resolves =
            HashMap::from([(resolve_message_id.clone(), LastCopy::Sent(Instant::now()))]);

        let exchanges = exchange_runner(&client_config, &client_devices, &network_address);

        let result = handle_resolve_matches(
            &exchanges,
            Arc::clone(&client_devices),
            &network_address,
            Instant::now(),
            &mut resolves,
            ResolveMatches {
                relates_to: resolve_message_id,
                app_sequence: AppSequence::new(1, None, 6),
                resolve_match: Some(ResolveMatch {
                    endpoint: endpoint.clone(),
                    raw_xaddrs: Some(xaddrs_of(&server)),
                    metadata_version: 1,
                }),
            },
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        metadata_exchange.assert_async().await;

        assert!(client_devices.read().await.contains_key(&endpoint));
    }

    #[tokio::test]
    async fn keeps_device_after_a_bye_older_than_its_hello() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        let endpoint = new_endpoint();

        let exchange = start_exchange(
            &client_devices,
            &endpoint,
            &AppSequence::new(1, None, 5),
            &network_address,
        )
        .await;

        let result =
            finish_exchange_with_synology(&client_devices, exchange, &network_address).await;

        assert!(result.is_none());

        let result = bye(&client_devices, &endpoint, AppSequence::new(1, None, 4)).await;

        assert_matches!(result, Ok(()));

        assert!(client_devices.read().await.contains_key(&endpoint));
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn keeps_device_after_a_bye_older_than_its_probe_match() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let (server, metadata_exchange) = metadata_server(1).await;

        let endpoint = new_endpoint();

        let (multicast_tx, _multicast_rx) = tokio::sync::mpsc::channel(1);

        let exchanges = exchange_runner(&client_config, &client_devices, &network_address);

        let result = handle_probe_match(
            &exchanges,
            &client_config,
            Arc::clone(&client_devices),
            &network_address,
            &multicast_tx,
            &mut HashMap::new(),
            &AppSequence::new(1, None, 7),
            ProbeMatch {
                endpoint: endpoint.clone(),
                raw_xaddrs: Some(xaddrs_of(&server)),
                metadata_version: 1,
            },
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        metadata_exchange.assert_async().await;

        let result = bye(&client_devices, &endpoint, AppSequence::new(1, None, 6)).await;

        assert_matches!(result, Ok(()));

        assert!(client_devices.read().await.contains_key(&endpoint));
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn keeps_device_after_a_bye_older_than_its_resolve_match() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let (server, metadata_exchange) = metadata_server(1).await;

        let endpoint = new_endpoint();

        let resolve_message_id = MessageId::from(Uuid::now_v7().urn());

        let mut resolves =
            HashMap::from([(resolve_message_id.clone(), LastCopy::Sent(Instant::now()))]);

        let exchanges = exchange_runner(&client_config, &client_devices, &network_address);

        let result = handle_resolve_matches(
            &exchanges,
            Arc::clone(&client_devices),
            &network_address,
            Instant::now(),
            &mut resolves,
            ResolveMatches {
                relates_to: resolve_message_id,
                app_sequence: AppSequence::new(1, None, 7),
                resolve_match: Some(ResolveMatch {
                    endpoint: endpoint.clone(),
                    raw_xaddrs: Some(xaddrs_of(&server)),
                    metadata_version: 1,
                }),
            },
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        metadata_exchange.assert_async().await;

        let result = bye(&client_devices, &endpoint, AppSequence::new(1, None, 6)).await;

        assert_matches!(result, Ok(()));

        assert!(client_devices.read().await.contains_key(&endpoint));
    }

    #[tokio::test]
    async fn removes_device_with_a_bye_equal_to_its_hello() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        let endpoint = new_endpoint();

        let exchange = start_exchange(
            &client_devices,
            &endpoint,
            &AppSequence::new(1, None, 5),
            &network_address,
        )
        .await;

        let result =
            finish_exchange_with_synology(&client_devices, exchange, &network_address).await;

        assert!(result.is_none());

        let result = bye(&client_devices, &endpoint, AppSequence::new(1, None, 5)).await;

        assert_matches!(result, Ok(()));

        assert!(client_devices.read().await.is_empty());
    }

    #[tokio::test]
    async fn keeps_metadata_when_a_stale_bye_arrived_during_the_exchange() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        let endpoint = new_endpoint();

        let exchange = start_exchange(
            &client_devices,
            &endpoint,
            &AppSequence::new(1, None, 5),
            &network_address,
        )
        .await;

        // another interface's loop handles the Bye while this one awaits the metadata
        let result = bye(&client_devices, &endpoint, AppSequence::new(1, None, 4)).await;

        assert_matches!(result, Ok(()));

        let result =
            finish_exchange_with_synology(&client_devices, exchange, &network_address).await;

        assert!(result.is_none());

        assert!(client_devices.read().await.contains_key(&endpoint));
    }

    #[tokio::test]
    async fn discards_metadata_when_a_bye_in_another_sequence_arrived_during_the_exchange() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        let endpoint = new_endpoint();

        let exchange = start_exchange(
            &client_devices,
            &endpoint,
            &AppSequence::new(1, Some("urn:uuid:a"), 5),
            &network_address,
        )
        .await;

        // another interface's loop handles the Bye while this one awaits the metadata
        let result = bye(
            &client_devices,
            &endpoint,
            AppSequence::new(1, Some("urn:uuid:b"), 0),
        )
        .await;

        assert_matches!(result, Ok(()));

        let result =
            finish_exchange_with_synology(&client_devices, exchange, &network_address).await;

        assert!(result.is_none());

        assert!(client_devices.read().await.is_empty());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn newer_bye_queued_behind_a_hello_stops_its_exchange() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let mut server = mock_server().await;

        let metadata_exchange = server
            .mock("POST", mockito::Matcher::Any)
            .with_status(200)
            .with_body(synology_metadata())
            .expect_at_most(1)
            .create_async()
            .await;

        let endpoint = new_endpoint();

        let mut queued_hello = pin!(hello(
            &client_config,
            &client_devices,
            &network_address,
            &endpoint,
            AppSequence::new(1, None, 5),
            Some(xaddrs_of(&server)),
        ));

        let mut queued_bye = pin!(bye(
            &client_devices,
            &endpoint,
            AppSequence::new(1, None, 6)
        ));

        // tokio's `RwLock` is fair: the Hello takes the lock first, the Bye right after
        let guard = client_devices.write().await;

        poll_fn(|context| {
            assert!(queued_hello.as_mut().poll(context).is_pending());
            assert!(queued_bye.as_mut().poll(context).is_pending());

            Poll::Ready(())
        })
        .await;

        drop(guard);

        let (hello_result, bye_result) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(queued_hello, queued_bye)
        })
        .await
        .unwrap();

        assert_matches!(hello_result, Ok(false));
        assert_matches!(bye_result, Ok(()));

        metadata_exchange.assert_async().await;

        assert!(client_devices.read().await.is_empty());
        assert!(!client_devices.read().await.has_running_exchanges());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn sends_probe() {
        let cancellation_token = CancellationToken::new();

        // client
        let (client_config, client_devices) = setup_client();

        let (_incoming_tx, incoming_rx) = tokio::sync::mpsc::channel(10);
        let (mc_local_port_tx, mut mc_local_port_rx) = tokio::sync::mpsc::channel(10);

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
            incoming_rx,
            mc_local_port_tx,
        );

        let probe = mc_local_port_rx.recv().await.unwrap();

        let expected = format!(
            include_str!("../../test/probe-template-wsdp-device.xml"),
            Uuid::nil()
        );

        let response = to_string_pretty(probe.message.as_ref()).unwrap();
        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn metadata_exchange_tries_next_xaddr_after_http_error() {
        let (_message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let mut server = mock_server().await;

        let failing = server
            .mock("POST", "/failing")
            .with_status(500)
            .with_header("Content-Type", constants::MIME_TYPE_SOAP_XML)
            .with_body(
                r#"<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"><soap:Body><soap:Fault><soap:Code><soap:Value>soap:Receiver</soap:Value></soap:Code></soap:Fault></soap:Body></soap:Envelope>"#,
            )
            .expect(1)
            .create_async()
            .await;

        let working = server
            .mock("POST", "/working")
            .with_header("Content-Type", constants::MIME_TYPE_SOAP_XML)
            .with_body(synology_metadata())
            .expect(1)
            .create_async()
            .await;

        let device_uri = DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());

        let xaddrs = Vec1::try_from_vec(
            ["failing", "working"]
                .into_iter()
                .map(|path| {
                    XAddr::try_from(format!("http://{}/{}", server.socket_address(), path).as_str())
                        .unwrap()
                })
                .collect(),
        )
        .unwrap();

        let exchange = start_exchange(
            &client_devices,
            &device_uri,
            &AppSequence::new(1, None, 1),
            &client_network_address,
        )
        .await;

        let result = exchange_runner(&client_config, &client_devices, &client_network_address)
            .perform(Fetch { exchange, xaddrs })
            .await;

        assert!(result.is_none());

        failing.assert_async().await;
        working.assert_async().await;

        assert!(client_devices.read().await.contains_key(&device_uri));
        assert!(!client_devices.read().await.has_running_exchanges());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn metadata_exchange_aborts_when_a_bye_arrives() {
        let (_message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let mut client_config = build_config(Uuid::now_v7(), 1_742_000_335);
        client_config.metadata_timeout = Duration::from_secs(60);
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        // host, which never answers
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let xaddr = XAddr::try_from(format!("http://{}/", listener.local_addr().unwrap()).as_str())
            .unwrap();
        let (received_tx, received_rx) = oneshot::channel();

        let host = async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0; 4096];

            assert!(stream.read(&mut buffer).await.unwrap() > 0);
            received_tx.send(()).unwrap();

            // ends when the client closes the connection
            while stream.read(&mut buffer).await.is_ok_and(|read| read > 0) {}
        };

        let device_uri = DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());

        let bye = async {
            received_rx.await.unwrap();

            bye(&client_devices, &device_uri, AppSequence::new(1, None, 1)).await
        };

        let exchanges = exchange_runner(
            &Arc::new(client_config),
            &client_devices,
            &client_network_address,
        );

        let exchange = start_exchange(
            &client_devices,
            &device_uri,
            &AppSequence::new(1, None, 1),
            &client_network_address,
        )
        .await;

        let exchange = Box::pin(exchanges.perform(Fetch {
            exchange,
            xaddrs: vec1![xaddr],
        }));

        let (result, bye_result, ()) = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::join!(exchange, bye, host)
        })
        .await
        .unwrap();

        assert!(result.is_none());
        assert_matches!(bye_result, Ok(()));

        assert!(client_devices.read().await.is_empty());
        assert!(!client_devices.read().await.has_running_exchanges());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn metadata_exchange_stores_nothing_when_every_xaddr_fails() {
        let (_message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let mut server = mock_server().await;

        let failing = server
            .mock("POST", "/failing")
            .with_status(500)
            .expect(1)
            .create_async()
            .await;

        let device_uri = DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());

        let xaddrs = vec1![
            XAddr::try_from(format!("http://{}/failing", server.socket_address()).as_str())
                .unwrap(),
        ];

        let exchange = start_exchange(
            &client_devices,
            &device_uri,
            &AppSequence::new(1, None, 1),
            &client_network_address,
        )
        .await;

        let result = exchange_runner(&client_config, &client_devices, &client_network_address)
            .perform(Fetch { exchange, xaddrs })
            .await;

        assert!(result.is_none());

        failing.assert_async().await;

        assert!(client_devices.read().await.is_empty());
        assert!(!client_devices.read().await.has_running_exchanges());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn metadata_exchange_stores_what_the_http_server_serves() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let http_server = WSDHttpServer::init(
            network_address.clone(),
            CancellationToken::new(),
            Arc::clone(&host_config),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0)),
            Arc::new(RwLock::new(MaxSizeDeque::new(
                constants::WSD_MAX_KNOWN_MESSAGES,
            ))),
        )
        .unwrap();

        let xaddrs = vec1![
            XAddr::try_from(
                format!(
                    "http://{}/{}",
                    http_server.http_bound_to(),
                    host_config.uuid
                )
                .as_str(),
            )
            .unwrap(),
        ];

        let exchange = start_exchange(
            &client_devices,
            &host_config.uuid_as_device_uri,
            &AppSequence::new(1, None, 1),
            &network_address,
        )
        .await;

        let result = exchange_runner(&client_config, &client_devices, &network_address)
            .perform(Fetch { exchange, xaddrs })
            .await;

        http_server.teardown().await;

        assert!(result.is_none());

        let client_devices = client_devices.read().await;

        let device = client_devices.get(&host_config.uuid_as_device_uri).unwrap();

        let expected_props = HashMap::from_iter([
            ("BelongsTo", "Workgroup:WORKGROUP"),
            ("DisplayName", "TEST-HOST-NAME"),
            ("FirmwareVersion", "1.0"),
            ("FriendlyName", "WSD Device test-host-name"),
            ("Manufacturer", "wsdd"),
            ("ModelName", "wsdd"),
            ("SerialNumber", "1"),
        ]);

        let device_props = device
            .props()
            .iter()
            .map(|(key, value)| (&**key, &**value))
            .collect::<HashMap<_, _>>();

        assert_eq!(device_props, expected_props);

        assert_eq!(
            device.types(),
            &HashSet::from_iter([Box::from("pub:Computer")])
        );
    }

    #[tokio::test]
    async fn discards_metadata_when_a_bye_arrived_during_the_exchange() {
        let (_message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        let device_uri = DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());

        let exchange = start_exchange(
            &client_devices,
            &device_uri,
            &AppSequence::new(1, None, 1),
            &client_network_address,
        )
        .await;

        // another interface's loop handles the Bye while this one awaits the metadata
        assert_matches!(
            bye(&client_devices, &device_uri, AppSequence::new(1, None, 1)).await,
            Ok(())
        );

        let result =
            finish_exchange_with_synology(&client_devices, exchange, &client_network_address).await;

        assert!(result.is_none());

        assert!(client_devices.read().await.is_empty());
    }

    #[tokio::test]
    async fn handles_metadata_synology() {
        let (_message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        let device_uri = DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());

        let exchange = start_exchange(
            &client_devices,
            &device_uri,
            &AppSequence::new(1, None, 1),
            &client_network_address,
        )
        .await;

        let result =
            finish_exchange_with_synology(&client_devices, exchange, &client_network_address).await;

        assert!(result.is_none());

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

        assert_eq!(device_props, expected_props);
    }

    #[tokio::test]
    async fn handles_metadata_samsung_printer() {
        let (_message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        let metadata: String = format!(
            include_str!("../../test/get-response-samsung-printer.xml"),
            Uuid::now_v7().urn(),
            Uuid::now_v7().urn(),
        );

        let device_uri = DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());

        let exchange = start_exchange(
            &client_devices,
            &device_uri,
            &AppSequence::new(1, None, 1),
            &client_network_address,
        )
        .await;

        let result = handle_metadata(
            &client_devices,
            metadata.as_bytes(),
            exchange,
            &XAddr::try_from("http://192.168.100.50:8018/wsd").unwrap(),
            &client_network_address,
        )
        .await;

        assert!(result.is_none());

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

        assert_eq!(device_props, expected_props);
    }

    #[tokio::test]
    async fn handles_metadata_windows() {
        let (_message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        let metadata: String = format!(
            include_str!("../../test/get-response-windows.xml"),
            Uuid::now_v7().urn(),
            Uuid::now_v7().urn(),
        );

        let device_uri = DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str());

        let exchange = start_exchange(
            &client_devices,
            &device_uri,
            &AppSequence::new(1, None, 1),
            &client_network_address,
        )
        .await;

        let result = handle_metadata(
            &client_devices,
            metadata.as_bytes(),
            exchange,
            &XAddr::try_from("http://192.168.100.71:5357/18de7c97-6277-43fe-9552-cac98a7610f5/")
                .unwrap(),
            &client_network_address,
        )
        .await;

        assert!(result.is_none());

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

        assert_eq!(device_props, expected_props);
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_probe_matches_without_xaddrs() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let host_message_id = Uuid::now_v7();
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let probe_matches = format!(
            include_str!("../../test/probe-matches-without-xaddrs-template.xml"),
            host_message_id.urn(),
            host_config.app_sequence.instance_id(),
            0,
            host_config.uuid_as_device_uri,
            1,
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (_, message) = message_handler
            .deconstruct_message(
                &probe_matches,
                SocketAddr::V4(SocketAddrV4::new(host_ip, 5000)),
            )
            .await
            .unwrap();

        let mut probes = {
            let mut hash_map = HashMap::new();

            hash_map.insert(
                MessageId::from(host_message_id.urn()),
                LastCopy::Sent(Instant::now()),
            );

            hash_map
        };

        let probe_matches = message.into_probe_matches().unwrap();

        let mut resolves = HashMap::new();

        let exchanges = exchange_runner(&client_config, &client_devices, &client_network_address);

        let result = handle_probe_matches(
            &exchanges,
            &client_config,
            Arc::clone(&client_devices),
            &client_network_address,
            Instant::now(),
            &mut probes,
            &multicast_tx,
            &mut resolves,
            probe_matches,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        // the resolve's message id must be recorded to accept the future ResolveMatches
        assert!(resolves.contains_key(&MessageId::from(Uuid::nil().urn())));

        let expected = format!(
            include_str!("../../test/resolve-template.xml"),
            Uuid::nil(),
            host_config.uuid_as_device_uri,
        );

        let response = {
            let response = multicast_rx.try_recv().unwrap();

            to_string_pretty(response.message.as_ref()).unwrap()
        };

        let expected = to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_every_probe_match() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // hosts
        let host_message_id = Uuid::now_v7();
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let first_endpoint = Uuid::now_v7().urn().to_string();
        let second_endpoint = Uuid::now_v7().urn().to_string();

        let probe_matches = format!(
            include_str!("../../test/probe-matches-multiple-without-xaddrs-template.xml"),
            host_message_id.urn(),
            first_endpoint,
            second_endpoint,
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(2);

        let (_, message) = message_handler
            .deconstruct_message(
                &probe_matches,
                SocketAddr::V4(SocketAddrV4::new(host_ip, 5000)),
            )
            .await
            .unwrap();

        let mut probes = {
            let mut hash_map = HashMap::new();

            hash_map.insert(
                MessageId::from(host_message_id.urn()),
                LastCopy::Sent(Instant::now()),
            );

            hash_map
        };

        let probe_matches = message.into_probe_matches().unwrap();

        let mut resolves = HashMap::new();

        let exchanges = exchange_runner(&client_config, &client_devices, &client_network_address);

        let result = handle_probe_matches(
            &exchanges,
            &client_config,
            Arc::clone(&client_devices),
            &client_network_address,
            Instant::now(),
            &mut probes,
            &multicast_tx,
            &mut resolves,
            probe_matches,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        for endpoint in [first_endpoint, second_endpoint] {
            let expected = format!(
                include_str!("../../test/resolve-template.xml"),
                Uuid::nil(),
                endpoint,
            );

            let response = {
                let response = multicast_rx.try_recv().unwrap();

                to_string_pretty(response.message.as_ref()).unwrap()
            };

            let expected = to_string_pretty(expected.as_bytes()).unwrap();

            assert_eq!(response, expected);
        }
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn ignores_probe_matches_for_outdated_probe() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let host_message_id = Uuid::now_v7();
        let host_ip = Ipv4Addr::new(192, 168, 100, 5);
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let probe_matches = format!(
            include_str!("../../test/probe-matches-without-xaddrs-template.xml"),
            host_message_id.urn(),
            host_config.app_sequence.instance_id(),
            0,
            host_config.uuid_as_device_uri,
            1,
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (_, message) = message_handler
            .deconstruct_message(
                &probe_matches,
                SocketAddr::V4(SocketAddrV4::new(host_ip, 5000)),
            )
            .await
            .unwrap();

        let last_copy_sent_at = Instant::now();

        let mut probes = {
            let mut hash_map = HashMap::new();

            hash_map.insert(
                MessageId::from(host_message_id.urn()),
                LastCopy::Sent(last_copy_sent_at),
            );

            hash_map
        };

        let probe_matches = message.into_probe_matches().unwrap();

        let mut resolves = HashMap::new();

        let exchanges = exchange_runner(&client_config, &client_devices, &client_network_address);

        let result = handle_probe_matches(
            &exchanges,
            &client_config,
            Arc::clone(&client_devices),
            &client_network_address,
            last_copy_sent_at + constants::MATCH_TIMEOUT,
            &mut probes,
            &multicast_tx,
            &mut resolves,
            probe_matches,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        // we expect no resolve to be sent
        assert_matches!(multicast_rx.try_recv(), Err(TryRecvError::Empty));
        assert!(resolves.is_empty());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_probe_matches_with_xaddrs() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let mut server = mock_server().await;

        let host_message_id = Uuid::now_v7();
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let expected_get = format!(
            include_str!("../../test/get-template.xml"),
            host_config.uuid_as_device_uri, client_config.uuid_as_device_uri
        );

        let mock = server
            .mock("POST", &*format!("/{}", host_config.uuid))
            .with_status(200)
            .with_body_from_request(move |request| {
                let metadata = synology_metadata();

                assert_eq!(
                    to_string_pretty(request.body().unwrap()).unwrap(),
                    to_string_pretty(expected_get.as_bytes()).unwrap()
                );

                metadata.into()
            })
            .create_async()
            .await;

        let probe_matches = format!(
            include_str!("../../test/probe-matches-with-xaddrs-template.xml"),
            host_message_id.urn(),
            host_config.app_sequence.instance_id(),
            0,
            host_config.uuid_as_device_uri,
            server.socket_address().ip(),
            server.socket_address().port(),
            host_config.uuid,
            1,
        );

        let (multicast_tx, mut multicast_rx) = tokio::sync::mpsc::channel(1);

        let (_, message) = message_handler
            .deconstruct_message(
                &probe_matches,
                SocketAddr::new(server.socket_address().ip(), 5000),
            )
            .await
            .unwrap();

        let mut probes = {
            let mut hash_map = HashMap::new();

            hash_map.insert(
                MessageId::from(host_message_id.urn()),
                LastCopy::Sent(Instant::now()),
            );

            hash_map
        };

        let probe_matches = message.into_probe_matches().unwrap();

        let mut resolves = HashMap::new();

        let exchanges = exchange_runner(&client_config, &client_devices, &client_network_address);

        let result = handle_probe_matches(
            &exchanges,
            &client_config,
            Arc::clone(&client_devices),
            &client_network_address,
            Instant::now(),
            &mut probes,
            &multicast_tx,
            &mut resolves,
            probe_matches,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        // ensure the mock is hit
        mock.assert_async().await;

        assert_matches!(multicast_rx.try_recv(), Err(TryRecvError::Empty));
        assert!(resolves.is_empty());

        let client_devices = client_devices.read().await;

        assert_matches!(client_devices.get(&host_config.uuid_as_device_uri), Some(_));
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_resolve_matches() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let mut server = mock_server().await;

        let host_message_id = Uuid::now_v7();
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let expected_get = format!(
            include_str!("../../test/get-template.xml"),
            host_config.uuid_as_device_uri, client_config.uuid_as_device_uri
        );

        let mock = server
            .mock("POST", &*format!("/{}", host_config.uuid))
            .with_status(200)
            .with_body_from_request(move |request| {
                let metadata = synology_metadata();

                assert_eq!(
                    to_string_pretty(request.body().unwrap()).unwrap(),
                    to_string_pretty(expected_get.as_bytes()).unwrap()
                );

                metadata.into()
            })
            .create_async()
            .await;

        let resolve_matches = format!(
            include_str!("../../test/resolve-matches-template.xml"),
            host_message_id.urn(),
            host_config.app_sequence.instance_id(),
            0,
            host_config.uuid_as_device_uri,
            server.socket_address().ip(),
            server.socket_address().port(),
            host_config.uuid,
            1,
        );

        let (_, message) = message_handler
            .deconstruct_message(
                &resolve_matches,
                SocketAddr::new(server.socket_address().ip(), 5000),
            )
            .await
            .unwrap();

        let mut resolves = {
            let mut hash_map = HashMap::new();

            hash_map.insert(
                MessageId::from(host_message_id.urn()),
                LastCopy::Sent(Instant::now()),
            );

            hash_map
        };

        let resolve_matches = message.into_resolve_matches().unwrap();

        let exchanges = exchange_runner(&client_config, &client_devices, &client_network_address);

        let result = handle_resolve_matches(
            &exchanges,
            Arc::clone(&client_devices),
            &client_network_address,
            Instant::now(),
            &mut resolves,
            resolve_matches,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        // ensure the mock is hit
        mock.assert_async().await;

        let client_devices = client_devices.read().await;

        assert_matches!(client_devices.get(&host_config.uuid_as_device_uri), Some(_));
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn handles_resolve_matches_without_match() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        let resolve_message_id = Uuid::now_v7();

        let resolve_matches = format!(
            include_str!("../../test/resolve-matches-without-match-template.xml"),
            resolve_message_id.urn(),
        );

        let (_, message) = message_handler
            .deconstruct_message(
                &resolve_matches,
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 100, 5), 5000)),
            )
            .await
            .unwrap();

        let resolve_matches = message.into_resolve_matches().unwrap();

        let mut resolves = HashMap::from([(
            MessageId::from(resolve_message_id.urn()),
            LastCopy::Sent(Instant::now()),
        )]);

        let exchanges = exchange_runner(&client_config, &client_devices, &client_network_address);

        let result = handle_resolve_matches(
            &exchanges,
            Arc::clone(&client_devices),
            &client_network_address,
            Instant::now(),
            &mut resolves,
            resolve_matches,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        assert!(client_devices.read().await.is_empty());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn ignores_resolve_matches_for_unknown_resolve() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let mut server = mock_server().await;

        let host_message_id = Uuid::now_v7();
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let mock = server
            .mock("POST", &*format!("/{}", host_config.uuid))
            .expect(0)
            .create_async()
            .await;

        let resolve_matches = format!(
            include_str!("../../test/resolve-matches-template.xml"),
            host_message_id.urn(),
            host_config.app_sequence.instance_id(),
            0,
            host_config.uuid_as_device_uri,
            server.socket_address().ip(),
            server.socket_address().port(),
            host_config.uuid,
            1,
        );

        let (_, message) = message_handler
            .deconstruct_message(
                &resolve_matches,
                SocketAddr::new(server.socket_address().ip(), 5000),
            )
            .await
            .unwrap();

        let resolve_matches = message.into_resolve_matches().unwrap();

        // no resolve with the message's `RelatesTo` was sent by us
        let exchanges = exchange_runner(&client_config, &client_devices, &client_network_address);

        let result = handle_resolve_matches(
            &exchanges,
            Arc::clone(&client_devices),
            &client_network_address,
            Instant::now(),
            &mut HashMap::new(),
            resolve_matches,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        // ensure the mock is not hit
        mock.assert_async().await;

        assert!(client_devices.read().await.is_empty());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn ignores_resolve_matches_for_outdated_resolve() {
        let (message_handler, client_network_address) = build_message_handler_with_network_address(
            IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host
        let mut server = mock_server().await;

        let host_message_id = Uuid::now_v7();
        let host_config = Arc::new(build_config(Uuid::now_v7(), 1_742_000_334));

        let mock = server
            .mock("POST", &*format!("/{}", host_config.uuid))
            .expect(0)
            .create_async()
            .await;

        let resolve_matches = format!(
            include_str!("../../test/resolve-matches-template.xml"),
            host_message_id.urn(),
            host_config.app_sequence.instance_id(),
            0,
            host_config.uuid_as_device_uri,
            server.socket_address().ip(),
            server.socket_address().port(),
            host_config.uuid,
            1,
        );

        let (_, message) = message_handler
            .deconstruct_message(
                &resolve_matches,
                SocketAddr::new(server.socket_address().ip(), 5000),
            )
            .await
            .unwrap();

        let last_copy_sent_at = Instant::now();

        let mut resolves = {
            let mut hash_map = HashMap::new();

            hash_map.insert(
                MessageId::from(host_message_id.urn()),
                LastCopy::Sent(last_copy_sent_at),
            );

            hash_map
        };

        let resolve_matches = message.into_resolve_matches().unwrap();

        let exchanges = exchange_runner(&client_config, &client_devices, &client_network_address);

        let result = handle_resolve_matches(
            &exchanges,
            Arc::clone(&client_devices),
            &client_network_address,
            last_copy_sent_at + constants::MATCH_TIMEOUT,
            &mut resolves,
            resolve_matches,
        )
        .await;

        exchanges.wait().await;

        assert_matches!(result, Ok(()));

        // ensure the mock is not hit
        mock.assert_async().await;

        assert!(client_devices.read().await.is_empty());
    }

    /// Reads one HTTP request, up to the end of its body.
    async fn read_request(stream: &mut TcpStream) {
        let mut request = Vec::new();
        let mut buffer = [0; 4096];

        loop {
            let read = stream.read(&mut buffer).await.unwrap();

            assert!(read > 0, "the client closed the connection mid-request");

            request.extend_from_slice(&buffer[..read]);

            let text = String::from_utf8_lossy(&request);

            if let Some((headers, _)) = text.split_once("\r\n\r\n") {
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        line.to_ascii_lowercase()
                            .strip_prefix("content-length:")
                            .map(|length| length.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);

                if request.len() >= headers.len() + 4 + content_length {
                    return;
                }
            }
        }
    }

    async fn respond_with_synology(stream: &mut TcpStream) {
        let body = synology_metadata();

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            constants::MIME_TYPE_SOAP_XML,
            body.len(),
            body
        );

        stream.write_all(response.as_bytes()).await.unwrap();
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn triggers_during_an_exchange_rerun_it_once() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let (client_config, client_devices) = setup_client();

        // host, which holds its first response until released
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let raw_xaddrs: Box<str> = format!("http://{}/", listener.local_addr().unwrap()).into();
        let (release_tx, release_rx) = oneshot::channel::<()>();
        let requests = Arc::new(AtomicUsize::new(0));

        let host = {
            let requests = Arc::clone(&requests);

            tokio::spawn(async move {
                let mut release_rx = Some(release_rx);

                loop {
                    let (mut stream, _) = listener.accept().await.unwrap();

                    read_request(&mut stream).await;

                    requests.fetch_add(1, Ordering::SeqCst);

                    if let Some(release_rx) = release_rx.take() {
                        release_rx.await.unwrap();
                    }

                    respond_with_synology(&mut stream).await;
                }
            })
        };

        let endpoint = new_endpoint();

        let exchanges = exchange_runner(&client_config, &client_devices, &network_address);

        let (multicast_tx, _multicast_rx) = tokio::sync::mpsc::channel(1);

        tokio::time::timeout(Duration::from_secs(10), async {
            for message_number in 1..=3 {
                let result = handle_hello(
                    &exchanges,
                    &client_config,
                    Arc::clone(&client_devices),
                    &network_address,
                    &multicast_tx,
                    &mut HashMap::new(),
                    Hello {
                        app_sequence: AppSequence::new(1, None, message_number),
                        endpoint: endpoint.clone(),
                        raw_xaddrs: Some(raw_xaddrs.clone()),
                        metadata_version: 1,
                    },
                )
                .await;

                assert_matches!(result, Ok(()));
            }

            release_tx.send(()).unwrap();

            exchanges.wait().await;
        })
        .await
        .unwrap();

        host.abort();

        assert_eq!(requests.load(Ordering::SeqCst), 2);

        assert!(client_devices.read().await.contains_key(&endpoint));
        assert!(!client_devices.read().await.has_running_exchanges());
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn cancellation_stops_a_running_exchange_and_its_rerun() {
        let (_message_handler, network_address) = build_message_handler_with_network_address(
            IpNet::new(Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        );

        // client
        let mut client_config = build_config(Uuid::now_v7(), 1_742_000_335);
        client_config.metadata_timeout = Duration::from_secs(60);
        let client_config = Arc::new(client_config);
        let client_devices = Arc::new(RwLock::new(Devices::default()));

        // host, which never answers
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let raw_xaddrs: Box<str> = format!("http://{}/", listener.local_addr().unwrap()).into();
        let (received_tx, received_rx) = oneshot::channel();

        let host = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();

            read_request(&mut stream).await;

            received_tx.send(()).unwrap();

            // ends when the client closes the connection
            let mut buffer = [0; 4096];

            while stream.read(&mut buffer).await.is_ok_and(|read| read > 0) {}
        });

        let cancellation_token = CancellationToken::new();

        let exchanges = ExchangeRunner::new(
            reqwest::ClientBuilder::new().build().unwrap(),
            Arc::clone(&client_config),
            Arc::clone(&client_devices),
            network_address.clone(),
            cancellation_token.clone(),
        );

        let (multicast_tx, _multicast_rx) = tokio::sync::mpsc::channel(1);

        let endpoint = new_endpoint();

        // the second Hello queues a rerun behind the hung exchange
        for message_number in 1..=2 {
            let result = handle_hello(
                &exchanges,
                &client_config,
                Arc::clone(&client_devices),
                &network_address,
                &multicast_tx,
                &mut HashMap::new(),
                Hello {
                    app_sequence: AppSequence::new(1, None, message_number),
                    endpoint: endpoint.clone(),
                    raw_xaddrs: Some(raw_xaddrs.clone()),
                    metadata_version: 1,
                },
            )
            .await;

            assert_matches!(result, Ok(()));
        }

        tokio::time::timeout(Duration::from_secs(5), received_rx)
            .await
            .unwrap()
            .unwrap();

        cancellation_token.cancel();

        tokio::time::timeout(Duration::from_secs(5), exchanges.wait())
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(5), host)
            .await
            .unwrap()
            .unwrap();

        assert!(client_devices.read().await.is_empty());
        assert!(!client_devices.read().await.has_running_exchanges());
    }

    fn new_endpoint() -> DeviceUri {
        DeviceUri::new(Uuid::now_v7().as_urn().to_string().into_boxed_str())
    }

    fn bound_to() -> IpNet {
        IpNet::new((Ipv4Addr::new(192, 168, 100, 20)).into(), 24).unwrap()
    }

    #[test]
    fn message_with_a_valid_xaddr_is_usable() {
        let check = check_xaddrs(
            bound_to(),
            "Hello",
            &new_endpoint(),
            Some(Box::from("http://192.168.100.5:5357/")),
        );

        assert_matches!(&check, XAddrsCheck::Usable(xaddrs) if xaddrs.len() == 1);
    }

    #[test]
    fn message_without_xaddrs_is_missing() {
        let check = check_xaddrs(bound_to(), "Hello", &new_endpoint(), None);

        assert_matches!(check, XAddrsCheck::Missing);
    }

    #[test]
    fn message_without_a_valid_xaddr_is_unusable() {
        let check = check_xaddrs(
            bound_to(),
            "Hello",
            &new_endpoint(),
            Some(Box::from("ftp://192.168.100.5/")),
        );

        assert_matches!(check, XAddrsCheck::Unusable);
    }

    #[test]
    fn filters_invalid_and_non_http_https() {
        let bound = IpNet::V4(Ipv4Net::new(Ipv4Addr::new(192, 168, 1, 10), 24).unwrap());

        let result = parse_xaddrs(
            bound,
            "http://valid.example.com https://also.valid ftp://ignored https:///#nohost",
        );

        let raws = result
            .iter()
            .map(|xaddr| xaddr.url().as_str())
            .collect::<Vec<_>>();

        assert_eq!(
            raws,
            ["http://valid.example.com/", "https://also.valid/"][..]
        );
    }

    #[test]
    fn rejects_missing_host() {
        let bound = IpNet::V4(Ipv4Net::new(Ipv4Addr::new(10, 0, 0, 1), 24).unwrap());

        let result = parse_xaddrs(
            bound,
            "http:////?missinghost=missing https://example.com/path",
        );

        let raws = result
            .iter()
            .map(|xaddr| xaddr.url().as_str())
            .collect::<Vec<_>>();

        assert_eq!(raws, ["https://example.com/path"][..]);
    }

    #[test]
    fn prefers_link_local_ipv6_first() {
        let bound =
            IpNet::V6(Ipv6Net::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64).unwrap());

        let result = parse_xaddrs(
            bound,
            "https://[2001:db8::1]/global https://[fe80::abcd]/local",
        );

        let raws = result
            .iter()
            .map(|xaddr| xaddr.url().as_str())
            .collect::<Vec<_>>();

        // link-local must be sorted first
        assert_eq!(raws.first().copied(), Some("https://[fe80::abcd]/local"));
    }

    #[test]
    fn keeps_device_order_within_equal_priority() {
        let bound =
            IpNet::V6(Ipv6Net::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 64).unwrap());

        // long enough that the sort does not take its small-slice path
        let (global, link_local): (Vec<_>, Vec<_>) = (1..=32_u16)
            .map(|index| {
                (
                    format!("https://[2001:db8::{:x}]/", index),
                    format!("https://[fe80::{:x}]/", index),
                )
            })
            .unzip();

        let raw_xaddrs = global
            .iter()
            .zip(&link_local)
            .flat_map(|(global, link_local)| [&**global, &**link_local])
            .collect::<Vec<_>>()
            .join(" ");

        let result = parse_xaddrs(bound, &raw_xaddrs);

        let raws = result
            .iter()
            .map(|xaddr| xaddr.url().as_str())
            .collect::<Vec<_>>();

        let expected = link_local
            .iter()
            .chain(&global)
            .map(|raw| &**raw)
            .collect::<Vec<_>>();

        assert_eq!(raws, expected);
    }
}
