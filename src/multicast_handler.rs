use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use color_eyre::{Section as _, eyre};
use hashbrown::HashMap;
use rand::Rng as _;
use socket2::{Domain, InterfaceIndexOrAddress, Socket, Type};
use tokio::net::UdpSocket;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{OnceCell, RwLock};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{Level, event};
use uuid::Uuid;

use crate::config::Config;
use crate::constants::{
    self, MULTICAST_UDP_REPEAT, UDP_MAX_DELAY, UDP_MIN_DELAY, UDP_UPPER_DELAY, UNICAST_UDP_REPEAT,
    WSD_HTTP_PORT, WSD_MAX_LEN, WSD_MCAST_GRP_V4, WSD_UDP_PORT,
};
use crate::network_address::NetworkAddress;
use crate::network_interface::NetworkInterface;
use crate::udp_address::UdpAddress;
use crate::url_ip_addr::UrlIpAddr;
use crate::utils::task::spawn_with_name;
use crate::wsd::device::WSDDiscoveredDevice;
use crate::wsd::http::http_server::WSDHttpServer;
use crate::wsd::udp::client::WSDClient;
use crate::wsd::udp::host::WSDHost;

/// A class for handling multicast traffic on a given interface for a
/// given address family. It provides multicast sender and receiver sockets
pub struct MulticastHandler {
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    devices: Arc<RwLock<HashMap<Uuid, WSDDiscoveredDevice>>>,

    messages_built: Arc<AtomicU64>,
    /// The address and interface we're bound on
    address: NetworkAddress,

    /// The multicast group on which we broadcast our messages
    #[expect(unused, reason = "WIP")]
    multicast_address: UdpAddress,
    #[expect(unused, reason = "WIP")]
    http_listen_address: SocketAddr,
    wsd_host: OnceCell<WSDHost>,
    wsd_client: OnceCell<WSDClient>,
    http_server: OnceCell<WSDHttpServer>,
    /// receiving multicast traffic on the WSD Port
    mc_wsd_port_rx: MessageReceiver,
    /// broadcast (sending multicast) from a socket bound to random / user provided port
    mc_local_port_tx: MessageSender<MulticastMessageSplitter>,
    /// receiving unicast traffic on the random / user provided port
    mc_local_port_rx: MessageReceiver,
    /// sending unicast messages from the WSD Port
    uc_wsd_port_tx: MessageSender<UnicastMessageSplitter>,
}

impl MulticastHandler {
    pub fn new(
        address: NetworkAddress,
        cancellation_token: CancellationToken,
        config: &Arc<Config>,
    ) -> Result<Self, eyre::Report> {
        let domain = match address.address {
            IpAddr::V4(_) => Domain::IPV4,
            IpAddr::V6(_) => Domain::IPV6,
        };

        // TODO error
        let mc_wsd_port_socket = Socket::new(domain, Type::DGRAM, None)?;
        mc_wsd_port_socket.set_nonblocking(true)?;
        mc_wsd_port_socket.set_reuse_address(true)?;

        // TODO error
        let mc_local_port_socket = Socket::new(domain, Type::DGRAM, None)?;
        mc_local_port_socket.set_nonblocking(true)?;

        // TODO error
        let uc_wsd_port_socket = Socket::new(domain, Type::DGRAM, None)?;
        uc_wsd_port_socket.set_nonblocking(true)?;
        uc_wsd_port_socket.set_reuse_address(true)?;

        let (multicast_address, http_listen_address) = match address.address {
            IpAddr::V4(ipv4_address) => MulticastHandler::init_v4(
                ipv4_address,
                Arc::clone(&address.interface),
                &mc_wsd_port_socket,
                &mc_local_port_socket,
                &uc_wsd_port_socket,
                config,
            )?,
            IpAddr::V6(ipv6_address) => MulticastHandler::init_v6(
                ipv6_address,
                Arc::clone(&address.interface),
                &mc_wsd_port_socket,
                &mc_local_port_socket,
                &uc_wsd_port_socket,
                config,
            )?,
        };

        event!(
            Level::INFO,
            "joined multicast group {} on {}",
            UrlIpAddr::from(multicast_address.transport_address.ip()),
            address
        );
        event!(
            Level::DEBUG,
            "transport address on {} is {}",
            address.interface.name,
            UrlIpAddr::from(address.address)
        );
        event!(
            Level::DEBUG,
            "will listen for HTTP traffic on address {}",
            http_listen_address
        );

        let mc_wsd_port_socket = Arc::new(UdpSocket::from_std(mc_wsd_port_socket.into())?);
        let mc_wsd_port_rx = MessageReceiver::new(Arc::clone(&mc_wsd_port_socket));

        let mc_local_port_socket = Arc::new(UdpSocket::from_std(mc_local_port_socket.into())?);
        let mc_local_port_tx = MessageSender::new(
            Arc::clone(&mc_local_port_socket),
            MulticastMessageSplitter {
                target: multicast_address.transport_address,
            },
        );
        let mc_local_port_rx = MessageReceiver::new(Arc::clone(&mc_local_port_socket));

        let uc_wsd_port_socket = Arc::new(UdpSocket::from_std(uc_wsd_port_socket.into())?);
        let uc_wsd_port_tx =
            MessageSender::new(Arc::clone(&uc_wsd_port_socket), UnicastMessageSplitter {});

        Ok(Self {
            config: Arc::clone(config),
            cancellation_token,
            address,
            devices: Arc::new(RwLock::new(HashMap::new())),
            messages_built: Arc::new(AtomicU64::new(0)),
            multicast_address,
            http_listen_address,
            wsd_client: OnceCell::new(),
            wsd_host: OnceCell::new(),
            http_server: OnceCell::new(),
            mc_wsd_port_rx,
            mc_local_port_tx,
            mc_local_port_rx,
            uc_wsd_port_tx,
        })
    }

    pub async fn teardown(self, graceful: bool) {
        if let Some(host) = self.wsd_host.into_inner() {
            host.teardown(graceful).await;

            // graceful teardown makes the host queue up a goodbye, so when we're here we have made an honest try to schedule the goodbye message

            // host is dropped
        }

        // TODO drop client
        if let Some(client) = self.wsd_client.into_inner() {
            client.teardown(graceful).await;

            // client is dropped
        }

        // TODO drop http

        if graceful {
            // we drop the sender first, which makes the handle go into cleanup mode, and gracefully try to send the lsat messages to the sockets

            // we have to rely on dropping the sender because that is the only way we can have the receiver run to completion
            // a cancellation token and tokio::select might cause the handle to top before parsing the rest of the messages
            let sender = self.mc_local_port_tx;
            sender.teardown().await;

            let sender = self.uc_wsd_port_tx;
            sender.teardown().await;
        }

        // since this consumes self, now the sockets etc are closed. We awaited all tasks, and thus are sure that messages were either
        // sent, or failed to send, but we avoided the 'schedule but shut down too soon' situation.
    }

    pub fn handles_address(&self, address: &NetworkAddress) -> bool {
        &self.address == address
    }

    fn init_v6(
        ipv6_address: Ipv6Addr,
        interface: Arc<NetworkInterface>,
        mc_wsd_port_socket: &Socket,
        mc_local_port_socket: &Socket,
        uc_wsd_port_socket: &Socket,
        config: &Arc<Config>,
    ) -> Result<(UdpAddress, SocketAddr), eyre::Report> {
        let idx = interface.index;

        let multicast_address = UdpAddress::new(
            SocketAddrV6::new(
                constants::WSD_MCAST_GRP_V6,
                constants::WSD_UDP_PORT.into(),
                0x575C_u32,
                idx,
            )
            .into(),
            interface,
        );

        // TODO handle error
        mc_wsd_port_socket.join_multicast_v6(&constants::WSD_MCAST_GRP_V6, idx)?;

        // TODO error
        mc_wsd_port_socket.set_only_v6(true)?;

        // TODO error
        // https://github.com/torvalds/linux/commit/15033f0457dca569b284bef0c8d3ad55fb37eacb
        if let Err(error) = mc_wsd_port_socket.set_multicast_all_v6(false) {
            event!(Level::WARN, ?error, "cannot unset IPV6_MULTICAST_ALL");
        }

        // bind to network interface, i.e. scope and handle OS differences,
        // see Stevens: Unix Network Programming, Section 21.6, last paragraph
        let socket_addr =
            SocketAddrV6::new(constants::WSD_MCAST_GRP_V6, WSD_UDP_PORT.into(), 0, idx);

        if let Err(error) = mc_wsd_port_socket.bind(&socket_addr.into()) {
            event!(Level::WARN, ?error, %socket_addr, "Failed to bind to socket");

            let fallback = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, idx);

            if let Err(error) = mc_wsd_port_socket.bind(&fallback.into()) {
                event!(
                    Level::ERROR,
                    ?error,
                    %fallback,
                    "Fallback also failed to bind",
                );

                return Err(eyre::Report::msg(format!(
                    "Fallback also failed to bind to {}",
                    fallback
                )));
            }
        }

        // TODO error
        mc_local_port_socket.set_multicast_loop_v6(false)?;

        // TODO error
        mc_local_port_socket.set_multicast_hops_v6(config.hoplimit.into())?;

        // TODO error
        mc_local_port_socket.set_multicast_if_v6(idx)?;

        // TODO error
        mc_local_port_socket
            .bind(&(SocketAddrV6::new(ipv6_address, config.source_port, 0, idx)).into())?;

        // bind unicast socket to interface address and WSD's udp port
        uc_wsd_port_socket
            .bind(&SocketAddrV6::new(ipv6_address, WSD_UDP_PORT.into(), 0, idx).into())?;

        let listen_address = SocketAddrV6::new(ipv6_address, WSD_HTTP_PORT.into(), 0, idx);

        Ok((multicast_address, listen_address.into()))
    }

    fn init_v4(
        ipv4_address: Ipv4Addr,
        interface: Arc<NetworkInterface>,
        mc_wsd_port_socket: &Socket,
        mc_local_port_socket: &Socket,
        uc_wsd_port_socket: &Socket,
        config: &Arc<Config>,
    ) -> Result<(UdpAddress, SocketAddr), eyre::Report> {
        let idx = interface.index;

        let multicast_address = UdpAddress::new(
            SocketAddrV4::new(WSD_MCAST_GRP_V4, WSD_UDP_PORT.into()).into(),
            interface,
        );

        if let Err(error) = mc_wsd_port_socket
            .join_multicast_v4_n(&WSD_MCAST_GRP_V4, &InterfaceIndexOrAddress::Index(idx))
        {
            event!(Level::ERROR, ?error, multi_addr = ?WSD_MCAST_GRP_V4, ifindex = ?idx, "could not join multicast group");

            return Err(eyre::Report::msg("could not join multicast group"));
        }

        if let Err(error) = mc_wsd_port_socket.set_multicast_all_v4(false) {
            event!(Level::ERROR, ?error, "could not unset IP_MULTICAST_ALL");

            return Err(eyre::Report::msg("could not unset IP_MULTICAST_ALL"));
        }

        let socket_addr = SocketAddrV4::new(WSD_MCAST_GRP_V4, WSD_UDP_PORT.into());

        if let Err(error) = mc_wsd_port_socket.bind(&socket_addr.into()) {
            event!(Level::WARN, ?error, %socket_addr, "Failed to bind to socket");

            let fallback = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, WSD_UDP_PORT.into());

            if let Err(error) = mc_wsd_port_socket.bind(&fallback.into()) {
                event!(
                    Level::ERROR,
                    ?error,
                    %fallback,
                    "Fallback also failed to bind",
                );

                return Err(eyre::Report::msg(format!(
                    "Fallback also failed to bind to {}",
                    fallback
                )));
            }
        }

        if let Err(error) = mc_local_port_socket.set_multicast_if_v4(&ipv4_address) {
            event!(
                Level::ERROR,
                ?error,
                "Failed to set IPPROTO_IP -> IP_MULTICAST_IF on socket"
            );

            return Err(eyre::Report::from(error)
                .with_note(|| "Failed to set IPPROTO_IP -> IP_MULTICAST_IF on socket"));
        }

        // # OpenBSD requires the optlen to be sizeof(char) for LOOP and TTL options
        // # (see also https://github.com/python/cpython/issues/67316)
        // TODO openBSD/freebsd case
        if let Err(error) = mc_local_port_socket.set_multicast_loop_v4(false) {
            event!(
                Level::ERROR,
                ?error,
                "Failed to set IPPROTO_IP -> IP_MULTICAST_LOOP on socket"
            );

            return Err(eyre::Report::from(error)
                .with_note(|| "Failed to set IPPROTO_IP -> IP_MULTICAST_LOOP on socket"));
        }

        if let Err(error) = mc_local_port_socket.set_multicast_ttl_v4(config.hoplimit.into()) {
            event!(
                Level::ERROR,
                ?error,
                "Failed to set IPPROTO_IP -> IP_MULTICAST_TTL on socket"
            );

            return Err(eyre::Report::from(error)
                .with_note(|| "Failed to set IPPROTO_IP -> IP_MULTICAST_TTL on socket"));
        }

        // TODO error
        mc_local_port_socket.bind(&(SocketAddrV4::new(ipv4_address, config.source_port)).into())?;

        // bind unicast socket to interface address and WSD's udp port
        uc_wsd_port_socket.bind(&SocketAddrV4::new(ipv4_address, WSD_UDP_PORT.into()).into())?;

        let listen_address = SocketAddrV4::new(ipv4_address, WSD_HTTP_PORT.into());

        Ok((multicast_address, listen_address.into()))
    }

    pub async fn enable_wsd_host(&mut self) {
        self.wsd_host
            .get_or_init(|| async {
                let host = WSDHost::init(
                    &self.cancellation_token,
                    Arc::clone(&self.config),
                    Arc::clone(&self.messages_built),
                    self.address.clone(),
                    self.mc_wsd_port_rx.get_listener().await,
                    self.mc_local_port_tx.get_sender(),
                    self.uc_wsd_port_tx.get_sender(),
                )
                .await;

                host
            })
            .await;
    }

    pub async fn enable_wsd_client(&mut self) {
        self.wsd_client
            .get_or_init(|| async {
                let client = WSDClient::init(
                    &self.cancellation_token,
                    Arc::clone(&self.config),
                    Arc::clone(&self.devices),
                    self.address.clone(),
                    self.mc_wsd_port_rx.get_listener().await,
                    self.mc_local_port_rx.get_listener().await,
                    self.mc_local_port_tx.get_sender(),
                )
                .await;

                client
            })
            .await;
    }

    pub async fn enable_http_server(&self) {
        self.http_server
            .get_or_init(|| async {
                let server = WSDHttpServer::init(
                    self.address.clone(),
                    self.cancellation_token.clone(),
                    Arc::clone(&self.config),
                );

                server
            })
            .await;
    }
}

type Receivers = Arc<RwLock<Vec<Sender<(SocketAddr, Arc<[u8]>)>>>>;

struct MessageReceiver {
    listeners: Receivers,
}

type Channels = Arc<RwLock<Vec<Sender<(SocketAddr, Arc<[u8]>)>>>>;

async fn socket_rx(socket: Arc<UdpSocket>, channels: Channels) {
    #[expect(clippy::infinite_loop, reason = "Endless task")]
    // TODO await cancellation token
    loop {
        let mut buffer = vec![MaybeUninit::<u8>::uninit(); WSD_MAX_LEN];

        let (bytes_read, from) = match socket.recv_buf_from(&mut buffer.as_mut_slice()).await {
            Ok(read) => read,
            Err(error) => {
                let local_addr = socket.local_addr().map_or_else(
                    |err| format!("Failed to get local socket address: {:?}", err),
                    |addr| addr.to_string(),
                );

                event!(
                    Level::ERROR,
                    ?error,
                    local_addr,
                    "Failed to read from socket"
                );

                continue;
            },
        };

        // `recv_buf` tells us that `bytes_read` were read from the socket into our `buffer`, so they're initialized
        buffer.truncate(bytes_read);

        let buffer = Arc::<[_]>::from(buffer);

        // SAFETY: we are only initializing the parts of the buffer `recv_buf_from` has written to
        let buffer = unsafe { buffer.assume_init() };

        let lock = channels.read().await;

        for channel in &*lock {
            if let Err(error) = channel.send((from, Arc::clone(&buffer))).await {
                event!(Level::ERROR, ?error, socket = ?socket.local_addr().unwrap(), "Failed to send data to channel");
            }
        }
    }
}

impl MessageReceiver {
    fn new(socket: Arc<UdpSocket>) -> Self {
        let listeners: Receivers = Receivers::new(RwLock::const_new(vec![]));

        let channels = Arc::clone(&listeners);

        spawn_with_name(
            format!("socket rx ({})", socket.local_addr().unwrap()).as_str(),
            socket_rx(socket, channels),
        );

        Self { listeners }
    }

    async fn get_listener(&mut self) -> Receiver<(SocketAddr, Arc<[u8]>)> {
        let (tx, rx) = tokio::sync::mpsc::channel(10);

        self.listeners.write().await.push(tx);

        rx
    }
}

trait MessageSplitter {
    const REPEAT: usize;

    type Message: Send;

    fn split_message(&self, message: Self::Message) -> (SocketAddr, Box<[u8]>);
}

struct MulticastMessageSplitter {
    target: SocketAddr,
}

impl MessageSplitter for MulticastMessageSplitter {
    const REPEAT: usize = MULTICAST_UDP_REPEAT;

    type Message = Box<[u8]>;

    fn split_message(&self, message: Self::Message) -> (SocketAddr, Box<[u8]>) {
        (self.target, message)
    }
}

struct UnicastMessageSplitter {}

impl MessageSplitter for UnicastMessageSplitter {
    const REPEAT: usize = UNICAST_UDP_REPEAT;

    type Message = (SocketAddr, Box<[u8]>);

    fn split_message(&self, message: Self::Message) -> (SocketAddr, Box<[u8]>) {
        (message.0, message.1)
    }
}

struct MessageSender<T: MessageSplitter> {
    handler: JoinHandle<()>,
    sender: Sender<T::Message>,
}

async fn repeatedly_send_buffer<T: MessageSplitter>(
    socket: Arc<UdpSocket>,
    buffer: Box<[u8]>,
    to: SocketAddr,
) {
    // Schedule to send the given message to the given address.
    // Implements SOAP over UDP, Appendix I.
    let mut delta = rand::rng().random_range(UDP_MIN_DELAY..=UDP_MAX_DELAY);

    for i in 0..T::REPEAT {
        if i != 0 {
            sleep(Duration::from_millis(delta)).await;
            delta = UDP_UPPER_DELAY.min(delta * 2);
        }

        match socket.send_to(buffer.as_ref(), to).await {
            Ok(_) => {},
            Err(error) => {
                event!(Level::WARN, ?error, "Failed to send data");
            },
        }
    }
}

impl<T: MessageSplitter + Send + 'static> MessageSender<T> {
    fn new(socket: Arc<UdpSocket>, message_splitter: T) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<T::Message>(10);

        let handler = spawn_with_name("sender", async move {
            let tracker = TaskTracker::new();

            loop {
                let Some(buffer) = rx.recv().await else {
                    event!(Level::INFO, "All senders gone, shutting down");
                    break;
                };

                let (to, buffer) = message_splitter.split_message(buffer);

                let socket = Arc::clone(&socket);

                spawn_with_name(
                    "message sender",
                    tracker.track_future(async move {
                        repeatedly_send_buffer::<T>(socket, buffer, to).await;
                    }),
                );
            }

            tracker.close();
            tracker.wait().await;
        });

        Self {
            handler,
            sender: tx,
        }
    }

    fn get_sender(&mut self) -> Sender<T::Message> {
        self.sender.clone()
    }

    async fn teardown(self) {
        drop(self.sender);

        let _r = self.handler.await;
    }
}
