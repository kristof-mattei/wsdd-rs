use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::time::Duration;

use color_eyre::eyre::{self, Context as _};
use hashbrown::HashMap;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
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

use crate::config::Config;
use crate::constants;
use crate::network_address::NetworkAddress;
use crate::network_interface::NetworkInterface;
use crate::udp_address::UdpAddress;
use crate::url_ip_addr::UrlIpAddr;
use crate::utils::task::spawn_with_name;
use crate::wsd::device::{DeviceUri, WSDDiscoveredDevice};
use crate::wsd::http::http_server::WSDHttpServer;
use crate::wsd::udp::client::WSDClient;
use crate::wsd::udp::host::WSDHost;

/// A class for handling multicast traffic on a given interface for a
/// given address family. It provides multicast sender and receiver sockets
pub struct MulticastHandler {
    cancellation_token: CancellationToken,
    config: Arc<Config>,

    /// Shared reference to all discovered devices
    devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,

    /// Shared reference for global message counter
    messages_built: Arc<AtomicU64>,
    /// The address and interface we're bound on
    network_address: NetworkAddress,

    /// The multicast group on which we broadcast our messages
    #[expect(unused, reason = "WIP")]
    multicast_address: UdpAddress,
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

#[expect(clippy::struct_field_names, reason = "Clarity")]
struct Sockets {
    mc_wsd_port_socket: Socket,
    mc_local_port_socket: Socket,
    uc_wsd_port_socket: Socket,
}

fn create_sockets(domain: Domain) -> Result<Sockets, eyre::Report> {
    let mc_wsd_port_socket = Socket::new(domain, Type::DGRAM, None)?;
    mc_wsd_port_socket.set_nonblocking(true)?;
    mc_wsd_port_socket.set_reuse_address(true)?;

    let mc_local_port_socket = Socket::new(domain, Type::DGRAM, None)?;
    mc_local_port_socket.set_nonblocking(true)?;

    let uc_wsd_port_socket = Socket::new(domain, Type::DGRAM, None)?;
    uc_wsd_port_socket.set_nonblocking(true)?;
    uc_wsd_port_socket.set_reuse_address(true)?;

    Ok(Sockets {
        mc_wsd_port_socket,
        mc_local_port_socket,
        uc_wsd_port_socket,
    })
}

impl MulticastHandler {
    pub fn new(
        network_address: NetworkAddress,
        cancellation_token: CancellationToken,
        config: Arc<Config>,
        devices: Arc<RwLock<HashMap<DeviceUri, WSDDiscoveredDevice>>>,
    ) -> Result<Self, (NetworkAddress, eyre::Report)> {
        let domain = match network_address.address {
            IpNet::V4(_) => Domain::IPV4,
            IpNet::V6(_) => Domain::IPV6,
        };

        let sockets = match create_sockets(domain).wrap_err("Failed to set up sockets") {
            Ok(sockets) => sockets,
            Err(err) => return Err((network_address, err)),
        };

        let (multicast_address, http_listen_address) = match MulticastHandler::init(
            network_address.address,
            Arc::clone(&network_address.interface),
            &sockets,
            &config,
        ) {
            Ok(addresses) => addresses,
            Err(err) => return Err((network_address, err)),
        };

        event!(
            Level::INFO,
            "joined multicast group {} on {}",
            UrlIpAddr::from(multicast_address.get_transport_address().ip()),
            network_address
        );

        event!(
            Level::DEBUG,
            "transport address on {} is {}",
            network_address.interface.name(),
            UrlIpAddr::from(network_address.address.addr())
        );

        event!(
            Level::DEBUG,
            "will listen for HTTP traffic on address {}",
            http_listen_address
        );

        let Sockets {
            mc_wsd_port_socket,
            mc_local_port_socket,
            uc_wsd_port_socket,
        } = sockets;

        let mc_wsd_port_socket = Arc::new({
            match UdpSocket::from_std(mc_wsd_port_socket.into()) {
                Ok(socket) => socket,
                Err(err) => return Err((network_address, err.into())),
            }
        });

        let mc_wsd_port_rx =
            MessageReceiver::new(cancellation_token.clone(), Arc::clone(&mc_wsd_port_socket));

        let mc_local_port_socket = Arc::new({
            match UdpSocket::from_std(mc_local_port_socket.into()) {
                Ok(socket) => socket,
                Err(err) => return Err((network_address, err.into())),
            }
        });

        let mc_local_port_tx = MessageSender::new(
            Arc::clone(&mc_local_port_socket),
            MulticastMessageSplitter {
                target: multicast_address.get_transport_address(),
            },
        );

        let mc_local_port_rx = MessageReceiver::new(
            cancellation_token.clone(),
            Arc::clone(&mc_local_port_socket),
        );

        let uc_wsd_port_socket = Arc::new({
            match UdpSocket::from_std(uc_wsd_port_socket.into()) {
                Ok(socket) => socket,
                Err(err) => return Err((network_address, err.into())),
            }
        });

        let uc_wsd_port_tx =
            MessageSender::new(Arc::clone(&uc_wsd_port_socket), UnicastMessageSplitter {});

        Ok(Self {
            config,
            cancellation_token,
            network_address,
            devices,
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

    fn init(
        address: IpNet,
        interface: Arc<NetworkInterface>,
        sockets: &Sockets,
        config: &Config,
    ) -> Result<(UdpAddress, SocketAddr), eyre::Report> {
        match address {
            IpNet::V4(ipv4_net) => MulticastHandler::init_v4(ipv4_net, interface, sockets, config),
            IpNet::V6(ipv6_net) => MulticastHandler::init_v6(ipv6_net, interface, sockets, config),
        }
    }

    pub async fn teardown(self, graceful: bool) {
        if let Some(host) = self.wsd_host.into_inner() {
            // graceful teardown makes the host queue up a goodbye, so when we're here we have made an honest try to schedule the goodbye message
            host.teardown(graceful).await;

            // host is dropped
        }

        if let Some(client) = self.wsd_client.into_inner() {
            client.teardown().await;

            // client is dropped
        }

        if let Some(http_server) = self.http_server.into_inner() {
            http_server.teardown().await;

            // http_server is dropped
        }

        if graceful {
            // we drop the sender first, which makes the handle go into cleanup mode, and gracefully try to send the last messages to the sockets

            // we have to rely on dropping the sender because that is the only way we can have the receiver run to completion
            // a cancellation token and tokio::select might cause the handle to top before parsing the rest of the messages
            let sender = self.mc_local_port_tx;
            sender.teardown().await;

            let sender = self.uc_wsd_port_tx;
            sender.teardown().await;
        }

        self.mc_wsd_port_rx.teardown().await;
        self.mc_local_port_rx.teardown().await;

        // since this consumes self, now the sockets etc are closed. We awaited all tasks, and thus are sure that messages were either
        // sent, or failed to send, but we avoided the 'schedule but shut down too soon' situation.
    }

    pub fn handles_address(&self, network_address: &NetworkAddress) -> bool {
        &self.network_address == network_address
    }

    fn init_v6(
        ipv6_net: Ipv6Net,
        interface: Arc<NetworkInterface>,
        &Sockets {
            ref mc_wsd_port_socket,
            ref mc_local_port_socket,
            ref uc_wsd_port_socket,
        }: &Sockets,
        config: &Config,
    ) -> Result<(UdpAddress, SocketAddr), eyre::Report> {
        let index = interface.index();

        let multicast_address = UdpAddress::new(
            SocketAddrV6::new(
                constants::WSD_MCAST_GRP_V6,
                constants::WSD_UDP_PORT.into(),
                0x575C_u32,
                index,
            )
            .into(),
            ipv6_net.into(),
            interface,
        );

        mc_wsd_port_socket
            .join_multicast_v6(&constants::WSD_MCAST_GRP_V6, index)
            .wrap_err("Failed to join IPv6 multicast group")?;

        mc_wsd_port_socket
            .set_only_v6(true)
            .wrap_err("Failed to set IPV6_V6ONLY")?;

        // TODO error
        // https://github.com/torvalds/linux/commit/15033f0457dca569b284bef0c8d3ad55fb37eacb
        if let Err(error) = mc_wsd_port_socket.set_multicast_all_v6(false) {
            event!(Level::WARN, ?error, "cannot unset IPV6_MULTICAST_ALL");
        }

        // bind to network interface, i.e. scope and handle OS differences,
        // see Stevens: Unix Network Programming, Section 21.6, last paragraph
        let socket_addr = SocketAddrV6::new(
            constants::WSD_MCAST_GRP_V6,
            constants::WSD_UDP_PORT.into(),
            0,
            index,
        );

        if let Err(error) = mc_wsd_port_socket.bind(&socket_addr.into()) {
            event!(Level::WARN, ?error, %socket_addr, "Failed to bind to socket");

            let fallback = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, index);

            mc_wsd_port_socket
                .bind(&fallback.into())
                .wrap_err("Failed to bind to fallback socket")?;
        }

        mc_local_port_socket
            .set_multicast_loop_v6(false)
            .wrap_err("Failed to disable IPV6_MULTICAST_LOOP")?;

        mc_local_port_socket
            .set_multicast_hops_v6(config.hoplimit.into())
            .wrap_err("Failed to set IPV6_MULTICAST_HOPS")?;

        mc_local_port_socket
            .set_multicast_if_v6(index)
            .wrap_err("Failed to set IPV6_MULTICAST_IF")?;

        mc_local_port_socket
            .bind(&(SocketAddrV6::new(ipv6_net.addr(), config.source_port, 0, index)).into())
            .wrap_err("Failed to bind to the socket")?;

        // bind unicast socket to interface address and WSD's udp port
        uc_wsd_port_socket
            .bind(
                &SocketAddrV6::new(ipv6_net.addr(), constants::WSD_UDP_PORT.into(), 0, index)
                    .into(),
            )
            .wrap_err("Failed to bind to the socket")?;

        let listen_address =
            SocketAddrV6::new(ipv6_net.addr(), constants::WSD_HTTP_PORT.into(), 0, index);

        Ok((multicast_address, listen_address.into()))
    }

    fn init_v4(
        ipv4_net: Ipv4Net,
        interface: Arc<NetworkInterface>,
        &Sockets {
            ref mc_wsd_port_socket,
            ref mc_local_port_socket,
            ref uc_wsd_port_socket,
        }: &Sockets,
        config: &Config,
    ) -> Result<(UdpAddress, SocketAddr), eyre::Report> {
        let index = interface.index();

        let multicast_address = UdpAddress::new(
            SocketAddrV4::new(constants::WSD_MCAST_GRP_V4, constants::WSD_UDP_PORT.into()).into(),
            ipv4_net.into(),
            interface,
        );

        mc_wsd_port_socket
            .join_multicast_v4_n(
                &constants::WSD_MCAST_GRP_V4,
                &InterfaceIndexOrAddress::Index(index),
            )
            .wrap_err("Failed to join IPv4 multicast group")?;

        mc_wsd_port_socket
            .set_multicast_all_v4(false)
            .wrap_err("Failed to disable IP_MULTICAST_ALL")?;

        let socket_addr =
            SocketAddrV4::new(constants::WSD_MCAST_GRP_V4, constants::WSD_UDP_PORT.into());

        if let Err(error) = mc_wsd_port_socket.bind(&socket_addr.into()) {
            event!(Level::WARN, ?error, %socket_addr, "Failed to bind to socket");

            let fallback = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, constants::WSD_UDP_PORT.into());

            mc_wsd_port_socket
                .bind(&fallback.into())
                .wrap_err("Failed to bind to fallback socket")?;
        }

        mc_local_port_socket
            .set_multicast_if_v4(&ipv4_net.addr())
            .wrap_err("Failed to set IP_MULTICAST_IF")?;

        // # OpenBSD requires the optlen to be sizeof(char) for LOOP and TTL options
        // # (see also https://github.com/python/cpython/issues/67316)
        // TODO openBSD/freebsd case
        mc_local_port_socket
            .set_multicast_loop_v4(false)
            .wrap_err("Failed to set IP_MULTICAST_LOOP")?;

        mc_local_port_socket
            .set_multicast_ttl_v4(config.hoplimit.into())
            .wrap_err("Failed to set IP_MULTICAST_TTL")?;

        mc_local_port_socket
            .bind(&(SocketAddrV4::new(ipv4_net.addr(), config.source_port)).into())
            .wrap_err("Failed to bind to the socket")?;

        // bind unicast socket to interface address and WSD's udp port
        uc_wsd_port_socket
            .bind(&SocketAddrV4::new(ipv4_net.addr(), constants::WSD_UDP_PORT.into()).into())
            .wrap_err("Failed to bind to the socket")?;

        let listen_address = SocketAddrV4::new(ipv4_net.addr(), constants::WSD_HTTP_PORT.into());

        Ok((multicast_address, listen_address.into()))
    }

    pub async fn enable_wsd_host(&mut self) {
        self.wsd_host
            .get_or_init(|| async {
                let host = WSDHost::init(
                    self.cancellation_token.child_token(),
                    Arc::clone(&self.config),
                    Arc::clone(&self.messages_built),
                    self.network_address.clone(),
                    self.mc_wsd_port_rx.get_rx().await,
                    self.mc_local_port_tx.get_tx(),
                    self.uc_wsd_port_tx.get_tx(),
                );

                host
            })
            .await;
    }

    pub fn wsd_client(&self) -> Option<&WSDClient> {
        self.wsd_client.get()
    }

    pub async fn enable_wsd_client(&mut self) {
        self.wsd_client
            .get_or_init(|| async {
                let client = WSDClient::init(
                    self.cancellation_token.child_token(),
                    Arc::clone(&self.config),
                    Arc::clone(&self.devices),
                    self.network_address.clone(),
                    self.mc_wsd_port_rx.get_rx().await,
                    self.mc_local_port_rx.get_rx().await,
                    self.mc_local_port_tx.get_tx(),
                );

                client
            })
            .await;
    }

    pub async fn enable_http_server(&self) {
        let result = self
            .http_server
            .get_or_try_init(|| async {
                let server = WSDHttpServer::init(
                    self.network_address.clone(),
                    self.cancellation_token.child_token(),
                    Arc::clone(&self.config),
                    self.http_listen_address,
                )
                .await;

                server
            })
            .await;

        if let Err(error) = result {
            event!(
                Level::ERROR,
                ?error,
                "Failed to initialize the http server, probably failed to bind to addr:port"
            );
        }
    }

    pub fn get_network_address(&self) -> &NetworkAddress {
        &self.network_address
    }
}

type Receivers = Arc<RwLock<Vec<Sender<(SocketAddr, Arc<[u8]>)>>>>;

struct MessageReceiver {
    cancellation_token: CancellationToken,
    handle: JoinHandle<()>,
    listeners: Receivers,
}

type Channels = Arc<RwLock<Vec<Sender<(SocketAddr, Arc<[u8]>)>>>>;

async fn socket_rx_forever(
    cancellation_token: CancellationToken,
    channels: Channels,
    socket: Arc<UdpSocket>,
) {
    loop {
        let mut buffer = vec![MaybeUninit::<u8>::uninit(); constants::WSD_MAX_LEN];

        let result = {
            let mut buffer_byte_cursor = &mut *buffer;

            tokio::select! {
                () = cancellation_token.cancelled() => {
                    break;
                }
                result = socket.recv_buf_from(&mut buffer_byte_cursor) => {
                    result
                },
            }
        };

        let (bytes_read, from) = match result {
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
    fn new(cancellation_token: CancellationToken, socket: Arc<UdpSocket>) -> Self {
        let listeners: Receivers = Receivers::new(RwLock::const_new(vec![]));

        let channels = Arc::clone(&listeners);

        let handle = spawn_with_name(
            format!("socket rx ({})", socket.local_addr().unwrap()).as_str(),
            socket_rx_forever(cancellation_token.clone(), channels, socket),
        );

        Self {
            cancellation_token,
            handle,
            listeners,
        }
    }

    async fn get_rx(&mut self) -> Receiver<(SocketAddr, Arc<[u8]>)> {
        let (tx, rx) = tokio::sync::mpsc::channel(10);

        self.listeners.write().await.push(tx);

        rx
    }

    async fn teardown(self) {
        self.cancellation_token.cancel();

        let _r = self.handle.await;
    }
}

trait MessageSplitter {
    const NAME: &str;
    const REPEAT: usize;

    type Message: Send;

    fn split_message(&self, message: Self::Message) -> (SocketAddr, Box<[u8]>);
}

struct MulticastMessageSplitter {
    target: SocketAddr,
}

impl MessageSplitter for MulticastMessageSplitter {
    const NAME: &str = "MulticastMessageSplitter";
    const REPEAT: usize = constants::MULTICAST_UDP_REPEAT;

    type Message = Box<[u8]>;

    fn split_message(&self, message: Self::Message) -> (SocketAddr, Box<[u8]>) {
        (self.target, message)
    }
}

struct UnicastMessageSplitter {}

impl MessageSplitter for UnicastMessageSplitter {
    const NAME: &str = "UnicastMessageSplitter";
    const REPEAT: usize = constants::UNICAST_UDP_REPEAT;

    type Message = (SocketAddr, Box<[u8]>);

    fn split_message(&self, message: Self::Message) -> (SocketAddr, Box<[u8]>) {
        (message.0, message.1)
    }
}

struct MessageSender<T: MessageSplitter> {
    handler: JoinHandle<()>,
    tx: Sender<T::Message>,
}

async fn repeatedly_send_buffer<T: MessageSplitter>(
    socket: Arc<UdpSocket>,
    buffer: Box<[u8]>,
    to: SocketAddr,
) {
    // Schedule to send the given message to the given address.
    // Implements SOAP over UDP, Appendix I.
    let mut delta = rand::rng().random_range(constants::UDP_MIN_DELAY..=constants::UDP_MAX_DELAY);

    for i in 0..T::REPEAT {
        if i != 0 {
            sleep(Duration::from_millis(delta)).await;
            delta = constants::UDP_UPPER_DELAY.min(delta * 2);
        }

        match socket.send_to(buffer.as_ref(), to).await {
            Ok(_) => {},
            Err(error) => {
                event!(Level::WARN, ?error, "Failed to send data");
            },
        }
    }
}

impl<T> MessageSender<T>
where
    T: MessageSplitter + Send + 'static,
{
    fn new(socket: Arc<UdpSocket>, message_splitter: T) -> Self {
        let (tx, mut rx) = tokio::sync::mpsc::channel::<T::Message>(10);

        let handler = spawn_with_name("sender", async move {
            let tracker = TaskTracker::new();

            loop {
                let Some(buffer) = rx.recv().await else {
                    event!(
                        Level::INFO,
                        socket = %socket
                            .local_addr()
                            .map(|l| l.to_string())
                            .unwrap_or_default(),
                        splitter = %T::NAME,
                        "All senders gone, stopping sender"
                    );
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

        Self { handler, tx }
    }

    fn get_tx(&mut self) -> Sender<T::Message> {
        self.tx.clone()
    }

    async fn teardown(self) {
        // all senders need to be dropped to ensure the handler can shutdown properly
        drop(self.tx);

        // we're explicitly not forcefully cancelling our own handler
        // to allow everybody to send their messages and shut down gracefully before we shut down
        let _r = self.handler.await;
    }
}
