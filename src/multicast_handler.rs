use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use color_eyre::{Section, eyre};
use rand::Rng;
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
use crate::constants::{
    self, MULTICAST_UDP_REPEAT, UDP_MAX_DELAY, UDP_MIN_DELAY, UDP_UPPER_DELAY, UNICAST_UDP_REPEAT,
    WSD_HTTP_PORT, WSD_MAX_LEN, WSD_MCAST_GRP_V4, WSD_MCAST_GRP_V6, WSD_UDP_PORT,
};
use crate::network_address::NetworkAddress;
use crate::network_interface::NetworkInterface;
use crate::udp_address::UdpAddress;
use crate::url_ip_addr::UrlIpAddr;
use crate::utils::task::spawn_with_name;
use crate::wsd::http::http_server::WSDHttpServer;
use crate::wsd::udp::client::WSDClient;
use crate::wsd::udp::host::WSDHost;

/// A class for handling multicast traffic on a given interface for a
/// given address family. It provides multicast sender and receiver sockets
pub struct MulticastHandler {
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    /// The address and interface we're bound on
    address: NetworkAddress,

    /// The multicast group on which we broadcast our messages
    #[expect(unused)]
    multicast_address: UdpAddress,
    #[expect(unused)]
    http_listen_address: SocketAddr,
    wsd_host: OnceCell<WSDHost>,
    wsd_client: OnceCell<WSDClient>,
    #[expect(unused)]
    http_server: OnceCell<WSDHttpServer>,
    /// receiving multicast traffic on the WSD Port
    recv_socket_receiver: MessageReceiver,
    /// sending multicast from a socket bound to random / user provided port
    mc_socket_sender: MessageSender<MulticastMessageSplitter>,
    /// receiving unicast traffic on the random / user provided port
    #[expect(unused)]
    mc_socket_receiver: MessageReceiver,
    /// sending unicast messages from the WSD Port
    uc_socket_sender: MessageSender<UnicastMessageSplitter>,
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
        let recv_socket = Socket::new(domain, Type::DGRAM, None)?;
        recv_socket.set_nonblocking(true)?;
        recv_socket.set_reuse_address(true)?;

        // TODO error
        let mc_send_socket = Socket::new(domain, Type::DGRAM, None)?;
        mc_send_socket.set_nonblocking(true)?;

        // TODO error
        let uc_send_socket = Socket::new(domain, Type::DGRAM, None)?;
        uc_send_socket.set_nonblocking(true)?;
        uc_send_socket.set_reuse_address(true)?;

        let (multicast_address, http_listen_address) = match address.address {
            IpAddr::V4(ipv4_address) => {
                let (multicast_address, listen_address) = MulticastHandler::init_v4(
                    ipv4_address,
                    &address.interface,
                    &recv_socket,
                    &mc_send_socket,
                    &uc_send_socket,
                    config,
                )?;

                (multicast_address, SocketAddr::V4(listen_address))
            },
            IpAddr::V6(ipv6_address) => {
                let (multicast_address, listen_address) = MulticastHandler::init_v6(
                    ipv6_address,
                    &address.interface,
                    &recv_socket,
                    &mc_send_socket,
                    &uc_send_socket,
                    config,
                )?;

                (multicast_address, SocketAddr::V6(listen_address))
            },
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

        let recv_socket = Arc::new(UdpSocket::from_std(recv_socket.into())?);
        let recv_socket_receiver = MessageReceiver::new(Arc::clone(&recv_socket));

        let mc_send_socket = Arc::new(UdpSocket::from_std(mc_send_socket.into())?);
        let mc_socket_sender = MessageSender::new(
            Arc::clone(&mc_send_socket),
            MulticastMessageSplitter {
                target: multicast_address.transport_address,
            },
        );
        let mc_socket_receiver = MessageReceiver::new(Arc::clone(&mc_send_socket));

        let uc_send_socket = Arc::new(UdpSocket::from_std(uc_send_socket.into())?);
        let uc_socket_sender =
            MessageSender::new(Arc::clone(&uc_send_socket), UnicastMessageSplitter {});

        Ok(Self {
            config: Arc::clone(config),
            cancellation_token,
            address,
            multicast_address,
            http_listen_address,
            wsd_client: OnceCell::new(),
            wsd_host: OnceCell::new(),
            http_server: OnceCell::new(),
            recv_socket_receiver,
            mc_socket_sender,
            mc_socket_receiver,
            uc_socket_sender,
        })
    }

    pub async fn teardown(self, graceful: bool) {
        if let Some(host) = self.wsd_host.into_inner() {
            host.teardown(graceful).await;

            // graceful teardown makes the host queue up a goodbye, so when we're here we have made an honest try to schedule the goodbye message

            // host is dropped
        }

        // TODO drop client

        // TODO drop http

        if graceful {
            // we drop the sender first, which makes the handle go into cleanup mode, and gracefully try to send the lsat messages to the sockets

            // we have to rely on dropping the sender because that is the only way we can have the receiver run to completion
            // a cancellation token and tokio::select might cause the handle to top before parsing the rest of the messages
            let sender = self.mc_socket_sender;
            sender.teardown().await;

            let sender = self.uc_socket_sender;
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
        interface: &Arc<NetworkInterface>,
        recv_socket: &Socket,
        mc_send_socket: &Socket,
        uc_send_socket: &Socket,
        config: &Arc<Config>,
    ) -> Result<(UdpAddress, SocketAddrV6), eyre::Report> {
        let idx = interface.index;

        let multicast_address = UdpAddress::new(
            SocketAddrV6::new(
                constants::WSD_MCAST_GRP_V6,
                constants::WSD_UDP_PORT.into(),
                0x575Cu32,
                idx,
            )
            .into(),
            interface,
        );

        // TODO handle error
        recv_socket
            .join_multicast_v6(&constants::WSD_MCAST_GRP_V6, idx)
            .unwrap();

        // TODO error
        recv_socket.set_only_v6(true).unwrap();

        // TODO error
        // https://github.com/torvalds/linux/commit/15033f0457dca569b284bef0c8d3ad55fb37eacb
        if let Err(err) = recv_socket.set_multicast_all_v6(false) {
            event!(Level::WARN, ?err, "cannot unset IPV6_MULTICAST_ALL");
        }

        // bind to network interface, i.e. scope and handle OS differences,
        // see Stevens: Unix Network Programming, Section 21.6, last paragraph
        let socket_addr = SocketAddrV6::new(WSD_MCAST_GRP_V6, WSD_UDP_PORT.into(), 0, idx);

        if let Err(err) = recv_socket.bind(&socket_addr.into()) {
            event!(Level::WARN, "Failed to bind to {}: {}", socket_addr, err);

            let socket_addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, idx);

            if let Err(err) = recv_socket.bind(&socket_addr.into()) {
                event!(
                    Level::ERROR,
                    "Fallback also failed to bind to {}: {}",
                    socket_addr,
                    err
                );

                return Err(eyre::Report::msg(format!(
                    "Fallback also failed to bind to {}",
                    socket_addr
                )));
            }
        }

        // bind unicast socket to interface address and WSD's udp port
        uc_send_socket
            .bind(&SocketAddrV6::new(ipv6_address, WSD_UDP_PORT.into(), 0, idx).into())?;

        // TODO error
        mc_send_socket.set_multicast_loop_v6(false)?;

        // TODO error
        mc_send_socket.set_multicast_hops_v6(config.hoplimit.into())?;

        // TODO error
        mc_send_socket.set_multicast_if_v6(idx).unwrap();

        // TODO error
        mc_send_socket
            .bind(&(SocketAddrV6::new(ipv6_address, config.source_port, 0, idx)).into())?;

        let listen_address = SocketAddrV6::new(ipv6_address, WSD_HTTP_PORT.into(), 0, idx);

        Ok((multicast_address, listen_address))
    }

    fn init_v4(
        ipv4_address: Ipv4Addr,
        interface: &Arc<NetworkInterface>,
        recv_socket: &Socket,
        mc_send_socket: &Socket,
        uc_send_socket: &Socket,
        config: &Arc<Config>,
    ) -> Result<(UdpAddress, SocketAddrV4), eyre::Report> {
        let idx = interface.index;

        let multicast_address = UdpAddress::new(
            SocketAddrV4::new(WSD_MCAST_GRP_V4, WSD_UDP_PORT.into()).into(),
            interface,
        );

        if let Err(err) =
            recv_socket.join_multicast_v4_n(&WSD_MCAST_GRP_V4, &InterfaceIndexOrAddress::Index(idx))
        {
            event!(Level::ERROR, ?err, multi_addr = ?WSD_MCAST_GRP_V4, ifindex = ?idx, "could not join multicast group");

            return Err(eyre::Report::msg("could not join multicast group"));
        };

        if let Err(err) = recv_socket.set_multicast_all_v4(false) {
            event!(Level::ERROR, ?err, "could not unset IP_MULTICAST_ALL");

            return Err(eyre::Report::msg("could not unset IP_MULTICAST_ALL"));
        };

        let socket_addr = SocketAddrV4::new(WSD_MCAST_GRP_V4, WSD_UDP_PORT.into());

        if let Err(err) = recv_socket.bind(&socket_addr.into()) {
            event!(Level::WARN, "Failed to bind to {}: {}", socket_addr, err);

            let socket_addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, WSD_UDP_PORT.into());

            if let Err(err) = recv_socket.bind(&socket_addr.into()) {
                event!(
                    Level::ERROR,
                    ?err,
                    "Fallback also failed to bind to {}",
                    socket_addr,
                );

                return Err(eyre::Report::msg(format!(
                    "Fallback also failed to bind to {}",
                    socket_addr
                )));
            }
        }

        // bind unicast socket to interface address and WSD's udp port
        uc_send_socket.bind(&SocketAddrV4::new(ipv4_address, WSD_UDP_PORT.into()).into())?;

        if let Err(err) = mc_send_socket.set_multicast_if_v4(&ipv4_address) {
            event!(
                Level::ERROR,
                ?err,
                "Failed to set IPPROTO_IP -> IP_MULTICAST_IF on socket"
            );

            return Err(eyre::Report::from(err)
                .with_note(|| "Failed to set IPPROTO_IP -> IP_MULTICAST_IF on socket"));
        }

        // # OpenBSD requires the optlen to be sizeof(char) for LOOP and TTL options
        // # (see also https://github.com/python/cpython/issues/67316)
        // TODO openBSD/freebsd case
        if let Err(err) = mc_send_socket.set_multicast_loop_v4(false) {
            event!(
                Level::ERROR,
                ?err,
                "Failed to set IPPROTO_IP -> IP_MULTICAST_LOOP on socket"
            );

            return Err(eyre::Report::from(err)
                .with_note(|| "Failed to set IPPROTO_IP -> IP_MULTICAST_LOOP on socket"));
        }

        if let Err(err) = mc_send_socket.set_multicast_ttl_v4(config.hoplimit.into()) {
            event!(
                Level::ERROR,
                ?err,
                "Failed to set IPPROTO_IP -> IP_MULTICAST_TTL on socket"
            );

            return Err(eyre::Report::from(err)
                .with_note(|| "Failed to set IPPROTO_IP -> IP_MULTICAST_TTL on socket"));
        }

        // TODO error
        mc_send_socket.bind(&(SocketAddrV4::new(ipv4_address, config.source_port)).into())?;

        let listen_address = SocketAddrV4::new(ipv4_address, WSD_HTTP_PORT.into());

        Ok((multicast_address, listen_address))
    }

    pub async fn enable_wsd_host(&mut self) {
        self.wsd_host
            .get_or_init(|| async {
                // interests:
                // * recv_socket

                let host = WSDHost::init(
                    &self.cancellation_token,
                    Arc::clone(&self.config),
                    self.address.address,
                    self.recv_socket_receiver.get_listener().await,
                    self.mc_socket_sender.get_sender(),
                    self.uc_socket_sender.get_sender(),
                )
                .await;

                #[expect(clippy::let_and_return)]
                host
            })
            .await;
    }

    pub async fn enable_wsd_client(&mut self) {
        self.wsd_client
            .get_or_init(|| async {
                // interests:
                // * recv_socket
                // * mc_send_socket

                let client = WSDClient::init(
                    &self.cancellation_token,
                    Arc::clone(&self.config),
                    self.address.address,
                    self.recv_socket_receiver.get_listener().await,
                    self.mc_socket_sender.get_sender(),
                    self.uc_socket_sender.get_sender(),
                )
                .await;

                #[expect(clippy::let_and_return)]
                client
            })
            .await;
    }

    pub async fn enable_http_server(&self) {
        self.http_server
            .get_or_init(|| async {
                let server =
                    WSDHttpServer::init(self.cancellation_token.clone(), Arc::clone(&self.config))
                        .await;

                #[expect(clippy::let_and_return)]
                server
            })
            .await;
    }
}

type Receivers = Arc<RwLock<Vec<Sender<(SocketAddr, Arc<[u8]>)>>>>;

struct MessageReceiver {
    listeners: Receivers,
}

impl MessageReceiver {
    fn new(socket: Arc<UdpSocket>) -> Self {
        let listeners: Receivers = Receivers::new(RwLock::const_new(vec![]));

        {
            let socket = Arc::clone(&socket);
            let channels = Arc::clone(&listeners);

            spawn_with_name(
                format!("socket receiver ({})", socket.local_addr().unwrap()).as_str(),
                async move {
                    loop {
                        let mut buffer = vec![MaybeUninit::<u8>::uninit(); WSD_MAX_LEN];

                        let (bytes_read, from) = match socket
                            .recv_buf_from(&mut buffer.as_mut_slice())
                            .await
                        {
                            Ok(read) => read,
                            Err(err) => {
                                let local_addr = socket.local_addr().map_or_else(
                                    |err| format!("Failed to get local socket address: {:?}", err),
                                    |addr| addr.to_string(),
                                );

                                event!(
                                    Level::ERROR,
                                    ?err,
                                    local_addr,
                                    "Failed to read from socket"
                                );

                                continue;
                            },
                        };

                        // `recv_buf` tells us that `bytes_read` were read from the socket into our `buffer`, so they're initialized
                        buffer.shrink_to(bytes_read);

                        let buffer = Arc::<[_]>::from(buffer);

                        let buffer = unsafe { buffer.assume_init() };

                        let lock = channels.read().await;

                        for channel in &*lock {
                            if let Err(err) = channel.send((from, Arc::clone(&buffer))).await {
                                event!(Level::ERROR, ?err, socket = ?socket.local_addr().unwrap(), "Failed to send data to channel");
                            }
                        }
                    }
                },
            );
        }

        Self { listeners }
    }

    async fn get_listener(&mut self) -> Receiver<(SocketAddr, Arc<[u8]>)> {
        let (sender, receiver) = tokio::sync::mpsc::channel(10);

        self.listeners.write().await.push(sender);

        receiver
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

impl<T: MessageSplitter + Send + 'static> MessageSender<T> {
    fn new(socket: Arc<UdpSocket>, message_splitter: T) -> Self {
        let (sender, mut receiver) = tokio::sync::mpsc::channel::<T::Message>(10);

        let handler = spawn_with_name("sender", async move {
            let tracker = TaskTracker::new();

            loop {
                let Some(buffer) = receiver.recv().await else {
                    event!(Level::INFO, "All senders gone, shutting down");
                    break;
                };

                let (to, buffer) = message_splitter.split_message(buffer);

                let socket = socket.clone();

                spawn_with_name(
                    "message sender",
                    tracker.track_future(async move {
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
                                Err(err) => {
                                    event!(Level::WARN, ?err, "Failed to send data");
                                },
                            }
                        }
                    }),
                );
            }

            tracker.close();
            tracker.wait().await;
        });

        Self { handler, sender }
    }

    fn get_sender(&mut self) -> Sender<T::Message> {
        self.sender.clone()
    }

    async fn teardown(self) {
        drop(self.sender);

        let _r = self.handler.await;
    }
}
