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
use tokio::time::sleep;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::config::Config;
use crate::constants::{
    self, MULTICAST_UDP_REPEAT, UDP_MAX_DELAY, UDP_MIN_DELAY, UDP_UPPER_DELAY, WSD_HTTP_PORT,
    WSD_MAX_LEN, WSD_MCAST_GRP_V4, WSD_MCAST_GRP_V6, WSD_UDP_PORT,
};
use crate::network_address::NetworkAddress;
use crate::network_interface::NetworkInterface;
use crate::soap::builder::MessageType;
use crate::udp_address::UdpAddress;
use crate::url_ip_addr::UrlIpAddr;
use crate::utils::task::spawn_with_name;
use crate::wsd::http::http_server::WSDHttpServer;
use crate::wsd::udp::client::WSDClient;
use crate::wsd::udp::host::WSDHost;

/// A class for handling multicast traffic on a given interface for a
/// given address family. It provides multicast sender and receiver sockets
pub struct MulticastHandler {
    #[expect(unused)]
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    //     # base interface addressing information
    //     address: NetworkAddress
    /// The address and interface we're bound on
    address: NetworkAddress,

    //     # individual interface-bound sockets for:
    //     #  - receiving multicast traffic
    //     #  - sending multicast from a socket bound to WSD port
    //     #  - sending unicast messages from a random port
    //     recv_socket: socket.socket
    //     mc_send_socket: socket.socket
    //     uc_send_socket: socket.socket
    recv_socket_wrapper: SocketWithReceivers,
    mc_send_socket_wrapper: SocketWithReceivers,
    uc_send_socket_wrapper: SocketWithReceivers,

    //     # addresses used for communication and data
    //     multicast_address: UdpAddress
    /// The multicast group on which we broadcast our messages
    multicast_address: UdpAddress,
    //     listen_address: Tuple
    #[expect(unused)]
    http_listen_address: SocketAddr,

    //     # dictionary that holds INetworkPacketHandlers instances for sockets created above
    //     message_handlers: Dict[socket.socket, List[INetworkPacketHandler]]
    // message_handlers: HashMap<Arc<UdpSocket>, Vec<&'nph (dyn NetworkPacketHandler + Sync)>>,
    wsd_host: OnceCell<WSDHost>,
    wsd_client: OnceCell<WSDClient>,
    #[expect(unused)]
    http_server: OnceCell<WSDHttpServer>,
    unicast: Sender<(Box<[u8]>, SocketAddr)>,
    multicast: Sender<(MessageType, Box<[u8]>)>,
}

impl MulticastHandler {
    //     def __init__(self, address: NetworkAddress, aio_loop: asyncio.AbstractEventLoop) -> None:
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
                    &uc_send_socket,
                    &mc_send_socket,
                    config,
                )?;

                (multicast_address, SocketAddr::V4(listen_address))
            },
            IpAddr::V6(ipv6_address) => {
                let (multicast_address, listen_address) = MulticastHandler::init_v6(
                    ipv6_address,
                    &address.interface,
                    &recv_socket,
                    &uc_send_socket,
                    &mc_send_socket,
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

        // TODO
        //         # register calbacks for incoming data (also for mc)
        //         self.aio_loop.add_reader(self.recv_socket.fileno(), self.read_socket, self.recv_socket)
        //         self.aio_loop.add_reader(self.mc_send_socket.fileno(), self.read_socket, self.mc_send_socket)
        //         self.aio_loop.add_reader(self.uc_send_socket.fileno(), self.read_socket, self.uc_send_socket)

        let recv_socket_wrapper =
            SocketWithReceivers::new(UdpSocket::from_std(recv_socket.into())?);
        let uc_send_socket_wrapper =
            SocketWithReceivers::new(UdpSocket::from_std(uc_send_socket.into())?);
        let mc_send_socket_wrapper =
            SocketWithReceivers::new(UdpSocket::from_std(mc_send_socket.into())?);

        let multicast = {
            let socket = Arc::clone(&mc_send_socket_wrapper.socket);
            let address = multicast_address.network_address.address;
            let interface = multicast_address.network_address.interface.name.clone();
            let multicast_target = multicast_address.transport_address;

            let (sender, mut receiver) = tokio::sync::mpsc::channel::<(MessageType, Box<[u8]>)>(10);

            {
                // TODO handle error
                let name = format!("multicast handler ({})", multicast_target);
                spawn_with_name(name.as_str(), async move {
                    loop {
                        if let Some((message_type, buffer)) = receiver.recv().await {
                            // TODO this needs to be changed, we're not scheduling, we're sending
                            event!(
                                Level::INFO,
                                "scheduling {} message via {} to {}%{}",
                                message_type,
                                interface,
                                address,
                                interface,
                            );
                            {
                                let socket = socket.clone();

                                tokio::spawn(async move {
                                    // Schedule to send the given message to the given address.
                                    // Implements SOAP over UDP, Appendix I.

                                    let mut delta =
                                        rand::rng().random_range(UDP_MIN_DELAY..=UDP_MAX_DELAY);

                                    for i in 0..MULTICAST_UDP_REPEAT {
                                        if i != 0 {
                                            sleep(Duration::from_millis(delta)).await;
                                            delta = UDP_UPPER_DELAY.min(delta * 2);
                                        }

                                        match socket.send_to(&buffer, multicast_target).await {
                                            Ok(_) => {},
                                            Err(err) => {
                                                event!(
                                                    Level::WARN,
                                                    ?err,
                                                    target = ?multicast_target,
                                                    "Failed to send data"
                                                );
                                            },
                                        }
                                    }
                                });
                            }
                        } else {
                            // receiver gone? :(
                        }
                    }
                })
                .expect("Failed to launch task");
            }

            sender
        };

        let unicast = {
            let socket = Arc::clone(&uc_send_socket_wrapper.socket);

            let (sender, mut receiver) = tokio::sync::mpsc::channel::<(Box<[u8]>, SocketAddr)>(10);

            // TODO failure here is fatal
            let name = format!("unicast handler ({})", socket.local_addr().unwrap());
            spawn_with_name(name.as_str(), async move {
                loop {
                    if let Some((buf, target)) = receiver.recv().await {
                        match socket.send_to(&buf, target).await {
                            Ok(_) => {},
                            Err(err) => {
                                event!(Level::WARN, ?err, target = ?target, "Failed to send data");
                            },
                        }
                    } else {
                        // receiver gone? :(
                    }
                }
            })
            .expect("Failed to set up unicast handler");

            sender
        };

        Ok(Self {
            config: Arc::clone(config),
            cancellation_token,
            address,
            recv_socket_wrapper,
            uc_send_socket_wrapper,
            mc_send_socket_wrapper,
            multicast_address,
            http_listen_address,
            wsd_client: OnceCell::new(),
            wsd_host: OnceCell::new(),
            http_server: OnceCell::new(),
            multicast,
            unicast,
        })
    }

    //     def cleanup(self) -> None:
    pub fn cleanup(&mut self) {
        // Do not tear the client/hosts down. Saying goodbye does not work
        // because the address is already gone (at least on Linux).
        // TODO
        //     for c in WSDClient.instances:
        //         if c.mch == mch:
        //             c.cleanup()
        //             break
        //     for h in WSDHost.instances:
        //         if h.mch == mch:
        //             h.cleanup()
        //             break
        //     for s in self.http_servers:
        //         if s.mch == mch:
        //             s.server_close()
        //             self.http_servers.remove(s)

        // TODO
        //         self.aio_loop.remove_reader(self.recv_socket)
        //         self.aio_loop.remove_reader(self.mc_send_socket)
        //         self.aio_loop.remove_reader(self.uc_send_socket)

        //         self.recv_socket.close()
        //         self.mc_send_socket.close()
        //         self.uc_send_socket.close()
    }

    pub fn handles_address(&self, address: &NetworkAddress) -> bool {
        &self.address == address
    }

    fn init_v6(
        ipv6_address: Ipv6Addr,
        interface: &Arc<NetworkInterface>,
        recv_socket: &Socket,
        uc_send_socket: &Socket,
        mc_send_socket: &Socket,
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

        // v6: member_request = { multicast_addr, intf_idx }
        // mreq = (socket.inet_pton(self.address.family, WSD_MCAST_GRP_V6) + struct.pack('@I', idx))
        // self.recv_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        // TODO handle error
        recv_socket
            .join_multicast_v6(&constants::WSD_MCAST_GRP_V6, idx)
            .unwrap();

        // self.recv_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        // TODO error
        recv_socket.set_only_v6(true).unwrap();

        // Could anyone ask the Linux folks for the rationale for this!?
        // if platform.system() == 'Linux':
        //     try:
        //         # supported starting from Linux 4.20
        //         IPV6_MULTICAST_ALL = 29
        //         self.recv_socket.setsockopt(socket.IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)

        // TODO error
        if let Err(err) = recv_socket.set_multicast_all_v6(false) {
            // except OSError as e:
            //  logger.warning('cannot unset all_multicast: {}'.format(e))
            event!(Level::WARN, ?err, "cannot unset all_multicast");
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
        uc_send_socket: &Socket,
        mc_send_socket: &Socket,
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

        // # bind unicast socket to interface address and WSD's udp port
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

        // self.mc_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, struct.pack('B', 0))
        // self.mc_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('B', args.hoplimit))

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

    //     def read_socket(self, key: socket.socket) -> None:

    #[expect(unused)]
    fn read_socket(&self, _key: UdpSocket) {
        //         # TODO: refactor this
        //         s = None
        //         if key == self.uc_send_socket:
        //             s = self.uc_send_socket
        //         elif key == self.mc_send_socket:
        //             s = self.mc_send_socket
        //         elif key == self.recv_socket:
        //             s = self.recv_socket
        //         else:
        //             raise ValueError("Unknown socket passed as key.")

        //         msg, raw_address = s.recvfrom(WSD_MAX_LEN)
        //         address = UdpAddress(self.address.family, raw_address, self.address.interface)
        //         if s in self.message_handlers:
        //             for handler in self.message_handlers[s]:
        //                 handler.handle_packet(msg.decode('utf-8'), address)
    }

    //     def send(self, msg: bytes, addr: UdpAddress):
    #[expect(unused)]
    async fn send(&self, message: &[u8], address: &UdpAddress) -> Result<(), eyre::Report> {
        // Request from a client must be answered from a socket that is bound
        // to the WSD port, i.e. the recv_socket. Messages to multicast
        // addresses are sent over the dedicated send socket.
        //         if addr == self.multicast_address:
        // if address == &self.multicast_address {
        //     // self.mc_send_socket.sendto(msg, addr.transport_address)
        //     self.mc_send_socket
        //         .send_to(message, address.transport_address)?;
        // } else {
        //     // else:
        //     // self.uc_send_socket.sendto(msg, addr.transport_address)
        //     self.uc_send_socket
        //         .send_to(message, address.transport_address)?;
        // }

        if address == &self.multicast_address {
            self.mc_send_socket_wrapper
                .socket
                .send_to(message, address.transport_address)
                .await?;
        } else {
            self.uc_send_socket_wrapper
                .socket
                .send_to(message, address.transport_address)
                .await?;
        }

        Ok(())
    }

    pub(crate) async fn enable_wsd_host(&mut self) {
        self.wsd_host
            .get_or_init(|| async {
                // interests:
                // * recv_socket

                let host = WSDHost::new(
                    Arc::clone(&self.config),
                    self.address.address,
                    self.recv_socket_wrapper.get_channel().await,
                    self.unicast.clone(),
                    self.multicast.clone(),
                )
                .await;

                #[expect(clippy::let_and_return)]
                host
            })
            .await;
    }

    pub(crate) fn enable_http_server(&self) {
        // http_server = Some(WSDHttpServer::new(&multicast_handler));
    }

    pub(crate) async fn enable_wsd_client(&mut self) {
        self.wsd_client
            .get_or_init(|| async {
                // interests:
                // * recv_socket
                // * mc_send_socket

                // WSDClient::new(
                //     self.mc_send_socket_wrapper.get_channel().await,
                //     self.recv_socket_wrapper.get_channel().await,
                // )

                todo!()
            })
            .await;
    }
}

type Channels = Arc<RwLock<Vec<Sender<(Arc<[u8]>, SocketAddr)>>>>;

struct SocketWithReceivers {
    socket: Arc<UdpSocket>,
    channels: Channels,
}

impl SocketWithReceivers {
    fn new(socket: UdpSocket) -> Self {
        let socket = Arc::new(socket);

        let channels: Channels = Channels::new(RwLock::const_new(vec![]));

        {
            let socket = Arc::clone(&socket);
            let channels = Arc::clone(&channels);

            // TODO handle error
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
                            if let Err(err) = channel.send((Arc::clone(&buffer), from)).await {
                                event!(Level::ERROR, ?err, "Failed to send data to channel");
                            }
                        }
                    }
                },
            )
            .expect("Failed to launch receiver");
        }

        Self { socket, channels }
    }

    async fn get_channel(&mut self) -> Receiver<(Arc<[u8]>, SocketAddr)> {
        let (sender, receiver) = tokio::sync::mpsc::channel::<(Arc<_>, SocketAddr)>(10);

        self.channels.write().await.push(sender);

        receiver
    }
}
