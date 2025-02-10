use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
    os::fd::AsRawFd,
    rc::Rc,
};
use std::{io::Error, sync::Arc};

use libc::{
    ip_mreqn, socklen_t, IPPROTO_IP, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, IPV6_MULTICAST_IF,
    IPV6_MULTICAST_LOOP, IPV6_V6ONLY, IP_ADD_MEMBERSHIP, IP_MULTICAST_LOOP, IP_MULTICAST_TTL,
    SOL_SOCKET, SO_REUSEADDR,
};
use socket2::{Domain, Socket, Type};
use tracing::{event, Level};

use crate::{
    config::Config,
    constants::{self, WSD_HTTP_PORT, WSD_MCAST_GRP_V4, WSD_MCAST_GRP_V6, WSD_UDP_PORT},
    network_address::NetworkAddress,
    network_interface::NetworkInterface,
    network_packet_handler::NetworkPacketHandler,
    udp_address::UdpAddress,
};

// class MulticastHandler:
pub struct MulticastHandler<'s> {
    //     """
    //     A class for handling multicast traffic on a given interface for a
    //     given address family. It provides multicast sender and receiver sockets
    //     """

    //     # base interface addressing information
    //     address: NetworkAddress
    address: NetworkAddress,

    //     # individual interface-bound sockets for:
    //     #  - receiving multicast traffic
    //     #  - sending multicast from a socket bound to WSD port
    //     #  - sending unicast messages from a random port
    //     recv_socket: socket.socket
    //     mc_send_socket: socket.socket
    //     uc_send_socket: socket.socket
    recv_socket: UdpSocket,
    mc_send_socket: UdpSocket,
    uc_send_socket: UdpSocket,

    //     # addresses used for communication and data
    //     multicast_address: UdpAddress
    multicast_address: UdpAddress,
    //     listen_address: Tuple
    listen_address: SocketAddr,

    //     aio_loop: asyncio.AbstractEventLoop
    aio_loop: (),

    //     # dictionary that holds INetworkPacketHandlers instances for sockets created above
    //     message_handlers: Dict[socket.socket, List[INetworkPacketHandler]]
    message_handlers: HashMap<Rc<UdpSocket>, Vec<&'s dyn NetworkPacketHandler>>,
}

impl<'s> MulticastHandler<'s> {
    //     def __init__(self, address: NetworkAddress, aio_loop: asyncio.AbstractEventLoop) -> None:
    pub fn new(address: NetworkAddress, aio_loop: (), config: Arc<Config>) -> Self {
        // self.address = address

        // self.recv_socket = socket.socket(self.address.family, socket.SOCK_DGRAM)
        let domain = if address.address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        let recv_socket = Socket::new(domain, Type::DGRAM, None).unwrap();

        // self.recv_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        {
            let value: libc::c_int = 1;

            #[expect(clippy::cast_possible_truncation)]
            unsafe {
                libc::setsockopt(
                    recv_socket.as_raw_fd(),
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    std::ptr::addr_of!(value).cast::<libc::c_void>(),
                    size_of_val(&value) as libc::socklen_t,
                )
            };
        }

        // self.mc_send_socket = socket.socket(self.address.family, socket.SOCK_DGRAM)
        let mc_send_socket = Socket::new(domain, Type::DGRAM, None).unwrap();

        // self.uc_send_socket = socket.socket(self.address.family, socket.SOCK_DGRAM)
        let uc_send_socket = Socket::new(domain, Type::DGRAM, None).unwrap();

        // self.uc_send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        {
            let value: libc::c_int = 1;

            #[expect(clippy::cast_possible_truncation)]
            unsafe {
                libc::setsockopt(
                    uc_send_socket.as_raw_fd(),
                    SOL_SOCKET,
                    SO_REUSEADDR,
                    std::ptr::addr_of!(value).cast::<libc::c_void>(),
                    size_of_val(&value) as libc::socklen_t,
                )
            };
        }

        //         self.message_handlers = {}
        let message_handlers = HashMap::new();

        //         self.aio_loop = aio_loop
        let aio_loop = aio_loop;

        //         if self.address.family == socket.AF_INET:
        //             self.init_v4()
        //         elif self.address.family == socket.AF_INET6:
        //             self.init_v6()

        let (multicast_address, listen_address) = match address.address {
            IpAddr::V4(ipv4_address) => {
                let (multicast_address, listen_address) = MulticastHandler::init_v4(
                    &ipv4_address,
                    &address.interface,
                    &recv_socket,
                    &uc_send_socket,
                    &mc_send_socket,
                    config,
                );

                (multicast_address, SocketAddr::V4(listen_address))
            },
            IpAddr::V6(ipv6_address) => {
                let (multicast_address, listen_address) = MulticastHandler::init_v6(
                    &ipv6_address,
                    &address.interface,
                    &recv_socket,
                    &uc_send_socket,
                    &mc_send_socket,
                    config,
                );

                (multicast_address, SocketAddr::V6(listen_address))
            },
        };

        //         logger.info('joined multicast group {0} on {1}'.format(self.multicast_address.transport_str, self.address))
        //         logger.debug('transport address on {0} is {1}'.format(self.address.interface.name, self.address.transport_str))
        //         logger.debug('will listen for HTTP traffic on address {0}'.format(self.listen_address))

        event!(
            Level::INFO,
            "joined multicast group {} on {}",
            multicast_address,
            address
        );
        event!(
            Level::DEBUG,
            "transport address on {} is {}",
            address.interface.name,
            address
        );
        event!(
            Level::DEBUG,
            "will listen for HTTP traffic on address {}",
            listen_address
        );

        //         # register calbacks for incoming data (also for mc)
        //         self.aio_loop.add_reader(self.recv_socket.fileno(), self.read_socket, self.recv_socket)
        //         self.aio_loop.add_reader(self.mc_send_socket.fileno(), self.read_socket, self.mc_send_socket)
        //         self.aio_loop.add_reader(self.uc_send_socket.fileno(), self.read_socket, self.uc_send_socket)

        Self {
            address,
            recv_socket: recv_socket.into(),
            uc_send_socket: uc_send_socket.into(),
            mc_send_socket: mc_send_socket.into(),
            multicast_address,
            listen_address,
            aio_loop,
            message_handlers,
        }
    }

    //     def cleanup(self) -> None:
    pub fn cleanup(&mut self) {
        //         self.aio_loop.remove_reader(self.recv_socket)
        //         self.aio_loop.remove_reader(self.mc_send_socket)
        //         self.aio_loop.remove_reader(self.uc_send_socket)

        //         self.recv_socket.close()
        //         self.mc_send_socket.close()
        //         self.uc_send_socket.close()
    }

    //     def handles_address(self, address: NetworkAddress) -> bool:
    pub fn handles_address(&self, address: &NetworkAddress) -> bool {
        //         return self.address == address
        &self.address == address
    }

    //     def init_v6(self) -> None:
    #[expect(clippy::too_many_lines)]
    fn init_v6(
        ipv6_address: &Ipv6Addr,
        interface: &NetworkInterface,
        recv_socket: &Socket,
        uc_send_socket: &Socket,
        mc_send_socket: &Socket,
        config: Arc<Config>,
    ) -> (UdpAddress, SocketAddrV6) {
        let idx = interface.index;

        let raw_mc_addr = SocketAddrV6::new(
            constants::WSD_MCAST_GRP_V6,
            constants::WSD_UDP_PORT.into(),
            0x575Cu32,
            idx,
        );

        // self.multicast_address = UdpAddress(self.address.family, raw_mc_addr, self.address.interface)
        let multicast_address = UdpAddress::new(SocketAddr::V6(raw_mc_addr), interface.clone());

        // v6: member_request = { multicast_addr, intf_idx }
        // mreq = (socket.inet_pton(self.address.family, WSD_MCAST_GRP_V6) + struct.pack('@I', idx))
        // self.recv_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        recv_socket.join_multicast_v6(&constants::WSD_MCAST_GRP_V6, idx);

        // self.recv_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        {
            let value: libc::c_int = 1;

            #[expect(clippy::cast_possible_truncation)]
            unsafe {
                libc::setsockopt(
                    recv_socket.as_raw_fd(),
                    IPPROTO_IPV6,
                    IPV6_V6ONLY,
                    std::ptr::addr_of!(value).cast::<libc::c_void>(),
                    size_of_val(&value) as libc::socklen_t,
                )
            };
        }

        #[cfg(target_os = "linux")]
        {
            // Could anyone ask the Linux folks for the rationale for this!?
            // if platform.system() == 'Linux':
            //     try:
            //         # supported starting from Linux 4.20
            //         IPV6_MULTICAST_ALL = 29
            //         self.recv_socket.setsockopt(socket.IPPROTO_IPV6, IPV6_MULTICAST_ALL, 0)
            let value: libc::c_int = 0;

            const IPV6_MULTICAST_ALL: i32 = 29;

            #[expect(clippy::cast_possible_truncation)]
            let result = unsafe {
                libc::setsockopt(
                    recv_socket.as_raw_fd(),
                    IPPROTO_IPV6,
                    IPV6_MULTICAST_ALL,
                    std::ptr::addr_of!(value).cast::<libc::c_void>(),
                    size_of_val(&value) as libc::socklen_t,
                )
            };

            // except OSError as e:
            //  logger.warning('cannot unset all_multicast: {}'.format(e))
            if result != 0 {
                event!(
                    Level::WARN,
                    "cannot unset all_multicast: {}",
                    Error::last_os_error()
                );
            }
        }

        // bind to network interface, i.e. scope and handle OS differences,
        // see Stevens: Unix Network Programming, Section 21.6, last paragraph
        // try:
        //   self.recv_socket.bind((WSD_MCAST_GRP_V6, WSD_UDP_PORT, 0, idx))
        let socket_addr = SocketAddrV6::new(WSD_MCAST_GRP_V6, WSD_UDP_PORT.into(), 0, idx);
        if let Err(e) = recv_socket.bind(&socket_addr.into()) {
            event!(Level::WARN, "Failed to bind to {}: {}", socket_addr, e);
            // except OSError:
            //   self.recv_socket.bind(('::', 0, 0, idx))
            let socket_addr = SocketAddrV6::new(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 0, 0, idx);
            if let Err(e) = recv_socket.bind(&socket_addr.into()) {
                event!(
                    Level::ERROR,
                    "Fallback also failed to bind to {}: {}",
                    socket_addr,
                    e
                );
            }
        }

        // bind unicast socket to interface address and WSD's udp port
        // self.uc_send_socket.bind((str(self.address), WSD_UDP_PORT, 0, idx))
        uc_send_socket
            .bind(&SocketAddrV6::new(*ipv6_address, WSD_UDP_PORT.into(), 0, idx).into())
            .unwrap();

        // self.mc_send_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 0)
        {
            let value: libc::c_int = 0;

            #[expect(clippy::cast_possible_truncation)]
            unsafe {
                libc::setsockopt(
                    mc_send_socket.as_raw_fd(),
                    IPPROTO_IPV6,
                    IPV6_MULTICAST_LOOP,
                    std::ptr::addr_of!(value).cast::<libc::c_void>(),
                    size_of_val(&value) as libc::socklen_t,
                )
            };
        }

        // self.mc_send_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, args.hoplimit)
        {
            let value: u8 = config.hoplimit;

            #[expect(clippy::cast_possible_truncation)]
            unsafe {
                libc::setsockopt(
                    mc_send_socket.as_raw_fd(),
                    IPPROTO_IPV6,
                    IPV6_MULTICAST_HOPS,
                    std::ptr::addr_of!(value).cast::<libc::c_void>(),
                    size_of_val(&value) as libc::socklen_t,
                )
            };
        }

        // self.mc_send_socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, idx)
        {
            let value: libc::c_int = idx.try_into().unwrap();

            #[expect(clippy::cast_possible_truncation)]
            unsafe {
                libc::setsockopt(
                    mc_send_socket.as_raw_fd(),
                    IPPROTO_IPV6,
                    IPV6_MULTICAST_IF,
                    std::ptr::addr_of!(value).cast::<libc::c_void>(),
                    size_of_val(&value) as libc::socklen_t,
                )
            };
        }

        let listen_address = SocketAddrV6::new(*ipv6_address, WSD_HTTP_PORT.into(), 0, idx);

        (multicast_address, listen_address)
    }

    //     def init_v4(self) -> None:
    fn init_v4(
        ipv4_address: &Ipv4Addr,
        interface: &NetworkInterface,
        recv_socket: &Socket,
        uc_send_socket: &Socket,
        mc_send_socket: &Socket,
        config: Arc<Config>,
    ) -> (UdpAddress, SocketAddrV4) {
        // idx = self.address.interface.index
        let idx = interface.index;

        // raw_mc_addr = (WSD_MCAST_GRP_V4, WSD_UDP_PORT)
        let raw_mc_addr = SocketAddrV4::new(WSD_MCAST_GRP_V4, WSD_UDP_PORT.into());
        // self.multicast_address = UdpAddress(self.address.family, raw_mc_addr, self.address.interface)
        let multicast_address = UdpAddress::new(SocketAddr::V4(raw_mc_addr), interface.clone());

        // # v4: member_request (ip_mreqn) = { multicast_addr, intf_addr, idx }
        // mreq = (socket.inet_pton(self.address.family, WSD_MCAST_GRP_V4) + self.address.raw + struct.pack('@I', idx))
        let mpreq = ip_mreqn {
            imr_address: libc::in_addr {
                s_addr: WSD_MCAST_GRP_V4.to_bits(),
            },
            imr_multiaddr: libc::in_addr {
                s_addr: ipv4_address.to_bits(),
            },
            imr_ifindex: idx as i32,
        };

        // self.recv_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
        #[expect(clippy::cast_possible_truncation)]
        unsafe {
            libc::setsockopt(
                recv_socket.as_raw_fd(),
                IPPROTO_IP,
                IP_ADD_MEMBERSHIP,
                std::ptr::addr_of!(mpreq).cast::<libc::c_void>(),
                size_of_val(&mpreq) as libc::socklen_t,
            )
        };

        #[cfg(target_os = "linux")]
        {
            // if platform.system() == 'Linux':
            //     IP_MULTICAST_ALL = 49
            //     self.recv_socket.setsockopt(socket.IPPROTO_IP, IP_MULTICAST_ALL, 0)
            let value: libc::c_int = 0;

            const IP_MULTICAST_ALL: i32 = 49;

            #[expect(clippy::cast_possible_truncation)]
            let result = unsafe {
                libc::setsockopt(
                    recv_socket.as_raw_fd(),
                    IPPROTO_IP,
                    IP_MULTICAST_ALL,
                    std::ptr::addr_of!(value).cast::<libc::c_void>(),
                    size_of_val(&value) as libc::socklen_t,
                )
            };

            // except OSError as e:
            //  logger.warning('cannot unset all_multicast: {}'.format(e))
            if result != 0 {
                event!(
                    Level::WARN,
                    "cannot unset all_multicast: {}",
                    Error::last_os_error()
                );
            }
        }

        // try:
        //     self.recv_socket.bind((WSD_MCAST_GRP_V4, WSD_UDP_PORT))
        let socket_addr = SocketAddrV4::new(WSD_MCAST_GRP_V4, WSD_UDP_PORT.into());

        if let Err(e) = recv_socket.bind(&socket_addr.into()) {
            event!(Level::WARN, "Failed to bind to {}: {}", socket_addr, e);
            // except OSError:
            //     self.recv_socket.bind(('', WSD_UDP_PORT))
            let socket_addr = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), WSD_UDP_PORT.into());
            if let Err(e) = recv_socket.bind(&socket_addr.into()) {
                event!(
                    Level::ERROR,
                    "Fallback also failed to bind to {}: {}",
                    socket_addr,
                    e
                );
            }
        }

        // # bind unicast socket to interface address and WSD's udp port
        // self.uc_send_socket.bind((self.address.address_str, WSD_UDP_PORT))
        uc_send_socket
            .bind(&SocketAddrV4::new(*ipv4_address, WSD_UDP_PORT.into()).into())
            .unwrap();

        // self.mc_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, mreq)
        // # OpenBSD requires the optlen to be sizeof(char) for LOOP and TTL options
        // # (see also https://github.com/python/cpython/issues/67316)
        // self.mc_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, struct.pack('B', 0))
        {
            let value: u8 = 0;

            #[expect(clippy::cast_possible_truncation)]
            unsafe {
                libc::setsockopt(
                    mc_send_socket.as_raw_fd(),
                    IPPROTO_IP,
                    IP_MULTICAST_LOOP,
                    std::ptr::addr_of!(value).cast::<libc::c_void>(),
                    size_of_val(&value) as socklen_t,
                )
            };
        }
        // self.mc_send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack('B', args.hoplimit))
        {
            let value: u8 = config.hoplimit;

            #[expect(clippy::cast_possible_truncation)]
            unsafe {
                libc::setsockopt(
                    mc_send_socket.as_raw_fd(),
                    IPPROTO_IP,
                    IP_MULTICAST_TTL,
                    std::ptr::addr_of!(value).cast::<libc::c_void>(),
                    size_of_val(&value) as socklen_t,
                )
            };
        }

        let listen_address = SocketAddrV4::new(*ipv4_address, WSD_HTTP_PORT.into());

        (multicast_address, listen_address)
    }

    //     def add_handler(self, socket: socket.socket, handler: INetworkPacketHandler) -> None:
    fn add_handler(self, socket: Rc<UdpSocket>, handler: &dyn NetworkPacketHandler) {
        //         # try:
        //         #    self.selector.register(socket, selectors.EVENT_READ, self)
        //         # except KeyError:
        //         #    # accept attempts of multiple registrations
        //         #    pass

        // if self.message_handlers.get(&socket) {

        // }

        //         if socket in self.message_handlers:
        //             self.message_handlers[socket].append(handler)
        //         else:
        //             self.message_handlers[socket] = [handler]
    }

    //     def remove_handler(self, socket: socket.socket, handler) -> None:
    fn remove_handler(&mut self, socket: &UdpSocket, handler: &dyn NetworkPacketHandler) {
        //         if socket in self.message_handlers:
        //             if handler in self.message_handlers[socket]:
        //                 self.message_handlers[socket].remove(handler)
    }

    //     def read_socket(self, key: socket.socket) -> None:
    fn read_socket(&self, key: UdpSocket) {
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
    fn send(&self, message: &[u8], address: &UdpAddress) -> Result<(), color_eyre::Report> {
        // Request from a client must be answered from a socket that is bound
        // to the WSD port, i.e. the recv_socket. Messages to multicast
        // addresses are sent over the dedicated send socket.
        //         if addr == self.multicast_address:
        if address == &self.multicast_address {
            // self.mc_send_socket.sendto(msg, addr.transport_address)
            self.mc_send_socket
                .send_to(message, address.transport_address)?;
        } else {
            // else:
            // self.uc_send_socket.sendto(msg, addr.transport_address)
            self.uc_send_socket
                .send_to(message, address.transport_address)?;
        }

        Ok(())
    }
}
