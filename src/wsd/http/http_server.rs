use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::{config::Config, network_address::NetworkAddress};

#[expect(unused)]
pub struct WSDHttpServer {
    address: NetworkAddress,
    cancellation_token: CancellationToken,
    config: Arc<Config>,
}

impl WSDHttpServer {
    pub(crate) fn init(
        address: NetworkAddress,
        cancellation_token: CancellationToken,
        config: Arc<Config>,
    ) -> WSDHttpServer {
        Self {
            address,
            cancellation_token,
            config,
        }
    }
}

// class WSDHttpServer(http.server.HTTPServer):
//     """ HTTP server both with IPv6 support and WSD handling """

//     mch: MulticastHandler
//     aio_loop: asyncio.AbstractEventLoop
//     wsd_handler: WSDHttpMessageHandler
//     registered: bool

//     def __init__(self, mch: MulticastHandler, aio_loop: asyncio.AbstractEventLoop):
//         # hacky way to convince HTTP/SocketServer of the address family
//         type(self).address_family = mch.address.family

//         self.mch = mch
//         self.aio_loop = aio_loop
//         self.wsd_handler = WSDHttpMessageHandler()
//         self.registered = False

//         # WSDHttpRequestHandler is a BaseHTTPRequestHandler. Passing to the parent constructor is therefore safe and
//         # we can ignore the type error reported by mypy
//         super().__init__(mch.listen_address, WSDHttpRequestHandler)  # type: ignore

//     def server_bind(self) -> None:
//         if self.mch.address.family == socket.AF_INET6:
//             self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)

//         super().server_bind()

//     def server_activate(self) -> None:
//         super().server_activate()
//         self.aio_loop.add_reader(self.fileno(), self.handle_request)
//         self.registered = True

//     def server_close(self) -> None:
//         if self.registered:
//             self.aio_loop.remove_reader(self.fileno())
//         super().server_close()
