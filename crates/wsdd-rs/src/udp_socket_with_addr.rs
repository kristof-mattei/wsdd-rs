/// A `tokio::net::UdpSocket` paired with its local address.
pub struct UdpSocketWithAddr {
    socket: tokio::net::UdpSocket,
    local: std::net::SocketAddr,
}

impl UdpSocketWithAddr {
    pub fn new(socket: tokio::net::UdpSocket) -> Result<Self, std::io::Error> {
        let local = socket.local_addr()?;

        Ok(Self { socket, local })
    }

    /// Returns a cached version of the local address, avoiding `getsockname` syscalls when going through `socket().local_addr()`.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.local
    }

    /// Returns the underlying socket.
    pub fn socket(&self) -> &tokio::net::UdpSocket {
        &self.socket
    }
}
