use std::pin::Pin;

use pin_project::pin_project;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};

#[pin_project(project = GenericReadHalfProjection)]
pub enum GenericReadHalf {
    Tcp(#[pin] tokio::net::tcp::OwnedReadHalf),
    Unix(#[pin] tokio::net::unix::OwnedReadHalf),
}

impl AsyncRead for GenericReadHalf {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.project() {
            GenericReadHalfProjection::Tcp(pin) => pin.poll_read(cx, buf),
            GenericReadHalfProjection::Unix(pin) => pin.poll_read(cx, buf),
        }
    }
}

impl From<tokio::net::tcp::OwnedReadHalf> for GenericReadHalf {
    fn from(value: tokio::net::tcp::OwnedReadHalf) -> Self {
        GenericReadHalf::Tcp(value)
    }
}

impl From<tokio::net::unix::OwnedReadHalf> for GenericReadHalf {
    fn from(value: tokio::net::unix::OwnedReadHalf) -> Self {
        GenericReadHalf::Unix(value)
    }
}

#[pin_project(project = GenericWriteHalfProjection)]
pub enum GenericWriteHalf {
    Tcp(#[pin] tokio::net::tcp::OwnedWriteHalf),
    Unix(#[pin] tokio::net::unix::OwnedWriteHalf),
}

impl AsyncWrite for GenericWriteHalf {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.project() {
            GenericWriteHalfProjection::Tcp(pin) => pin.poll_write(cx, buf),
            GenericWriteHalfProjection::Unix(pin) => pin.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project() {
            GenericWriteHalfProjection::Tcp(pin) => pin.poll_flush(cx),
            GenericWriteHalfProjection::Unix(pin) => pin.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project() {
            GenericWriteHalfProjection::Tcp(pin) => pin.poll_shutdown(cx),
            GenericWriteHalfProjection::Unix(pin) => pin.poll_shutdown(cx),
        }
    }
}

impl From<tokio::net::tcp::OwnedWriteHalf> for GenericWriteHalf {
    fn from(value: tokio::net::tcp::OwnedWriteHalf) -> Self {
        GenericWriteHalf::Tcp(value)
    }
}

impl From<tokio::net::unix::OwnedWriteHalf> for GenericWriteHalf {
    fn from(value: tokio::net::unix::OwnedWriteHalf) -> Self {
        GenericWriteHalf::Unix(value)
    }
}

#[pin_project(project = GenericStreamProjection)]
pub enum GenericStream {
    Tcp {
        #[pin]
        tcp_stream: TcpStream,
        socket_addr: std::net::SocketAddr,
    },
    Unix {
        #[pin]
        unix_stream: UnixStream,
        socket_addr: tokio::net::unix::SocketAddr,
    },
}

impl GenericStream {
    pub fn into_split(self) -> (GenericReadHalf, GenericWriteHalf) {
        match self {
            GenericStream::Tcp {
                tcp_stream,
                socket_addr: _socket_addr,
            } => {
                let (reader, writer) = tcp_stream.into_split();

                (reader.into(), writer.into())
            },
            GenericStream::Unix {
                unix_stream,
                socket_addr: _socket_addr,
            } => {
                let (reader, writer) = unix_stream.into_split();

                (reader.into(), writer.into())
            },
        }
    }
}

impl AsyncWrite for GenericStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.project() {
            GenericStreamProjection::Tcp {
                tcp_stream,
                socket_addr: _socket_addr,
            } => tcp_stream.poll_write(cx, buf),
            GenericStreamProjection::Unix {
                unix_stream,
                socket_addr: _socket_addr,
            } => unix_stream.poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project() {
            GenericStreamProjection::Tcp {
                tcp_stream,
                socket_addr: _socket_addr,
            } => tcp_stream.poll_flush(cx),
            GenericStreamProjection::Unix {
                unix_stream,
                socket_addr: _socket_addr,
            } => unix_stream.poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.project() {
            GenericStreamProjection::Tcp {
                tcp_stream,
                socket_addr: _socket_addr,
            } => tcp_stream.poll_shutdown(cx),
            GenericStreamProjection::Unix {
                unix_stream,
                socket_addr: _socket_addr,
            } => unix_stream.poll_shutdown(cx),
        }
    }
}

impl From<(TcpStream, std::net::SocketAddr)> for GenericStream {
    fn from((tcp_stream, socket_addr): (TcpStream, std::net::SocketAddr)) -> Self {
        GenericStream::Tcp {
            tcp_stream,
            socket_addr,
        }
    }
}

impl From<(UnixStream, tokio::net::unix::SocketAddr)> for GenericStream {
    fn from((unix_stream, socket_addr): (UnixStream, tokio::net::unix::SocketAddr)) -> Self {
        GenericStream::Unix {
            unix_stream,
            socket_addr,
        }
    }
}

pub enum GenericListener {
    Tcp(TcpListener),
    Unix(UnixListener),
}

impl From<TcpListener> for GenericListener {
    fn from(value: TcpListener) -> Self {
        GenericListener::Tcp(value)
    }
}

impl From<UnixListener> for GenericListener {
    fn from(value: UnixListener) -> Self {
        GenericListener::Unix(value)
    }
}

impl GenericListener {
    pub async fn accept(&self) -> io::Result<GenericStream> {
        match *self {
            GenericListener::Tcp(ref tcp_listener) => tcp_listener.accept().await.map(Into::into),
            GenericListener::Unix(ref unix_listener) => {
                unix_listener.accept().await.map(Into::into)
            },
        }
    }
}
