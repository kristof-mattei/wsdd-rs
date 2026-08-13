mod generic;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::FromRawFd as _;
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre;
use socket2::{Domain, Type};
use time::format_description::well_known::Iso8601;
use time::format_description::well_known::iso8601::{Config as Iso8601Config, TimePrecision};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::mpsc::Sender;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::api_server::generic::{GenericListener, GenericStream};
use crate::config::PortOrSocket;
use crate::network_handler::Command;
use crate::wsd::device::{DeviceUri, WSDDiscoveredDevice};

const MAX_CONNECTION_BACKLOG: u32 = 100;
const MAX_CONCURRENT_CONNECTIONS: usize = 10;

/// `Iso8601`, like `2026-01-14T17:37:29Z`, rounded on seconds (ergo no milliseconds / nanoseconds).
const ISO8601_SECOND_PRECISION: Iso8601<
    {
        Iso8601Config::DEFAULT
            .set_time_precision(TimePrecision::Second {
                decimal_digits: None,
            })
            .encode()
    },
> = Iso8601;

pub struct ApiServer {
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
    listeners: (GenericListener, Option<GenericListener>),
}

impl ApiServer {
    pub fn new(
        cancellation_token: CancellationToken,
        listen_on: &PortOrSocket,
        command_tx: Sender<Command>,
    ) -> Result<ApiServer, std::io::Error> {
        let listeners: (GenericListener, Option<GenericListener>) = match *listen_on {
            PortOrSocket::Port(port) => {
                // one loopback socket per family, only wildcard binds can be dual-stack
                let v4 =
                    bind_tcp_loopback(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)));
                let v6 = bind_tcp_loopback(SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::LOCALHOST,
                    port,
                    0,
                    0,
                )));

                match (v4, v6) {
                    (Ok(v4), Ok(v6)) => (v4, Some(v6)),
                    (Ok(v4), Err(error)) => {
                        event!(
                            Level::WARN,
                            ?error,
                            "Failed to bind [::1], API server is IPv4-only"
                        );

                        (v4, None)
                    },
                    (Err(error), Ok(v6)) => {
                        event!(
                            Level::WARN,
                            ?error,
                            "Failed to bind 127.0.0.1, API server is IPv6-only"
                        );

                        (v6, None)
                    },
                    (Err(v4_error), Err(v6_error)) => {
                        event!(
                            Level::ERROR,
                            ?v4_error,
                            ?v6_error,
                            "Failed to bind either loopback"
                        );

                        return Err(v4_error);
                    },
                }
            },
            PortOrSocket::Socket(fd) => {
                // SAFETY: passed in by systemd, so it's a valid descriptor
                let socket = unsafe { socket2::Socket::from_raw_fd(fd) };

                match (socket.r#type(), socket.domain()) {
                    (Ok(Type::STREAM), Ok(Domain::UNIX)) => {
                        socket.set_nonblocking(true)?;

                        let socket = UnixListener::from_std(socket.into())?;

                        (socket.into(), None)
                    },
                    (r#type, domain) => {
                        event!(
                            Level::ERROR,
                            ?r#type,
                            ?domain,
                            "Received socket of invalid type and/or domain"
                        );

                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "Invalid socket is of invalid domain and/or type",
                        ));
                    },
                }
            },
            PortOrSocket::SocketPath(ref path) => {
                let socket = tokio::net::UnixSocket::new_stream()?;
                socket.bind(path)?;
                (socket.listen(MAX_CONNECTION_BACKLOG)?.into(), None)
            },
        };

        Ok(Self {
            cancellation_token,
            command_tx,
            listeners,
        })
    }

    pub async fn handle_connections(&self) -> Result<(), eyre::Report> {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

        loop {
            let new_connection = tokio::select! {
                () = self.cancellation_token.cancelled() => {
                    return Ok(());
                },
                new_connection = self.listeners.0.accept() => {
                    new_connection
                },
                new_connection = accept_secondary(self.listeners.1.as_ref()) => {
                    new_connection
                },
            };

            match new_connection {
                Ok(mut stream) => {
                    let Ok(permit) = Arc::clone(&semaphore).try_acquire_owned() else {
                        event!(
                            Level::ERROR,
                            "Failed to accept connection, no slots available"
                        );

                        tokio::task::spawn(async move {
                            match timeout(
                                Duration::from_secs(5),
                                stream.write_all("No slots available".as_bytes()),
                            )
                            .await
                            {
                                Ok(Ok(())) => {},
                                Ok(Err(error)) => {
                                    event!(Level::ERROR, ?error, "Failed to write to socket");
                                },
                                Err(error) => {
                                    event!(
                                        Level::ERROR,
                                        ?error,
                                        "Timeout occurred when writing to socket"
                                    );
                                },
                            }
                        });

                        continue;
                    };

                    let cancellation_token: CancellationToken =
                        self.cancellation_token.child_token();

                    let command_tx = self.command_tx.clone();

                    tokio::task::spawn(handle_single_connection(
                        cancellation_token,
                        command_tx,
                        stream,
                        permit,
                    ));
                },
                Err(error) => {
                    event!(Level::ERROR, ?error, "Failed to accept connection");
                },
            }
        }
    }

    pub fn teardown(self) {
        self.cancellation_token.cancel();
    }
}

fn bind_tcp_loopback(address: SocketAddr) -> Result<GenericListener, std::io::Error> {
    let socket = match address {
        SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4(),
        SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6(),
    }?;

    socket.set_reuseaddr(true)?;
    socket.set_reuseport(true)?;
    socket.bind(address)?;

    Ok(socket.listen(MAX_CONNECTION_BACKLOG)?.into())
}

/// Never resolves when there is no secondary listener.
async fn accept_secondary(
    listener: Option<&GenericListener>,
) -> Result<GenericStream, std::io::Error> {
    match listener {
        Some(listener) => listener.accept().await,
        None => std::future::pending().await,
    }
}

async fn handle_single_connection(
    cancellation_token: CancellationToken,
    command_tx: Sender<Command>,
    stream: GenericStream,
    _permit: OwnedSemaphorePermit,
) {
    const BUFFER_SIZE: usize = 255;

    let mut buffer = vec![0_u8; BUFFER_SIZE];

    let (mut reader, mut writer) = stream.into_split();

    loop {
        let read = tokio::select! {
            () = cancellation_token.cancelled() => {
                break;
            },
            read = reader.read(&mut buffer) => {
                read
            },
        };

        match read {
            Ok(0) => {
                event!(Level::INFO, "Stream closed");
                break;
            },
            Ok(bytes_read) => {
                match process_command(&buffer[0..bytes_read], &command_tx, &mut writer).await {
                    Ok(true) => {
                        // all good
                        continue;
                    },
                    Ok(false) => {
                        // closed
                        event!(Level::INFO, "Stream closed");
                        break;
                    },
                    Err(error) => {
                        event!(Level::ERROR, ?error, "Something went wrong with the stream");
                        break;
                    },
                }
            },
            Err(error) => {
                event!(Level::INFO, ?error, "Stream gone");
                break;
            },
        }
    }

    event!(Level::INFO, "API Client gone");

    // `_permit` is released here
}

/// Process commands.
///
/// Remember, `raw_command` is newline terminated.
async fn process_command<W>(
    raw_command: &[u8],
    command_tx: &Sender<Command>,
    writer: &mut W,
) -> Result<bool, std::io::Error>
where
    W: AsyncWriteExt + Unpin,
{
    let command = match str::from_utf8(raw_command) {
        Ok(command) => command.trim(),
        Err(_error) => {
            writer.write_all("Invalid UTF-8".as_bytes()).await?;

            return Ok(true);
        },
    };

    let (command, command_arg) = command
        .split_once(' ')
        .map_or((command, None), |(left, right)| (left, Some(right)));

    match command {
        "probe" => {
            event!(Level::DEBUG, interface = ?command_arg, "probing devices upon request");

            if command_tx
                .send(Command::SendProbes {
                    interface_filter: command_arg.map(Into::into),
                })
                .await
                .is_err()
            {
                writer
                    .write_all("Failed to issue probe command. Please retry.".as_bytes())
                    .await?;

                return Ok(true);
            }
        },
        "clear" => {
            event!(Level::DEBUG, "clearing list of known devices");

            if command_tx.send(Command::ClearDevices).await.is_err() {
                writer
                    .write_all("Failed to issue clear command. Please retry.".as_bytes())
                    .await?;

                return Ok(true);
            }
        },
        "list" => {
            let (devices_tx, mut devices_rx) = tokio::sync::mpsc::channel(20);

            if command_tx
                .send(Command::ListDevices {
                    devices_tx,
                    wsd_type_filter: command_arg.map(Into::into),
                })
                .await
                .is_err()
            {
                writer
                    .write_all("Failed to issue list command. Please retry.".as_bytes())
                    .await?;
                return Ok(true);
            }

            while let Some((device_uri, device)) = devices_rx.recv().await {
                let line = format_wsd_discovered_device(&device_uri, &device);

                writer.write_all(line.as_bytes()).await?;
            }

            writer.write_all(".\n".as_bytes()).await?;
        },
        "quit" => {
            writer.shutdown().await?;
            return Ok(false);
        },
        "start" => {
            if command_tx.send(Command::Start).await.is_err() {
                writer
                    .write_all("Failed to issue start command. Please retry.".as_bytes())
                    .await?;
            }
        },
        "stop" => {
            if command_tx.send(Command::Stop).await.is_err() {
                writer
                    .write_all("Failed to issue stop command. Please retry.".as_bytes())
                    .await?;
            }
        },
        "help" => {
            let list = "Valid commands are: \"clear\", \"probe\", \"list\", \"quit\", \"start\", \"stop\", \"help\"";

            writer.write_all(list.as_bytes()).await?;
        },
        _ => {
            event!(
                Level::DEBUG,
                command,
                ?command_arg,
                "could not handle API request"
            );
        },
    }

    Ok(true)
}

fn format_wsd_discovered_device(device_uri: &DeviceUri, device: &WSDDiscoveredDevice) -> String {
    format!(
        "{}\t{}\t{}\t{}\t{}\t{}\n",
        device_uri,
        device.display_name().unwrap_or_default(),
        device
            .props()
            .get("BelongsTo")
            .map(|b| &**b)
            .unwrap_or_default(),
        device
            .last_seen()
            .format(&ISO8601_SECOND_PRECISION)
            .unwrap(),
        device
            .addresses()
            .iter()
            .map(|(interface_name, addresses)| {
                let addresses = addresses
                    .iter()
                    .map(|a| &**a)
                    .collect::<Vec<_>>()
                    .join(", ");

                format!("{}, {{{}}}", interface_name, addresses)
            })
            .collect::<Vec<_>>()
            .join(","),
        device
            .types()
            .iter()
            .map(|t| &**t)
            .collect::<Vec<_>>()
            .join(","),
    )
}

//     async def cleanup(self) -> None:
//         # ensure the server is not created after we have teared down
//         await self.create_task
//         if self.server:
//             self.server.close()
//             await self.server.wait_closed()

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use pretty_assertions::assert_eq;
    use tokio::io::AsyncReadExt as _;
    use tokio_util::sync::CancellationToken;

    use crate::api_server::{ApiServer, MAX_CONCURRENT_CONNECTIONS};
    use crate::config::PortOrSocket;

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn port_mode_binds_both_loopbacks() {
        let probe =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("Failed to find a port");
        let port = probe
            .local_addr()
            .expect("Bound socket has an address")
            .port();
        drop(probe);

        let (command_tx, _command_rx) = tokio::sync::mpsc::channel(1);

        let api_server = ApiServer::new(
            CancellationToken::new(),
            &PortOrSocket::Port(port),
            command_tx,
        )
        .expect("Failed to bind API server");

        tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("Failed to connect over IPv4 loopback");
        tokio::net::TcpStream::connect((Ipv6Addr::LOCALHOST, port))
            .await
            .expect("Failed to connect over IPv6 loopback");

        api_server.teardown();
    }

    #[cfg_attr(not(miri), tokio::test)]
    #[cfg_attr(miri, expect(unused, reason = "This test doesn't work with Miri"))]
    async fn rejects_connections_beyond_the_cap() {
        let probe =
            std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("Failed to find a port");
        let port = probe
            .local_addr()
            .expect("Bound socket has an address")
            .port();
        drop(probe);

        let (command_tx, _command_rx) = tokio::sync::mpsc::channel(1);

        let cancellation_token = CancellationToken::new();

        let api_server = ApiServer::new(
            cancellation_token.child_token(),
            &PortOrSocket::Port(port),
            command_tx,
        )
        .expect("Failed to bind API server");

        tokio::task::spawn(async move { api_server.handle_connections().await });

        let mut held = Vec::new();
        for _ in 0..MAX_CONCURRENT_CONNECTIONS {
            held.push(
                tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .expect("Failed to connect"),
            );
        }

        let mut rejected = tokio::net::TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .expect("Failed to connect");

        let mut response = String::new();
        rejected
            .read_to_string(&mut response)
            .await
            .expect("Failed to read the rejection");

        assert_eq!(response, "No slots available");

        cancellation_token.cancel();
    }
}
