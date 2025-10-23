mod generic;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre;
use time::format_description::well_known::Iso8601;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use uuid::Uuid;

use crate::api_server::generic::{GenericListener, GenericStream};
use crate::config::PortOrSocket;
use crate::network_handler::Command;
use crate::wsd::device::WSDDiscoveredDevice;

const MAX_CONNECTION_BACKLOG: u32 = 100;
const MAX_CONCURRENT_CONNECTIONS: usize = 10;

pub struct ApiServer {
    cancellation_token: CancellationToken,
    listener: GenericListener,
    command_tx: tokio::sync::mpsc::Sender<Command>,
}

impl ApiServer {
    pub fn new(
        cancellation_token: CancellationToken,
        listen_on: &PortOrSocket,
        command_tx: tokio::sync::mpsc::Sender<Command>,
    ) -> Result<ApiServer, std::io::Error> {
        let listener: GenericListener = match *listen_on {
            PortOrSocket::Port(port) => {
                let socket = tokio::net::TcpSocket::new_v4()?;
                socket.set_reuseaddr(true)?;
                socket.set_reuseport(true)?;
                socket.bind(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)))?;

                socket.listen(MAX_CONNECTION_BACKLOG)?.into()
            },
            PortOrSocket::SocketPath(ref path) => {
                let socket = tokio::net::UnixSocket::new_stream()?;
                socket.bind(path)?;
                socket.listen(MAX_CONNECTION_BACKLOG)?.into()
            },
        };

        Ok(Self {
            cancellation_token,
            listener,
            command_tx,
        })
    }

    pub async fn handle_connections(&self) -> Result<(), eyre::Report> {
        let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

        loop {
            let new_connection = tokio::select! {
                () = self.cancellation_token.cancelled() => {
                    return Ok(());
                },
                new_connection = self.listener.accept() => {
                    new_connection
                }
            };

            match new_connection {
                Ok(mut stream) => {
                    let Ok(permit) = Arc::clone(&semaphore).acquire_owned().await else {
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

    #[expect(clippy::unused_async, reason = "WIP")]
    pub(crate) async fn teardown(&self) {}
}

async fn handle_single_connection(
    cancellation_token: CancellationToken,
    command_tx: tokio::sync::mpsc::Sender<Command>,
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
            }
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

/// `raw_command` is newline terminated
async fn process_command<W>(
    raw_command: &[u8],
    command_tx: &tokio::sync::mpsc::Sender<Command>,
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
                    wsd_type_filter: command_arg.map(Into::into),
                    devices_tx,
                })
                .await
                .is_err()
            {
                writer
                    .write_all("Failed to issue list command. Please retry.".as_bytes())
                    .await?;
                return Ok(true);
            }

            while let Some((uuid, device)) = devices_rx.recv().await {
                format_wsd_discovered_device(writer, uuid, &device).await;
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

async fn format_wsd_discovered_device<W>(writer: &mut W, uuid: Uuid, device: &WSDDiscoveredDevice)
where
    W: AsyncWriteExt + Unpin,
{
    let _r = writer.write_all(uuid.to_string().as_bytes()).await;
    let _r = writer.write_all("\t".as_bytes()).await;
    let _r = writer
        .write_all(device.display_name().unwrap_or_default().as_bytes())
        .await;
    let _r = writer.write_all("\t".as_bytes()).await;
    let _r = writer
        .write_all(
            device
                .props()
                .get("BelongsTo")
                .map(|b| &**b)
                .unwrap_or_default()
                .as_bytes(),
        )
        .await;
    let _r = writer.write_all("\t".as_bytes()).await;
    let _r = writer
        .write_all(
            device
                .last_seen()
                .format(&Iso8601::DEFAULT)
                .unwrap()
                .as_bytes(),
        )
        .await;
    let _r = writer.write_all("\t".as_bytes()).await;
    let addresses = device
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
        .join(",");
    let _r = writer.write_all(addresses.as_bytes()).await;
    let _r = writer.write_all("\t".as_bytes()).await;
    let _r = writer
        .write_all(
            device
                .types()
                .iter()
                .map(|t| &**t)
                .collect::<Vec<_>>()
                .join(",")
                .as_bytes(),
        )
        .await;
    let _r = writer.write_all("\n".as_bytes()).await;
}

//     async def cleanup(self) -> None:
//         # ensure the server is not created after we have teared down
//         await self.create_task
//         if self.server:
//             self.server.close()
//             await self.server.wait_closed()
