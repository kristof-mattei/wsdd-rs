mod generic;

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::api_server::generic::{GenericListener, GenericStream, GenericWriteHalf};
use crate::config::PortOrSocket;
use crate::network_handler::Command;

const MAX_CONNECTION_BACKLOG: u32 = 100;
const MAX_CONCURRENT_CONNECTIONS: usize = 10;

pub struct ApiServer {
    cancellation_token: CancellationToken,
    listener: GenericListener,
    command_sender: tokio::sync::mpsc::Sender<Command>,
}

impl ApiServer {
    pub fn new(
        cancellation_token: CancellationToken,
        listen_on: &PortOrSocket,
        command_sender: tokio::sync::mpsc::Sender<Command>,
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
            command_sender,
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

                    let command_sender = self.command_sender.clone();

                    tokio::task::spawn(handle_single_connection(
                        cancellation_token,
                        command_sender,
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
    command_sender: tokio::sync::mpsc::Sender<Command>,
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
                match process_command(&buffer[0..bytes_read], &command_sender, &mut writer).await {
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

    // RELEASE THE KRAKEN
    // I mean permit
}

/// `raw_command` is newline terminated
async fn process_command(
    raw_command: &[u8],
    command_sender: &tokio::sync::mpsc::Sender<Command>,
    writer: &mut GenericWriteHalf,
) -> Result<bool, std::io::Error> {
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
            // send probes
            event!(Level::DEBUG, interface = ?command_arg, "probing devices upon request");
            // for client in self.get_clients_by_interface(intf):
            //   client.send_probe()
        },
        "clear" => {
            event!(Level::DEBUG, "clearing list of known devices");
            // WSDDiscoveredDevice.instances.clear()
        },
        "list" => {
            // elif command == 'list' and args.discovery:
            //   wsd_type = command_args[0] if command_args else None
            //   write_stream.write(bytes(self.get_list_reply(wsd_type), 'utf-8'))

            let (children_tx, mut children_rx) = tokio::sync::mpsc::channel(20);

            if command_sender
                .send(Command::ListDevices(
                    command_arg.map(Into::into),
                    children_tx,
                ))
                .await
                .is_err()
            {
                writer
                    .write_all("Failed to issue list command. Please retry.".as_bytes())
                    .await?;
                return Ok(true);
            }

            while let Some(child) = children_rx.recv().await {
                writer.write_all(format!("{:?}", child).as_bytes()).await?;
            }
        },
        "quit" => {
            writer.shutdown().await?;
            return Ok(false);
        },
        "start" => {
            if command_sender.send(Command::Start).await.is_err() {
                writer
                    .write_all("Failed to issue start command. Please retry.".as_bytes())
                    .await?;
            }
        },
        "stop" => {
            if command_sender.send(Command::Stop).await.is_err() {
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

//     def get_clients_by_interface(self, interface: Optional[str]) -> List[WSDClient]:
//         return [c for c in WSDClient.instances if c.mch.address.interface.name == interface or not interface]

//     def get_list_reply(self, wsd_type: Optional[str]) -> str:
//         retval = ''
//         for dev_uuid, dev in WSDDiscoveredDevice.instances.items():
//             if wsd_type and (wsd_type not in dev.types):
//                 continue

//             addrs_str = []
//             for addrs in dev.addresses.items():
//                 addrs_str.append(', '.join(['{}'.format(a) for a in addrs]))

//             retval = retval + '{}\t{}\t{}\t{}\t{}\t{}\n'.format(
//                 dev_uuid, dev.display_name, dev.props['BelongsTo'] if 'BelongsTo' in dev.props else '',
//                 datetime.datetime.fromtimestamp(dev.last_seen).isoformat('T', 'seconds'), ','.join(addrs_str), ','.join(
//                     dev.types))

//         retval += '.\n'
//         return retval

//     async def cleanup(self) -> None:
//         # ensure the server is not created after we have teared down
//         await self.create_task
//         if self.server:
//             self.server.close()
//             await self.server.wait_closed()
