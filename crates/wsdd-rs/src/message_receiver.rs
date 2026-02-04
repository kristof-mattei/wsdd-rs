use std::mem::MaybeUninit;
use std::sync::Arc;

use tokio::net::UdpSocket;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::constants;
use crate::multicast_handler::{IncomingClientMessage, IncomingHostMessage};
use crate::network_address::NetworkAddress;
use crate::soap::WSDMessage;
use crate::soap::parser::MessageHandler;
use crate::utils::SocketAddrDisplay;
use crate::utils::task::spawn_with_name;
use crate::wsd::HANDLED_MESSAGES;

struct ClientHostListener {
    host_tx: Option<Sender<IncomingHostMessage>>,
    client_tx: Option<Sender<IncomingClientMessage>>,
}
pub struct MessageReceiver {
    cancellation_token: CancellationToken,
    handle: JoinHandle<()>,
    listeners: Arc<RwLock<ClientHostListener>>,
}

impl MessageReceiver {
    pub fn new(
        cancellation_token: CancellationToken,
        network_address: NetworkAddress,
        socket: Arc<UdpSocket>,
    ) -> Self {
        let listeners = Arc::new(RwLock::const_new(ClientHostListener {
            host_tx: None,
            client_tx: None,
        }));

        let handle = {
            let listeners = Arc::clone(&listeners);

            spawn_with_name(
                format!("socket rx ({})", SocketAddrDisplay(&socket)).as_str(),
                socket_rx_forever(
                    cancellation_token.clone(),
                    network_address,
                    listeners,
                    socket,
                ),
            )
        };

        Self {
            cancellation_token,
            handle,
            listeners,
        }
    }

    pub async fn get_host_rx(&mut self) -> Result<Receiver<IncomingHostMessage>, ()> {
        let mut writer = self.listeners.write().await;

        if writer.host_tx.is_some() {
            return Err(());
        }

        let (tx, rx) = tokio::sync::mpsc::channel(10);

        writer.host_tx = Some(tx);

        Ok(rx)
    }

    pub async fn get_client_rx(&mut self) -> Result<Receiver<IncomingClientMessage>, ()> {
        let mut writer = self.listeners.write().await;

        if writer.client_tx.is_some() {
            return Err(());
        }

        let (tx, rx) = tokio::sync::mpsc::channel(10);

        writer.client_tx = Some(tx);

        Ok(rx)
    }

    pub async fn teardown(self) {
        self.cancellation_token.cancel();

        let _r = self.handle.await;
    }
}

async fn socket_rx_forever(
    cancellation_token: CancellationToken,
    network_address: NetworkAddress,
    listeners: Arc<RwLock<ClientHostListener>>,
    socket: Arc<UdpSocket>,
) {
    let message_handler = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES), network_address);

    loop {
        let mut buffer = vec![MaybeUninit::<u8>::uninit(); constants::WSD_MAX_LEN];

        let result = {
            let mut buffer_byte_cursor = &mut *buffer;

            tokio::select! {
                () = cancellation_token.cancelled() => {
                    break;
                },
                result = socket.recv_buf_from(&mut buffer_byte_cursor) => {
                    result
                },
            }
        };

        let (bytes_read, from) = match result {
            Ok(read) => read,
            Err(error) => {
                event!(
                    Level::ERROR,
                    ?error,
                    socket = %SocketAddrDisplay(&socket),
                    "Failed to read from socket"
                );

                continue;
            },
        };

        // `recv_buf` tells us that `bytes_read` were read from the socket into our `buffer`, so they're initialized
        buffer.truncate(bytes_read);

        // SAFETY: we are only initializing the parts of the buffer `recv_buf_from` has written to
        let buffer = unsafe { &*(&raw const *buffer as *const [u8]) };

        let (header, message) = match message_handler.deconstruct_message(buffer, from).await {
            Ok(decoded) => decoded,
            Err(error) => {
                error.log(buffer);

                continue;
            },
        };

        let lock = listeners.read().await;

        match message {
            WSDMessage::ClientMessage(message) => {
                if let &Some(ref client_tx) = &lock.client_tx {
                    if let Err(error) = client_tx
                        .send(IncomingClientMessage {
                            from,
                            header,
                            message,
                        })
                        .await
                    {
                        event!(Level::ERROR, ?error, socket = %SocketAddrDisplay(&socket), "Failed to send data to channel");
                    }
                }
            },
            WSDMessage::HostMessage(message) => {
                if let &Some(ref host_tx) = &lock.host_tx {
                    if let Err(error) = host_tx
                        .send(IncomingHostMessage {
                            from,
                            header,
                            message,
                        })
                        .await
                    {
                        event!(Level::ERROR, ?error, socket = %SocketAddrDisplay(&socket), "Failed to send data to channel");
                    }
                }
            },
        }
    }
}
