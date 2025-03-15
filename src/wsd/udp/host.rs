use std::net::{IpAddr, SocketAddr};
use std::string::String;
use std::sync::{Arc, LazyLock};

use color_eyre::eyre;
use quick_xml::NsReader;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::constants;
use crate::soap::builder::{self, Builder, MessageType};
use crate::soap::parser::{self, MessageHandler};
use crate::utils::task::spawn_with_name;
use crate::{config::Config, max_size_deque::MaxSizeDeque};

static HANDLED_MESSAGES: LazyLock<Arc<RwLock<MaxSizeDeque<String>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(MaxSizeDeque::new(10))));

/// handles WSD requests coming from UDP datagrams.
pub(crate) struct WSDHost {
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    address: IpAddr,
    multicast: Sender<Box<[u8]>>,
}

impl WSDHost {
    pub(crate) async fn init(
        cancellation_token: &CancellationToken,
        config: Arc<Config>,
        address: IpAddr,
        mut receiver: Receiver<(SocketAddr, Arc<[u8]>)>,
        multicast: Sender<Box<[u8]>>,
        unicast: Sender<(SocketAddr, Box<[u8]>)>,
    ) -> Self {
        let m = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES));

        let cancellation_token = cancellation_token.child_token();

        // TODO error handler setup
        {
            let config = Arc::clone(&config);

            let cancellation_token = cancellation_token.clone();

            spawn_with_name(format!("wsd host ({})", address).as_str(), async move {
                loop {
                    let message = tokio::select! {
                        () = cancellation_token.cancelled() => {
                            break;
                        },
                        message = receiver.recv() => {
                            message
                        }
                    };

                    let Some((from, buffer)) = message else {
                        // the end, but we just got it before the cancellation
                        break;
                    };

                    let (message_id, action, body_reader) =
                        match m.deconstruct_message(&buffer).await {
                            Ok(Some(pieces)) => pieces,
                            Ok(None) => {
                                event!(
                                    Level::TRACE,
                                    "XML Message did not have required elements: {}",
                                    String::from_utf8_lossy(&buffer)
                                );
                                continue;
                            },
                            Err(err) => {
                                event!(
                                    Level::ERROR,
                                    ?err,
                                    "Error while decoding XML: {}",
                                    String::from_utf8_lossy(&buffer)
                                );
                                continue;
                            },
                        };

                    // handle based on action
                    let response = match action.as_ref() {
                        constants::WSD_PROBE => handle_probe(Arc::clone(&config), body_reader),
                        constants::WSD_RESOLVE => {
                            handle_resolve(Arc::clone(&config), address, config.uuid, body_reader)
                        },
                        _ => {
                            event!(Level::DEBUG, "unhandled action {}/{}", action, message_id);
                            continue;
                        },
                    };

                    let response = match response {
                        Ok(response) => response,
                        Err(err) => {
                            event!(
                                Level::ERROR,
                                ?action,
                                ?err,
                                "Failure to create XML response"
                            );
                            continue;
                        },
                    };

                    // return to sender
                    if let Err(err) = unicast.send((from, response.into())).await {
                        event!(Level::ERROR, ?err, to = ?from, "Failed to respond to message");
                    }
                }
            });
        };

        let host = Self {
            cancellation_token,
            config,
            address,
            multicast,
        };

        // TODO is this fatal? What should we do?
        if let Err(err) = host.send_hello().await {
            event!(Level::ERROR, ?err, "Failed to send hello");
        }

        host
    }

    // WS-Discovery, Section 4.1, Hello message
    async fn send_hello(&self) -> Result<(), eyre::Report> {
        let hello = Builder::build_hello(self.config.clone(), self.address)?;

        // deviation, we can't write that we're scheduling it with the same data, as we don't have the knowledge
        // TODO move event to here and write properly

        event!(Level::INFO, "scheduling {} message", MessageType::Hello);

        Ok(self
            .multicast
            .send(hello.into_bytes().into_boxed_slice())
            .await?)
    }

    /// WS-Discovery, Section 4.2, Bye message
    async fn send_bye(&self) -> Result<(), eyre::Report> {
        let bye = Builder::build_bye(self.config.clone())?;

        // deviation, we can't write that we're scheduling it with the same data, as we don't have the knowledge
        // TODO move event to here and write properly

        event!(Level::INFO, "scheduling {} message", MessageType::Bye);
        Ok(self
            .multicast
            .send(bye.into_bytes().into_boxed_slice())
            .await?)
    }

    // or async drop if you will?
    pub async fn teardown(self, graceful: bool) {
        // this makes us stop listeneng for probes & resolves
        // note that this is a child token, so we only cancel ourselves
        self.cancellation_token.cancel();

        if graceful {
            if let Err(err) = self.send_bye().await {
                event!(Level::DEBUG, ?err, "Failed to schedule bye message");
            }
        }
    }
}

fn handle_probe(config: Arc<Config>, mut reader: NsReader<&[u8]>) -> Result<Vec<u8>, eyre::Report> {
    parser::parse_probe_body(&mut reader)?;

    builder::Builder::build_probe_matches(config).map(String::into_bytes)
}

fn handle_resolve(
    config: Arc<Config>,
    address: IpAddr,
    target_uuid: uuid::Uuid,
    mut reader: NsReader<&[u8]>,
) -> Result<Vec<u8>, eyre::Report> {
    parser::parse_resolve_body(&mut reader, target_uuid)?;

    builder::Builder::build_resolve_matches(config, address).map(String::into_bytes)
}

//     def handle_packet(self, msg: str, src: UdpAddress) -> None:
//         reply = self.handle_message(msg, src)
//         if reply:
//             self.enqueue_datagram(reply, src)
