use std::net::{IpAddr, SocketAddr};
use std::string::String;
use std::sync::Arc;
use std::time::Duration;

use color_eyre::eyre;
use quick_xml::NsReader;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_util::sync::CancellationToken;
use tracing::{Level, event};
use uuid::fmt::Urn;

use super::HANDLED_MESSAGES;
use crate::config::Config;
use crate::constants;
use crate::network_address::NetworkAddress;
use crate::soap::builder::{self, Builder, MessageType};
use crate::soap::parser::{self, HeaderError, MessageHandler, MessageHandlerError};
use crate::utils::task::spawn_with_name;

/// handles WSD requests coming from UDP datagrams.
pub struct WSDHost {
    address: IpAddr,
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    multicast: Sender<Box<[u8]>>,
}

impl WSDHost {
    pub async fn init(
        cancellation_token: &CancellationToken,
        config: Arc<Config>,
        network_address: NetworkAddress,
        receiver: Receiver<(SocketAddr, Arc<[u8]>)>,
        multicast: Sender<Box<[u8]>>,
        unicast: Sender<(SocketAddr, Box<[u8]>)>,
    ) -> Self {
        let cancellation_token = cancellation_token.child_token();

        let address = network_address.address;

        spawn_receiver_loop(
            cancellation_token.clone(),
            Arc::clone(&config),
            network_address,
            receiver,
            unicast,
        );

        let host = Self {
            address,
            cancellation_token,
            config,
            multicast,
        };

        // avoid packet storm when hosts come up by delaying initial hello
        tokio::time::sleep(Duration::from_millis(rand::random_range(
            0..=constants::APP_MAX_DELAY,
        )))
        .await;

        if let Err(err) = host.send_hello().await {
            // TODO is this fatal? What should we do?
            event!(Level::ERROR, ?err, "Failed to send hello");
        }

        host
    }

    // or async drop if you will?
    pub async fn teardown(self, graceful: bool) {
        // this makes us stop listeneng for probes & resolves
        // note that this is a child token, so we only cancel ourselves
        self.cancellation_token.cancel();

        if graceful && let Err(err) = self.send_bye().await {
            event!(Level::DEBUG, ?err, "Failed to schedule bye message");
        }
    }

    // WS-Discovery, Section 4.1, Hello message
    async fn send_hello(&self) -> Result<(), eyre::Report> {
        let hello = Builder::build_hello(&self.config, self.address)?;

        // deviation, we can't write that we're scheduling it with the same data, as we don't have the knowledge
        // TODO move event to here and write properly
        event!(Level::INFO, "scheduling {} message", MessageType::Hello);

        self.multicast.send(hello.into_boxed_slice()).await?;

        Ok(())
    }

    /// WS-Discovery, Section 4.2, Bye message
    async fn send_bye(&self) -> Result<(), eyre::Report> {
        let bye = Builder::build_bye(&self.config)?;

        // deviation, we can't write that we're scheduling it with the same data, as we don't have the knowledge
        // TODO move event to here and write properly
        event!(Level::INFO, "scheduling {} message", MessageType::Bye);

        Ok(self.multicast.send(bye.into_boxed_slice()).await?)
    }
}

fn handle_probe(
    config: &Config,
    relates_to: Urn,
    mut reader: NsReader<&[u8]>,
) -> Result<Vec<u8>, eyre::Report> {
    parser::probe::parse_probe_body(&mut reader)?;

    Ok(builder::Builder::build_probe_matches(config, relates_to)?)
}

fn handle_resolve(
    config: &Config,
    address: IpAddr,
    target_uuid: uuid::Uuid,
    relates_to: Urn,
    mut reader: NsReader<&[u8]>,
) -> Result<Vec<u8>, eyre::Report> {
    parser::resolve::parse_resolve_body(&mut reader, target_uuid)?;

    Ok(builder::Builder::build_resolve_matches(
        config, address, relates_to,
    )?)
}

#[expect(clippy::too_many_lines, reason = "WIP")]
fn spawn_receiver_loop(
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    network_address: NetworkAddress,
    mut receiver: Receiver<(SocketAddr, Arc<[u8]>)>,
    unicast: Sender<(SocketAddr, Box<[u8]>)>,
) {
    let address = network_address.address;

    let message_handler = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES), network_address);

    spawn_with_name(format!("wsd host ({})", address).as_str(), async move {
        loop {
            #[expect(clippy::pattern_type_mismatch, reason = "Tokio macro")]
            let message = {
                tokio::select! {
                    () = cancellation_token.cancelled() => {
                        break;
                    },
                    message = receiver.recv() => {
                        message
                    }
                }
            };

            let Some((from, buffer)) = message else {
                // the end, but we just got it before the cancellation
                break;
            };

            let (header, body_reader) = match message_handler
                .deconstruct_message(&buffer, Some(from))
                .await
            {
                Ok(pieces) => pieces,
                Err(error) => {
                    match error {
                        MessageHandlerError::DuplicateMessage => {
                            // nothing
                        },
                        missing @ (MessageHandlerError::MissingHeader
                        | MessageHandlerError::MissingBody) => {
                            event!(
                                Level::TRACE,
                                ?missing,
                                "XML Message did not have required elements: {}",
                                String::from_utf8_lossy(&buffer)
                            );
                        },
                        MessageHandlerError::HeaderError(
                            HeaderError::InvalidMessageId(uuid_error)
                            | HeaderError::InvalidRelatesTo(uuid_error),
                        ) => {
                            event!(
                                Level::TRACE,
                                ?uuid_error,
                                "XML Message Header was malformed: {}",
                                String::from_utf8_lossy(&buffer)
                            );
                        },
                        MessageHandlerError::HeaderError(
                            error @ (HeaderError::MissingAction | HeaderError::MissingMessageId),
                        ) => {
                            event!(
                                Level::TRACE,
                                %error,
                                "XML Message Header is missing pieces: {}",
                                String::from_utf8_lossy(&buffer)
                            );
                        },
                        MessageHandlerError::HeaderError(HeaderError::XmlError(error))
                        | MessageHandlerError::XmlError(error) => {
                            event!(
                                Level::ERROR,
                                ?error,
                                "Error while decoding XML: {}",
                                String::from_utf8_lossy(&buffer)
                            );
                        },
                    }

                    continue;
                },
            };

            // handle based on action
            let response = match &*header.action {
                constants::WSD_PROBE => handle_probe(&config, header.message_id, body_reader),
                constants::WSD_RESOLVE => handle_resolve(
                    &config,
                    address,
                    config.uuid,
                    header.message_id,
                    body_reader,
                ),
                _ => {
                    event!(
                        Level::DEBUG,
                        "unhandled action {}/{}",
                        header.action,
                        header.message_id
                    );
                    continue;
                },
            };

            let response = match response {
                Ok(response) => response,
                Err(err) => {
                    event!(
                        Level::ERROR,
                        action = &*header.action,
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
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
        sync::Arc,
    };

    use libc::RT_SCOPE_SITE;
    use pretty_assertions::assert_eq;
    use tokio::sync::RwLock;

    use crate::{
        cli,
        max_size_deque::MaxSizeDeque,
        network_address::NetworkAddress,
        network_interface::NetworkInterface,
        soap::parser::MessageHandler,
        test_utils,
        wsd::udp::host::{handle_probe, handle_resolve},
    };

    #[tokio::test]
    async fn handles_resolve() {
        let message_handler = MessageHandler::new(
            Arc::new(RwLock::new(MaxSizeDeque::new(20))),
            NetworkAddress::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)),
                Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
            ),
        );

        let message_id = "ba866dfd-8135-11f0-accb-d45ddf1e11a9";
        let endpoint_uuid = "f3dcd9d5-65ee-46ff-bc74-d151934a30c4";
        let instance_id = "instance-id";
        let from = Ipv4Addr::new(192, 168, 100, 5);

        let resolve = format!(
            include_str!("../../test/resolve-template.xml"),
            message_id, endpoint_uuid,
        );

        let config = Arc::new({
            let mut config = cli::parse_cli_from([
                "-4",
                "--uuid",
                endpoint_uuid,
                "--hostname",
                "test-host-name",
            ])
            .unwrap();

            // instance ID is not settable with commandline
            config.wsd_instance_id = Box::from(instance_id);

            config
        });

        let (header, reader) = message_handler
            .deconstruct_message(
                resolve.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(from, 5000))),
            )
            .await
            .unwrap();

        let response = handle_resolve(
            &config,
            IpAddr::V4(from),
            config.uuid,
            header.message_id,
            reader,
        )
        .unwrap();

        let expected = format!(
            include_str!("../../test/resolve-matches-template.xml"),
            message_id, instance_id, endpoint_uuid, from, endpoint_uuid
        );

        let response = test_utils::to_string_pretty(&response).unwrap();
        let expected = test_utils::to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }

    #[tokio::test]
    async fn handles_probe() {
        let message_handler = MessageHandler::new(
            Arc::new(RwLock::new(MaxSizeDeque::new(20))),
            NetworkAddress::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 100, 1)),
                Arc::new(NetworkInterface::new_with_index("eth0", RT_SCOPE_SITE, 5)),
            ),
        );

        let message_id = "ba866dfd-8135-11f0-accb-d45ddf1e11a9";
        let endpoint_uuid = "f3dcd9d5-65ee-46ff-bc74-d151934a30c4";
        let instance_id = "instance-id";
        let from = Ipv4Addr::new(192, 168, 100, 5);

        let resolve = format!(include_str!("../../test/probe-template.xml"), message_id);

        let config = Arc::new({
            let mut config = cli::parse_cli_from([
                "-4",
                "--uuid",
                endpoint_uuid,
                "--hostname",
                "test-host-name",
            ])
            .unwrap();

            // instance ID is not settable with commandline
            config.wsd_instance_id = Box::from(instance_id);

            config
        });

        let (header, reader) = message_handler
            .deconstruct_message(
                resolve.as_bytes(),
                Some(SocketAddr::V4(SocketAddrV4::new(from, 5000))),
            )
            .await
            .unwrap();

        let response = handle_probe(&config, header.message_id, reader).unwrap();

        let expected = format!(
            include_str!("../../test/probe-matches-template.xml"),
            message_id, instance_id, endpoint_uuid
        );

        let response = test_utils::to_string_pretty(&response).unwrap();
        let expected = test_utils::to_string_pretty(expected.as_bytes()).unwrap();

        assert_eq!(response, expected);
    }
}
