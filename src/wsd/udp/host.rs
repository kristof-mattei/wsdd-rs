use std::net::{IpAddr, SocketAddr};
use std::string::String;
use std::sync::{Arc, LazyLock};

use color_eyre::eyre;
use hashbrown::HashSet;
use quick_xml::NsReader;
use tokio::sync::RwLock;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::task::JoinHandle;
use tracing::{Level, event};

use crate::config::Config;
use crate::constants;
use crate::soap::builder::{self, Builder, MessageType};
use crate::soap::parser::{self, MessageHandler};
use crate::utils::task::spawn_with_name;

static HANDLED_MESSAGES: LazyLock<Arc<RwLock<HashSet<String>>>> =
    LazyLock::new(|| Arc::<RwLock<HashSet<String>>>::new(RwLock::new(HashSet::new())));

pub(crate) struct WSDHost {
    config: Arc<Config>,
    address: IpAddr,
    // udp_message_handler: WSDUDPMessageHandler<'nph>,
    #[expect(unused)]
    listener_handle: JoinHandle<()>,
    multicast: Sender<(MessageType, Box<[u8]>)>,
}

// impl WSDHost {
//     pub(crate) fn new(
//         multicast_handler: &Arc<MulticastHandler<'nph>>,
//         config: &Arc<Config>,
//     ) -> Self {
//         Self {
//             // udp_message_handler: WSDUDPMessageHandler::new(multicast_handler, config),
//         }
//     }
// }
impl WSDHost {
    pub(crate) async fn new(
        config: Arc<Config>,
        address: IpAddr,
        mut receiver: Receiver<(Arc<[u8]>, SocketAddr)>,
        unicast: Sender<(Box<[u8]>, SocketAddr)>,
        multicast: Sender<(MessageType, Box<[u8]>)>,
    ) -> Self {
        let m = MessageHandler::new(Arc::clone(&HANDLED_MESSAGES));

        // TODO error handler setup
        let listener_handle = {
            let config = Arc::clone(&config);

            spawn_with_name(format!("wsd host ({})", address).as_str(), async move {
                loop {
                    if let Some((buffer, from)) = receiver.recv().await {
                        let (message_id, action, body_reader) =
                            match m.deconstruct_message(&buffer).await {
                                Ok(Some(pieces)) => pieces,
                                Ok(None) => {
                                    continue;
                                },
                                Err(_err) => {
                                    // TODO LOG ERROR BETTER
                                    println!("ERROR");
                                    continue;
                                },
                            };

                        // handle based on action
                        let response = match action.as_ref() {
                            constants::WSD_PROBE => handle_probe(Arc::clone(&config), body_reader),
                            constants::WSD_RESOLVE => handle_resolve(
                                Arc::clone(&config),
                                address,
                                config.uuid,
                                body_reader,
                            ),
                            _ => {
                                event!(Level::DEBUG, "unhandled action {}/{}", action, message_id);
                                continue;
                            },
                        };

                        let Ok(response) = response else {
                            // TODO error?
                            continue;
                        };

                        if let Err(err) = unicast.send((response.into(), from)).await {
                            event!(Level::ERROR, ?err, "Failed to broadcast");
                        }
                    } else {
                        // the end
                        event!(Level::ERROR, "recv socket gone?");
                        break;
                    }
                }
            })
            .expect("FAILED TO LAUNCH LISTENER")
        };

        let s = Self {
            config,
            address,
            listener_handle,
            multicast,
        };

        // this shouldn't be an await...
        s.send_hello().await.unwrap();

        s
    }

    // WS-Discovery, Section 4.1, Hello message
    async fn send_hello(&self) -> Result<(), eyre::Report> {
        let hello = Builder::build_hello(self.config.clone(), self.address)?;

        // deviation, we can't write that we're scheduling it with the same data, as we don't have the knowledge
        // TODO move event to here and write properly
        Ok(self
            .multicast
            .send((MessageType::Hello, hello.into_bytes().into_boxed_slice()))
            .await?)
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

// class WSDHost(WSDUDPMessageHandler):
//     """Class for handling WSD requests coming from UDP datagrams."""

//     message_number: ClassVar[int] = 0
//     instances: ClassVar[List['WSDHost']] = []

//     def __init__(self, mch: MulticastHandler) -> None:
//         super().__init__(mch)

//         WSDHost.instances.append(self)

//         self.mch.add_handler(self.mch.recv_socket, self)

//         self.handlers[WSD_PROBE] = self.handle_probe
//         self.handlers[WSD_RESOLVE] = self.handle_resolve

//         self.send_hello()

//     def cleanup(self) -> None:
//         super().cleanup()
//         WSDHost.instances.remove(self)

//     def teardown(self) -> None:
//         super().teardown()
//         self.send_bye()

//     def handle_packet(self, msg: str, src: UdpAddress) -> None:
//         reply = self.handle_message(msg, src)
//         if reply:
//             self.enqueue_datagram(reply, src)

//     def send_bye(self) -> None:
//         """WS-Discovery, Section 4.2, Bye message"""
//         bye = ElementTree.Element('wsd:Bye')
//         self.add_endpoint_reference(bye)

//         msg = self.build_message(WSA_DISCOVERY, WSD_BYE, None, bye)
//         self.enqueue_datagram(msg, self.mch.multicast_address, msg_type='Bye')

//     def handle_probe(self, header: ElementTree.Element, body: ElementTree.Element) -> Optional[WSDMessage]:
//         probe = body.find('./wsd:Probe', namespaces)
//         if probe is None:
//             return None

//         scopes = probe.find('./wsd:Scopes', namespaces)

//         if scopes:
//             # THINK: send fault message (see p. 21 in WSD)
//             logger.debug('scopes ({}) unsupported but probed'.format(scopes))
//             return None

//         types_elem = probe.find('./wsd:Types', namespaces)
//         if types_elem is None:
//             logger.debug('Probe message lacks wsd:Types element. Ignored.')
//             return None

//         types = types_elem.text
//         if not types == WSD_TYPE_DEVICE:
//             logger.debug('unknown discovery type ({}) for probe'.format(types))
//             return None

//         matches = ElementTree.Element('wsd:ProbeMatches')
//         match = ElementTree.SubElement(matches, 'wsd:ProbeMatch')
//         self.add_endpoint_reference(match)
//         self.add_types(match)
//         self.add_metadata_version(match)

//         return matches, WSD_PROBE_MATCH

//     def add_header_elements(self, header: ElementTree.Element, extra: Any):
//         ElementTree.SubElement(
//             header, 'wsd:AppSequence', {
//                 'InstanceId': str(wsd_instance_id),
//                 'SequenceId': uuid.uuid1().urn,
//                 'MessageNumber': str(type(self).message_number)
//             })

//         type(self).message_number += 1
