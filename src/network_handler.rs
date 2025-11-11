// class MetaEnumAfterInit(type):
//     def __call__(cls, *cargs, **kwargs):
//         obj = super().__call__(*cargs, **kwargs)
//         if not args.no_autostart:
//             obj.enumerate()
//         return obj

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use color_eyre::eyre;
use hashbrown::HashMap;
use hashbrown::hash_map::Entry;
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::sync::mpsc::Sender;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tracing::{Level, event};
use uuid::Uuid;

use crate::config::Config;
use crate::multicast_handler::MulticastHandler;
use crate::network_address::NetworkAddress;
use crate::network_interface::{self, NetworkInterface};
use crate::wsd::device::WSDDiscoveredDevice;

#[derive(Debug)]
pub enum Command {
    NewAddress {
        address: IpAddr,
        scope: u8,
        index: u32,
    },
    DeleteAddress {
        address: IpAddr,
        scope: u8,
        index: u32,
    },
    ClearDevices,
    ListDevices {
        wsd_type_filter: Option<Box<str>>,
        devices_tx: Sender<(Uuid, WSDDiscoveredDevice)>,
    },
    SendProbes {
        interface_filter: Option<Box<str>>,
    },
    Start,
    Stop,
}

#[derive(Debug, Error)]
pub enum Reason {
    #[error("Application not active")]
    NotActive,
    #[error("IPv4 only")]
    IPv4Only,
    #[error("IPv6 only")]
    IPv6Only,
    #[error("Not multicastable")]
    AddressNotMulticastable,
    #[error("Interface is excluded")]
    ExcludedInterface,
}

pub struct NetworkHandler {
    // TODO this should _probably_ be an AtomicBool
    active: AtomicBool,
    cancellation_token: CancellationToken,
    config: Arc<Config>,
    devices: Arc<RwLock<HashMap<Uuid, WSDDiscoveredDevice>>>,
    interfaces: HashMap<u32, Arc<NetworkInterface>>,
    multicast_handlers: Vec<MulticastHandler>,
    command_rx: tokio::sync::mpsc::Receiver<Command>,
    start_tx: tokio::sync::watch::Sender<()>,
}

#[derive(Error, Debug)]
pub enum NetworkHandlerError {
    #[error("Interface Detection Failed")]
    InterfaceDetectionFailed(std::io::Error),
}

/// Observes changes of network addresses, handles addition and removal of
/// network addresses, and filters for addresses/interfaces that are or are not
/// handled. The actual OS-specific implementation that detects the changes is
/// done in subclasses. This class is used as a singleton
impl NetworkHandler {
    pub fn new(
        cancellation_token: CancellationToken,
        config: &Arc<Config>,
        command_rx: tokio::sync::mpsc::Receiver<Command>,
        start_tx: tokio::sync::watch::Sender<()>,
    ) -> Self {
        Self {
            active: AtomicBool::new(false),
            config: Arc::clone(config),
            cancellation_token,
            devices: Arc::new(RwLock::new(HashMap::new())),
            interfaces: HashMap::new(),
            multicast_handlers: vec![],
            command_rx,
            start_tx,
        }
    }

    pub async fn process_commands(&mut self) -> Result<(), eyre::Report> {
        loop {
            let command = tokio::select! {
                () = self.cancellation_token.cancelled() => {
                    break;
                },
                command = self.command_rx.recv() => {
                    command
                }
            };

            let Some(command) = command else {
                // GONE?
                // TODO
                break;
            };

            match command {
                Command::NewAddress {
                    address,
                    scope,
                    index,
                } => {
                    let interface = match self.add_interface(scope, index) {
                        Ok(interface) => interface,
                        Err(_error) => {
                            return Ok(());
                        },
                    };

                    self.handle_new_address(NetworkAddress::new(address, Arc::clone(&interface)))
                        .await;
                },
                Command::DeleteAddress {
                    address,
                    scope,
                    index,
                } => {
                    let interface = match self.add_interface(scope, index) {
                        Ok(interface) => interface,
                        Err(_error) => {
                            return Ok(());
                        },
                    };

                    self.handle_deleted_address(NetworkAddress::new(
                        address,
                        Arc::clone(&interface),
                    ))
                    .await;
                },
                Command::ClearDevices => {
                    if self.config.discovery {
                        self.devices.write().await.clear();
                    }
                },
                Command::ListDevices {
                    wsd_type_filter,
                    devices_tx,
                } => {
                    if self.config.discovery {
                        self.list_devices(wsd_type_filter, devices_tx).await;
                    }
                },
                Command::SendProbes { interface_filter } => {
                    if self.config.discovery {
                        self.send_probes(interface_filter).await;
                    }
                },
                Command::Start => {
                    self.set_active()?;
                },
                Command::Stop => {
                    self.teardown().await;
                },
            }
        }

        Ok(())
    }

    async fn list_devices(
        &self,
        wsd_type_filter: Option<Box<str>>,
        devices_tx: Sender<(Uuid, WSDDiscoveredDevice)>,
    ) {
        // take the lock once, clone, store locally, and then yield items
        // that way we reduce the lifetime of the lock
        let devices = self.devices.read().await;

        let devices = if let Some(wsd_type) = wsd_type_filter.as_deref() {
            devices
                .iter()
                .filter_map(|(key, value)| {
                    if value.types().contains(wsd_type) {
                        Some((*key, value.clone()))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        } else {
            devices
                .iter()
                .map(|(key, value)| (*key, value.clone()))
                .collect::<Vec<_>>()
        };

        // purposefully fire and forget
        tokio::task::spawn(async move {
            for device in devices {
                // this will fail if the receiver is gone
                // which happens when there is an issue writing to the buffer
                // which usually means 'thing' connecting to the api is gone
                if (devices_tx.send(device).await).is_err() {
                    event!(
                        Level::WARN,
                        "Failed to send device on channel, aborting sending rest"
                    );

                    break;
                }
            }
        });
    }

    async fn send_probes(&self, interface_filter: Option<Box<str>>) {
        let interface_filter = interface_filter.as_ref();

        for multicast_handler in &self.multicast_handlers {
            let Some(wsd_client) = multicast_handler.wsd_client() else {
                continue;
            };

            let should_send_probe = match interface_filter {
                Some(interface) => multicast_handler.get_address().interface.name() == &**interface,
                None => true,
            };

            if should_send_probe {
                let _r = wsd_client.send_probe().await;
            }
        }
    }

    fn add_interface(
        &mut self,
        ifa_scope: u8,
        ifa_index: u32,
    ) -> Result<Arc<NetworkInterface>, NetworkHandlerError> {
        let interface = match self.interfaces.entry(ifa_index) {
            Entry::Occupied(occupied_entry) => Arc::clone(occupied_entry.get()),
            Entry::Vacant(vacant_entry) => {
                let if_name = match network_interface::if_indextoname(ifa_index) {
                    Ok(if_name) => if_name,
                    Err(error) => {
                        // accept this exception (which should not occur)
                        event!(
                            Level::ERROR,
                            ifa_idx = ifa_index,
                            ?error,
                            "interface detection failed",
                        );

                        return Err(NetworkHandlerError::InterfaceDetectionFailed(error));
                    },
                };

                let entry = vacant_entry.insert(Arc::new(NetworkInterface::new_with_index(
                    if_name.into_string(),
                    ifa_scope,
                    ifa_index,
                )));

                Arc::clone(entry)
            },
        };

        Ok(interface)
    }

    fn is_address_handled(&self, address: &NetworkAddress) -> Result<(), Reason> {
        // do not handle anything when we are not active
        if !self.active.load(Ordering::Relaxed) {
            return Err(Reason::NotActive);
        }

        // filter out address families we are not interested in
        if self.config.ipv4only && !address.address.is_ipv4() {
            return Err(Reason::IPv4Only);
        }

        if self.config.ipv6only && !address.address.is_ipv6() {
            return Err(Reason::IPv6Only);
        }

        if !address.is_multicastable() {
            return Err(Reason::AddressNotMulticastable);
        }

        // Use interface only if it's in the list of user-provided interface names
        if !self.config.interfaces.is_empty()
            && !self
                .config
                .interfaces
                .iter()
                .any(|i| &**i == address.interface.name())
            && !self
                .config
                .interfaces
                .iter()
                .any(|i| **i == address.address.to_string())
        {
            return Err(Reason::ExcludedInterface);
        }

        Ok(())
    }

    pub async fn handle_new_address(&mut self, address: NetworkAddress) {
        event!(Level::DEBUG, address = %address.address, interface = %address.interface.name(), "new address");

        if let Err(why) = self.is_address_handled(&address) {
            event!(Level::DEBUG, ?why, address = %address.address, interface = %address.interface.name(), "ignoring address");

            return;
        }

        // filter out what is not wanted
        // Ignore addresses or interfaces we already handle. There can only be
        // one multicast handler per address family and network interface
        for handler in &self.multicast_handlers {
            if handler.handles_address(&address) {
                return;
            }
        }

        event!(Level::DEBUG, "handling traffic for {}", address);

        // TODO: Proper error handling here
        let mut multicast_handler = MulticastHandler::new(
            address,
            self.cancellation_token.clone(),
            &self.config,
            Arc::clone(&self.devices),
        )
        .expect("FAIL");

        if !self.config.no_host {
            // it's important that the HTTP server is ready before we enable the WSD Host
            // which schedules the hello. We must be ready before that
            if !self.config.no_http {
                multicast_handler.enable_http_server().await;
            }

            multicast_handler.enable_wsd_host().await;
        }

        if self.config.discovery {
            multicast_handler.enable_wsd_client().await;
        }

        self.multicast_handlers.push(multicast_handler);
    }

    pub async fn handle_deleted_address(&mut self, address: NetworkAddress) {
        event!(Level::INFO, address = %address.address, interface = %address.interface.name(), "deleted address");

        if self.is_address_handled(&address).is_err() {
            return;
        }

        let Some(handler) = self.take_mch_by_address(&address) else {
            return;
        };

        handler.teardown(false).await;

        // handler gets dropped
    }

    pub async fn teardown(&mut self) {
        let mut was_active = self.active.load(Ordering::Relaxed);

        // we can get away with `Relaxed` because nothing depends on our value
        while was_active {
            match self.active.compare_exchange_weak(
                true,
                false,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(current) => was_active = current,
            }
        }

        if !was_active {
            // Already stopped, nothing to do
            return;
        }

        let tasks = TaskTracker::new();

        while let Some(mch) = self.multicast_handlers.pop() {
            tasks.spawn(async move {
                mch.teardown(true).await;
            });
        }

        tasks.close();
        tasks.wait().await;

        //     for h in WSDHost.instances:
        //         h.teardown()
        //         h.cleanup()
        //         self.teardown_tasks.extend(h.pending_tasks)

        //     for c in WSDClient.instances:
        //         c.teardown()
        //         c.cleanup()
        //         self.teardown_tasks.extend(c.pending_tasks)

        //     for s in self.http_servers:
        //         s.server_close()

        //     self.http_servers.clear()

        //     if not self.teardown_tasks:
        //         return

        //     if not self.aio_loop.is_running():
        //         # Wait here for all pending tasks so that the main loop can be finished on termination.
        //         self.aio_loop.run_until_complete(asyncio.gather(*self.teardown_tasks))
        //     else:
        //         for t in self.teardown_tasks:
        //             t.add_done_callback(self.mch_teardown)
    }

    // def mch_teardown(self, task) -> None:
    //     if any([not t.done() for t in self.teardown_tasks]):
    //         return

    //     self.teardown_tasks.clear()

    //     for mch in self.mchs:
    //         mch.cleanup()
    //     self.mchs.clear()

    // def cleanup(self) -> None:
    //     self.teardown()

    /// Get the MCI for the address, its family and the interface.
    /// adress must be given as a string.
    #[expect(unused, reason = "WIP")]
    fn get_mch_by_address(&mut self, address: &NetworkAddress) -> Option<&MulticastHandler> {
        self.multicast_handlers
            .iter()
            .find(|multicast_handler| multicast_handler.handles_address(address))
    }

    /// Takes the MCI for the address, its family and the interface.
    /// adress must be given as a string.
    fn take_mch_by_address(&mut self, address: &NetworkAddress) -> Option<MulticastHandler> {
        let position = self
            .multicast_handlers
            .iter()
            .position(|multicast_handler| multicast_handler.handles_address(address));

        if let Some(position) = position {
            Some(self.multicast_handlers.swap_remove(position))
        } else {
            None
        }
    }

    pub fn set_active(&mut self) -> Result<(), eyre::Report> {
        let mut was_active = self.active.load(Ordering::Relaxed);

        // we can get away with `Relaxed` because nothing depends on our value
        while !was_active {
            match self.active.compare_exchange_weak(
                false,
                true,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    self.start_tx
                        .send(())
                        .map_err(|_| eyre::Report::msg("channel gone"))?;
                    break;
                },
                Err(current) => {
                    was_active = current;
                },
            }
        }

        Ok(())
    }
}
