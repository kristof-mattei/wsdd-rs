// class MetaEnumAfterInit(type):
//     def __call__(cls, *cargs, **kwargs):
//         obj = super().__call__(*cargs, **kwargs)
//         if not args.no_autostart:
//             obj.enumerate()
//         return obj

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;
use tracing::{Level, event};

use crate::config::Config;
use crate::multicast_handler::MulticastHandler;
use crate::network_address::NetworkAddress;
use crate::network_interface::{self, NetworkInterface};

pub struct NetworkAddressMonitor {
    config: Arc<Config>,
    //     interfaces: Dict[int, NetworkInterface]
    interfaces: HashMap<u32, Arc<NetworkInterface>>,
    //     mchs: List[MulticastHandler]
    multicast_handlers: Vec<MulticastHandler>,
    //     teardown_tasks: List[asyncio.Task]
    //     active: bool
    active: bool,
}

// static INSTANCES: Lazy<NetworkAddressMonitor> = Lazy::new(|| NetworkAddressMonitor {});

// class NetworkAddressMonitor(metaclass=MetaEnumAfterInit):
/// Observes changes of network addresses, handles addition and removal of
/// network addresses, and filters for addresses/interfaces that are or are not
/// handled. The actual OS-specific implementation that detects the changes is
/// done in subclasses. This class is used as a singleton
impl NetworkAddressMonitor {
    // instance: ClassVar[object] = None

    pub fn new(config: &Arc<Config>) -> Self {
        Self {
            config: Arc::clone(config),
            interfaces: HashMap::new(),
            multicast_handlers: vec![],
            active: false,
        }
    }

    // def enumerate(self) -> None:
    //     """
    //     Performs an initial enumeration of addresses and sets up everything
    //     for observing future changes.
    //     """
    //     if self.active:
    //         return

    //     self.active = True
    //     self.do_enumerate()

    // def do_enumerate(self) -> None:
    //     pass

    // def handle_change(self) -> None:
    //     """ handle network change message """
    //     pass

    // def add_interface(self, interface: NetworkInterface) -> NetworkInterface:
    pub fn add_interface(
        &mut self,
        ifa_scope: u8,
        ifa_index: u32,
    ) -> Result<Arc<NetworkInterface>, String> {
        let interface = match self.interfaces.entry(ifa_index) {
            Entry::Occupied(occupied_entry) => occupied_entry.get().clone(),
            Entry::Vacant(vacant_entry) => {
                let if_name = match network_interface::if_indextoname(ifa_index) {
                    Ok(if_name) => if_name,
                    Err(err) => {
                        // accept this exception (which should not occur)

                        event!(
                            Level::ERROR,
                            ifa_idx = ifa_index,
                            ?err,
                            "interface detection failed",
                        );

                        return Err("interface detection failed".into());
                    },
                };

                vacant_entry
                    .insert(Arc::new(NetworkInterface::new_with_index(
                        if_name, ifa_scope, ifa_index,
                    )))
                    .clone()
            },
        };

        Ok(interface)
    }

    fn is_address_handled(&self, address: &NetworkAddress) -> bool {
        // do not handle anything when we are not active
        if !self.active {
            return false;
        }

        // filter out address families we are not interested in
        if self.config.ipv4only && !address.address.is_ipv4() {
            return false;
        }

        if self.config.ipv6only && !address.address.is_ipv6() {
            return false;
        }

        if !address.is_multicastable() {
            return false;
        }

        // Use interface only if it's in the list of user-provided interface names
        if !self.config.interface.is_empty()
            && !self.config.interface.contains(&address.interface.name)
            && !self.config.interface.contains(&address.address.to_string())
        {
            return false;
        }

        true
    }

    // def handle_new_address(self, address: NetworkAddress) -> None:
    pub fn handle_new_address(
        &mut self,
        address: NetworkAddress,
        cancellation_token: &CancellationToken,
    ) {
        event!(Level::DEBUG, "new address {}", address);

        if !(self.is_address_handled(&address)) {
            event!(
                Level::DEBUG,
                "ignoring that address on {}",
                address.interface
            );

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
        let mut multicast_handler =
            MulticastHandler::new(address, cancellation_token.clone(), &self.config).expect("FAIL");

        if !self.config.no_host {
            // TODO start WSDHost
            multicast_handler.enable_wsd_host();

            if !self.config.no_http {
                multicast_handler.enable_http_server();
            }
        }

        if self.config.discovery {
            // TODO
            // WSDClient(mch)
            multicast_handler.enable_wsd_client();
        }

        self.multicast_handlers.push(multicast_handler);
    }

    pub fn handle_deleted_address(&mut self, address: &NetworkAddress) {
        event!(Level::INFO, "deleted address {}", address);

        if !self.is_address_handled(address) {
            return;
        }

        let Some(mut handler) = self.take_mch_by_address(address) else {
            return;
        };

        // TODO
        //     self.mchs.remove(mch)
        handler.cleanup();
    }

    // def teardown(self) -> None:
    //     if not self.active:
    //         return

    //     self.active = False

    //     # return if we are still in tear down process
    //     if len(self.teardown_tasks) > 0:
    //         return

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
    #[expect(unused)]
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

    pub(crate) fn set_active(&mut self) {
        self.active = true;
    }
}
