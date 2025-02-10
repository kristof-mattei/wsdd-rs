// class MetaEnumAfterInit(type):
//     def __call__(cls, *cargs, **kwargs):
//         obj = super().__call__(*cargs, **kwargs)
//         if not args.no_autostart:
//             obj.enumerate()
//         return obj

use std::{collections::HashMap, sync::Arc};

use tracing::{event, Level};

use crate::{
    config::Config, multicast_handler::MulticastHandler, network_address::NetworkAddress,
    network_interface::NetworkInterface,
};

struct NetworkAddressMonitor<'mhl> {
    //     interfaces: Dict[int, NetworkInterface]
    interfaces: HashMap<u32, NetworkInterface>,
    //     aio_loop: asyncio.AbstractEventLoop
    //     mchs: List[MulticastHandler]
    mchs: Vec<MulticastHandler<'mhl>>,
    //     http_servers: List[WSDHttpServer]
    http_servers: Vec<()>,
    //     teardown_tasks: List[asyncio.Task]
    //     active: bool
    active: bool,

    config: Arc<Config>,
}

// static INSTANCES: Lazy<NetworkAddressMonitor> = Lazy::new(|| NetworkAddressMonitor {});

// class NetworkAddressMonitor(metaclass=MetaEnumAfterInit):
impl<'mhl> NetworkAddressMonitor<'mhl> {
    // """
    // Observes changes of network addresses, handles addition and removal of
    // network addresses, and filters for addresses/interfaces that are or are not
    // handled. The actual OS-specific implementation that detects the changes is
    // done in subclasses. This class is used as a singleton
    // """

    // instance: ClassVar[object] = None

    // def __init__(self, aio_loop: asyncio.AbstractEventLoop) -> None:
    fn new(config: Arc<Config>) -> Self {
        Self {
            interfaces: HashMap::new(),
            mchs: vec![],
            http_servers: vec![],
            active: false,
            config,
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
    fn add_interface(&mut self, interface: NetworkInterface) {
        if self.interfaces.contains_key(&interface.index) {
            return;
        }

        self.interfaces.insert(interface.index, interface);
        //     # TODO: Cleanup

        //     if interface.index in self.interfaces:
        //         pass
        //         # self.interfaces[idx].name = name
        //     else:
        //         self.interfaces[interface.index] = interface

        //     return self.interfaces[interface.index]
    }

    // def is_address_handled(self, address: NetworkAddress) -> bool:
    fn is_address_handled(&self, address: &NetworkAddress) -> bool {
        // # do not handle anything when we are not active
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

        if !address.address.is_multicast() {
            return false;
        }

        // Use interface only if it's in the list of user-provided interface names
        if !self.config.interface.is_empty()
            && !self.config.interface.contains(&address.interface.name)
            && !self.config.interface.contains(&address.address_str)
        {
            return false;
        }

        true
    }

    // def handle_new_address(self, address: NetworkAddress) -> None:
    fn handle_new_address(&mut self, address: NetworkAddress) {
        event!(Level::DEBUG, "new address {}", address);

        if !(self.is_address_handled(&address)) {
            event!(
                Level::DEBUG,
                "ignoring that address on {}",
                address.interface
            );
        }

        // filter out what is not wanted
        // Ignore addresses or interfaces we already handle. There can only be
        // one multicast handler per address family and network interface
        for mch in &self.mchs {
            if mch.handles_address(&address) {
                return;
            }
        }

        event!(Level::DEBUG, "handling traffic for {}", address);
        let mch = MulticastHandler::new(address, (), Arc::clone(&self.config));
        self.mchs.push(mch);

        if !self.config.no_host {
            // TODO start WSDHost
            // WSDHost(mch)
            if !self.config.no_http {
                // TODO
                // self.http_servers.append(WSDHttpServer(mch, ()))
            }
        }

        if self.config.discovery {
            // TODO
            // WSDClient(mch)
        }
    }

    fn handle_deleted_address(&mut self, address: &NetworkAddress) {
        event!(Level::INFO, "deleted address {}", address);

        if !self.is_address_handled(address) {
            return;
        }

        let Some(mut mch) = self.get_mch_by_address(address) else {
            return;
        };

        // Do not tear the client/hosts down. Saying goodbye does not work
        // because the address is already gone (at least on Linux).
        // TODO
        //     for c in WSDClient.instances:
        //         if c.mch == mch:
        //             c.cleanup()
        //             break
        //     for h in WSDHost.instances:
        //         if h.mch == mch:
        //             h.cleanup()
        //             break
        //     for s in self.http_servers:
        //         if s.mch == mch:
        //             s.server_close()
        //             self.http_servers.remove(s)

        mch.cleanup();
        //     self.mchs.remove(mch)
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

    fn get_mch_by_address(&mut self, address: &NetworkAddress) -> Option<MulticastHandler<'mhl>> {
        //     """
        //     Get the MCI for the address, its family and the interface.
        //     adress must be given as a string.
        //     """

        let p = self
            .mchs
            .iter()
            .position(|mch| mch.handles_address(address));

        if let Some(position) = p {
            Some(self.mchs.swap_remove(position))
        } else {
            None
        }
    }
}
