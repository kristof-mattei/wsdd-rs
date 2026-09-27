use std::net::IpAddr;

use hashbrown::{HashMap, HashSet};

use crate::network_address::NetworkAddress;

/// Handlers by address and interface index. The kernel keeps one IPv4 address with several prefix lengths as separate entries, so a handler lives until the last entry of its address is deleted.
pub struct AddressHandlers<H> {
    handled: HashMap<(IpAddr, u32), Handled<H>>,
}

struct Handled<H> {
    prefix_lens: HashSet<u8>,
    handler: H,
}

fn key(network_address: &NetworkAddress) -> (IpAddr, u32) {
    (
        network_address.address.addr(),
        network_address.interface.index(),
    )
}

impl<H> Default for AddressHandlers<H> {
    fn default() -> Self {
        Self {
            handled: HashMap::new(),
        }
    }
}

impl<H> AddressHandlers<H> {
    /// Adds the entry's prefix length to the handler of its address, `false` when that address has no handler yet.
    pub fn add_prefix_if_handled(&mut self, network_address: &NetworkAddress) -> bool {
        let Some(handled) = self.handled.get_mut(&key(network_address)) else {
            return false;
        };

        handled
            .prefix_lens
            .insert(network_address.address.prefix_len());

        true
    }

    pub fn insert(&mut self, network_address: &NetworkAddress, handler: H) {
        self.handled.insert(
            key(network_address),
            Handled {
                prefix_lens: HashSet::from([network_address.address.prefix_len()]),
                handler,
            },
        );
    }

    /// Removes the prefix length. Returns the handler when no other prefix length of its address remains.
    pub fn remove_prefix(&mut self, network_address: &NetworkAddress) -> Option<H> {
        let key = key(network_address);

        let handled = self.handled.get_mut(&key)?;

        handled
            .prefix_lens
            .remove(&network_address.address.prefix_len());

        if !handled.prefix_lens.is_empty() {
            return None;
        }

        self.handled.remove(&key).map(|handled| handled.handler)
    }

    pub fn handlers(&self) -> impl Iterator<Item = &H> {
        self.handled.values().map(|handled| &handled.handler)
    }

    pub fn drain(&mut self) -> impl Iterator<Item = H> {
        self.handled.drain().map(|(_, handled)| handled.handler)
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::sync::Arc;

    use ipnet::Ipv4Net;
    use libc::RT_SCOPE_SITE;
    use pretty_assertions::assert_eq;

    use crate::network_address::NetworkAddress;
    use crate::network_handler::address_handlers::AddressHandlers;
    use crate::network_interface::NetworkInterface;

    fn network_address(interface: &str, index: u32, prefix_len: u8) -> NetworkAddress {
        NetworkAddress::new(
            Ipv4Net::new(Ipv4Addr::new(10, 9, 9, 9), prefix_len)
                .unwrap()
                .into(),
            Arc::new(NetworkInterface::new_with_index(
                interface,
                RT_SCOPE_SITE,
                index,
            )),
        )
    }

    #[test]
    fn address_without_handler_is_not_recorded() {
        let mut handlers = AddressHandlers::<&str>::default();

        assert!(!handlers.add_prefix_if_handled(&network_address("eth0", 5, 24)));
    }

    #[test]
    fn second_prefix_of_an_address_uses_its_handler() {
        let mut handlers = AddressHandlers::default();

        handlers.insert(&network_address("eth0", 5, 24), "handler");

        assert!(handlers.add_prefix_if_handled(&network_address("eth0", 5, 16)));
        assert_eq!(handlers.handlers().collect::<Vec<_>>(), [&"handler"]);
    }

    #[test]
    fn same_address_on_another_interface_has_its_own_handler() {
        let mut handlers = AddressHandlers::default();

        handlers.insert(&network_address("eth0", 5, 24), "handler");

        assert!(!handlers.add_prefix_if_handled(&network_address("eth1", 6, 24)));
    }

    #[test]
    fn handler_stays_while_another_prefix_of_its_address_remains() {
        let mut handlers = AddressHandlers::default();

        handlers.insert(&network_address("eth0", 5, 24), "handler");
        handlers.add_prefix_if_handled(&network_address("eth0", 5, 16));

        assert_eq!(
            handlers.remove_prefix(&network_address("eth0", 5, 16)),
            None
        );
        assert_eq!(
            handlers.remove_prefix(&network_address("eth0", 5, 24)),
            Some("handler")
        );
        assert_eq!(handlers.handlers().count(), 0);
    }

    #[test]
    fn deleting_an_unrecorded_prefix_keeps_the_handler() {
        let mut handlers = AddressHandlers::default();

        handlers.insert(&network_address("eth0", 5, 24), "handler");

        assert_eq!(handlers.remove_prefix(&network_address("eth0", 5, 8)), None);
        assert_eq!(handlers.handlers().collect::<Vec<_>>(), [&"handler"]);
    }
}
