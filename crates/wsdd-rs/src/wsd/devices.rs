use color_eyre::eyre;
use hashbrown::HashMap;
use hashbrown::hash_map::{Entry, EntryRef};

use crate::network_address::NetworkAddress;
use crate::soap::parser::xaddrs::XAddr;
use crate::wsd::device::{DeviceUri, WSDDiscoveredDevice};

/// The discovered devices, shared by the clients of every interface.
#[derive(Default)]
pub struct Devices {
    discovered: HashMap<DeviceUri, WSDDiscoveredDevice>,
    /// The Target Services with a metadata exchange in progress.
    exchanges: HashMap<DeviceUri, Exchanges>,
}

#[derive(Default)]
struct Exchanges {
    running: usize,
    /// The Byes received while at least one exchange was running.
    byes: u64,
}

/// A metadata exchange started with `Devices::start_exchange`.
pub struct Exchange {
    byes: u64,
}

impl Devices {
    pub fn start_exchange(&mut self, endpoint: &DeviceUri) -> Exchange {
        let exchanges = match self.exchanges.entry_ref(endpoint) {
            EntryRef::Occupied(occupied_entry) => occupied_entry.into_mut(),
            EntryRef::Vacant(vacant_entry_ref) => {
                vacant_entry_ref.insert_with_key(endpoint.clone(), Exchanges::default())
            },
        };

        exchanges.running += 1;

        Exchange {
            byes: exchanges.byes,
        }
    }

    /// Ends `exchange`, and returns whether the Target Service at `endpoint` sent a Bye while it ran.
    pub fn finish_exchange(&mut self, endpoint: &DeviceUri, Exchange { byes }: Exchange) -> bool {
        let Some(exchanges) = self.exchanges.get_mut(endpoint) else {
            return false;
        };

        exchanges.running -= 1;

        let departed = exchanges.byes != byes;

        if exchanges.running == 0 {
            self.exchanges.remove(endpoint);
        }

        departed
    }

    pub fn store(
        &mut self,
        endpoint: DeviceUri,
        meta: &[u8],
        xaddr: &XAddr,
        bound_to: &NetworkAddress,
    ) -> Result<(), eyre::Report> {
        match self.discovered.entry(endpoint) {
            Entry::Occupied(occupied_entry) => {
                let (key, value) = occupied_entry.into_entry();

                value.update(key, meta, xaddr, bound_to)?;
            },
            Entry::Vacant(vacant_entry) => {
                let new = WSDDiscoveredDevice::new(vacant_entry.key(), meta, xaddr, bound_to)?;

                vacant_entry.insert(new);
            },
        }

        Ok(())
    }

    /// Removes the device at `endpoint`, and marks its running metadata exchanges so they discard their metadata.
    pub fn depart(&mut self, endpoint: &DeviceUri) -> Option<WSDDiscoveredDevice> {
        if let Some(exchanges) = self.exchanges.get_mut(endpoint) {
            exchanges.byes += 1;
        }

        self.discovered.remove(endpoint)
    }

    pub fn clear(&mut self) {
        self.discovered.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = (&DeviceUri, &WSDDiscoveredDevice)> {
        self.discovered.iter()
    }

    #[cfg(test)]
    pub fn get(&self, endpoint: &DeviceUri) -> Option<&WSDDiscoveredDevice> {
        self.discovered.get(endpoint)
    }

    #[cfg(test)]
    pub fn contains_key(&self, endpoint: &DeviceUri) -> bool {
        self.discovered.contains_key(endpoint)
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.discovered.is_empty()
    }

    #[cfg(test)]
    pub fn has_running_exchanges(&self) -> bool {
        !self.exchanges.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use crate::wsd::device::DeviceUri;
    use crate::wsd::devices::Devices;

    fn endpoint() -> DeviceUri {
        DeviceUri::new(Box::from("urn:uuid:00000000-0000-0000-0000-000000000001"))
    }

    #[test]
    fn bye_during_an_exchange_departs() {
        let mut devices = Devices::default();

        let exchange = devices.start_exchange(&endpoint());
        devices.depart(&endpoint());

        assert!(devices.finish_exchange(&endpoint(), exchange));
    }

    #[test]
    fn bye_before_an_exchange_does_not_depart() {
        let mut devices = Devices::default();

        devices.depart(&endpoint());
        let exchange = devices.start_exchange(&endpoint());

        assert!(!devices.finish_exchange(&endpoint(), exchange));
    }

    #[test]
    fn exchange_started_after_a_bye_does_not_depart() {
        let mut devices = Devices::default();

        let before = devices.start_exchange(&endpoint());
        devices.depart(&endpoint());
        let after = devices.start_exchange(&endpoint());

        assert!(devices.finish_exchange(&endpoint(), before));
        assert!(!devices.finish_exchange(&endpoint(), after));
    }

    #[test]
    fn finished_exchanges_leave_no_state() {
        let mut devices = Devices::default();

        let first = devices.start_exchange(&endpoint());
        let second = devices.start_exchange(&endpoint());
        devices.depart(&endpoint());
        devices.finish_exchange(&endpoint(), first);

        assert!(devices.has_running_exchanges());

        devices.finish_exchange(&endpoint(), second);

        assert!(!devices.has_running_exchanges());
    }

    #[test]
    fn bye_without_an_exchange_leaves_no_state() {
        let mut devices = Devices::default();

        devices.depart(&endpoint());

        assert!(!devices.has_running_exchanges());
    }
}
