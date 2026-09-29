use color_eyre::eyre;
use hashbrown::HashMap;
use hashbrown::hash_map::Entry;

use crate::network_address::NetworkAddress;
use crate::soap::parser::xaddrs::XAddr;
use crate::wsd::device::{DeviceUri, WSDDiscoveredDevice};

/// The discovered devices, shared by the clients of every interface.
#[derive(Default)]
pub struct Devices {
    discovered: HashMap<DeviceUri, WSDDiscoveredDevice>,
}

impl Devices {
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

    pub fn remove(&mut self, endpoint: &DeviceUri) -> Option<WSDDiscoveredDevice> {
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
}
