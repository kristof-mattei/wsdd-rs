use color_eyre::eyre;
use hashbrown::HashMap;
use hashbrown::hash_map::{Entry, EntryRef};
use tokio_util::sync::CancellationToken;

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
    /// Cancelled by a Bye and then replaced, so an exchange that starts after the Bye runs.
    bye: CancellationToken,
}

/// A metadata exchange started with `Devices::start_exchange`.
pub struct Exchange {
    bye: CancellationToken,
}

impl Exchange {
    /// Runs `future` unless the Target Service sends a Bye first, then returns `None`.
    pub async fn run_until_bye<F: Future>(&self, future: F) -> Option<F::Output> {
        self.bye.run_until_cancelled(future).await
    }
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
            bye: exchanges.bye.clone(),
        }
    }

    /// Ends `exchange`, and returns whether the Target Service at `endpoint` sent a Bye while it ran.
    pub fn finish_exchange(&mut self, endpoint: &DeviceUri, Exchange { bye }: Exchange) -> bool {
        let Some(exchanges) = self.exchanges.get_mut(endpoint) else {
            return false;
        };

        exchanges.running -= 1;

        let departed = bye.is_cancelled();

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

    /// Removes the device at `endpoint`, and stops its running metadata exchanges.
    pub fn depart(&mut self, endpoint: &DeviceUri) -> Option<WSDDiscoveredDevice> {
        if let Some(exchanges) = self.exchanges.get_mut(endpoint) {
            std::mem::take(&mut exchanges.bye).cancel();
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
    use std::time::Duration;

    use pretty_assertions::assert_eq;

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

    #[tokio::test]
    async fn bye_stops_a_running_exchange() {
        let mut devices = Devices::default();

        let exchange = devices.start_exchange(&endpoint());

        let (output, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                exchange.run_until_bye(std::future::pending::<()>()),
                async {
                    devices.depart(&endpoint());
                }
            )
        })
        .await
        .unwrap();

        assert_eq!(output, None);
    }

    #[tokio::test]
    async fn exchange_started_after_a_bye_runs() {
        let mut devices = Devices::default();

        let before = devices.start_exchange(&endpoint());
        devices.depart(&endpoint());
        let after = devices.start_exchange(&endpoint());

        assert_eq!(before.run_until_bye(async { 1 }).await, None);
        assert_eq!(after.run_until_bye(async { 1 }).await, Some(1));
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
