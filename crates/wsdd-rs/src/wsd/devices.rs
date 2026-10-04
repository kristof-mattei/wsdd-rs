use std::collections::VecDeque;

use color_eyre::eyre;
use hashbrown::HashMap;
use hashbrown::hash_map::{Entry, EntryRef};
use tokio_util::sync::CancellationToken;

use crate::network_address::NetworkAddress;
use crate::soap::parser::app_sequence::AppSequence;
use crate::soap::parser::xaddrs::XAddr;
use crate::wsd::device::{DeviceUri, WSDDiscoveredDevice};

/// The most sequences the ordering state tracks across all Target Services, which is WSDAPI's bound.
const MAX_SEQUENCES: usize = 128;

/// The discovered devices, shared by the clients of every interface.
/// It also holds the order of the messages each Target Service sent, see documentation/ws-discovery.pdf, Appendix I.
#[derive(Default)]
pub struct Devices {
    discovered: HashMap<DeviceUri, WSDDiscoveredDevice>,
    /// In insertion order.
    sequences: VecDeque<Sequence>,
    /// The Target Services with a metadata exchange in progress.
    exchanges: HashMap<DeviceUri, Exchanges>,
}

/// The last message of one sequence of the Target Service at `endpoint`.
struct Sequence {
    endpoint: DeviceUri,
    last: AppSequence,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Observation {
    Current,
    /// Older than a message received before it from the same Target Service.
    Stale,
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

    /// Records a Hello or Bye of the Target Service at `endpoint`.
    pub fn observe_announcement(
        &mut self,
        endpoint: &DeviceUri,
        app_sequence: &AppSequence,
    ) -> Observation {
        if self.is_stale(endpoint, app_sequence) {
            return Observation::Stale;
        }

        self.advance(endpoint, app_sequence);

        Observation::Current
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

    /// Forgets the discovered devices, not the order of their messages.
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

    fn is_stale(&self, endpoint: &DeviceUri, app_sequence: &AppSequence) -> bool {
        self.sequences
            .iter()
            .any(|sequence| sequence.endpoint == *endpoint && app_sequence < &sequence.last)
    }

    fn advance(&mut self, endpoint: &DeviceUri, app_sequence: &AppSequence) {
        // replaces in place the newest entry it orders after: its own sequence, or a sequence of an older instance
        if let Some(sequence) = self.sequences.iter_mut().rev().find(|sequence| {
            sequence.endpoint == *endpoint && sequence.last.partial_cmp(app_sequence).is_some()
        }) {
            sequence.last = app_sequence.clone();

            return;
        }

        if self.sequences.len() == MAX_SEQUENCES {
            self.sequences.pop_front();
        }

        self.sequences.push_back(Sequence {
            endpoint: endpoint.clone(),
            last: app_sequence.clone(),
        });
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use pretty_assertions::assert_eq;

    use crate::soap::parser::app_sequence::AppSequence;
    use crate::wsd::device::DeviceUri;
    use crate::wsd::devices::{Devices, MAX_SEQUENCES, Observation};

    fn endpoint(id: usize) -> DeviceUri {
        DeviceUri::new(format!("urn:uuid:00000000-0000-0000-0000-{:012}", id).into_boxed_str())
    }

    fn sequence(instance_id: u64, message_number: u64) -> AppSequence {
        AppSequence::new(instance_id, Some("urn:uuid:a"), message_number)
    }

    fn in_sequence(sequence_id: Option<&str>, message_number: u64) -> AppSequence {
        AppSequence::new(1, sequence_id, message_number)
    }

    #[test]
    fn first_message_is_current() {
        let mut devices = Devices::default();

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &sequence(1, 5)),
            Observation::Current
        );
    }

    #[test]
    fn lower_message_number_is_stale() {
        let mut devices = Devices::default();

        devices.observe_announcement(&endpoint(1), &sequence(1, 5));

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &sequence(1, 4)),
            Observation::Stale
        );
    }

    #[test]
    fn equal_message_is_current() {
        let mut devices = Devices::default();

        devices.observe_announcement(&endpoint(1), &sequence(1, 5));

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &sequence(1, 5)),
            Observation::Current
        );
    }

    #[test]
    fn clear_keeps_the_order() {
        let mut devices = Devices::default();

        devices.observe_announcement(&endpoint(1), &sequence(1, 5));

        devices.clear();

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &sequence(1, 4)),
            Observation::Stale
        );
    }

    #[test]
    fn stale_message_does_not_move_the_last_message() {
        let mut devices = Devices::default();

        devices.observe_announcement(&endpoint(1), &sequence(1, 5));
        devices.observe_announcement(&endpoint(1), &sequence(1, 3));

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &sequence(1, 4)),
            Observation::Stale
        );
    }

    #[test]
    fn lower_instance_is_stale() {
        let mut devices = Devices::default();

        devices.observe_announcement(&endpoint(1), &sequence(2, 0));

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &sequence(1, 9)),
            Observation::Stale
        );
    }

    #[test]
    fn different_sequences_are_current() {
        let mut devices = Devices::default();

        devices.observe_announcement(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 5));

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &in_sequence(Some("urn:uuid:b"), 3)),
            Observation::Current
        );
    }

    #[test]
    fn each_sequence_keeps_its_order() {
        let mut devices = Devices::default();

        devices.observe_announcement(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 5));
        devices.observe_announcement(&endpoint(1), &in_sequence(Some("urn:uuid:b"), 3));

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 4)),
            Observation::Stale
        );
    }

    #[test]
    fn null_sequence_keeps_its_order() {
        let mut devices = Devices::default();

        devices.observe_announcement(&endpoint(1), &in_sequence(None, 5));
        devices.observe_announcement(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 3));

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &in_sequence(None, 4)),
            Observation::Stale
        );

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &in_sequence(Some("urn:uuid:b"), 1)),
            Observation::Current
        );

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 2)),
            Observation::Stale
        );
    }

    #[test]
    fn newer_instance_restarts_the_sequences() {
        let mut devices = Devices::default();

        devices.observe_announcement(&endpoint(1), &AppSequence::new(1, Some("urn:uuid:a"), 5));
        devices.observe_announcement(&endpoint(1), &AppSequence::new(2, Some("urn:uuid:b"), 5));

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &AppSequence::new(2, Some("urn:uuid:a"), 0)),
            Observation::Current
        );

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &AppSequence::new(1, Some("urn:uuid:a"), 9)),
            Observation::Stale
        );
    }

    #[test]
    fn newer_instance_replaces_the_newest_entry_it_orders_after() {
        let mut devices = Devices::default();

        devices.observe_announcement(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:a"), 5));
        devices.observe_announcement(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:b"), 5));

        for id in 1..MAX_SEQUENCES - 1 {
            devices.observe_announcement(&endpoint(id), &sequence(1, 5));
        }

        devices.observe_announcement(&endpoint(0), &AppSequence::new(2, Some("urn:uuid:c"), 0));

        // evicts the entry of sequence a
        devices.observe_announcement(&endpoint(MAX_SEQUENCES - 1), &sequence(1, 5));

        assert_eq!(
            devices.observe_announcement(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:d"), 9)),
            Observation::Stale
        );

        // evicts the entry that sequence c replaced
        devices.observe_announcement(&endpoint(MAX_SEQUENCES), &sequence(1, 5));

        assert_eq!(
            devices.observe_announcement(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:d"), 9)),
            Observation::Current
        );
    }

    #[test]
    fn full_state_forgets_the_first_inserted() {
        let mut devices = Devices::default();

        for id in 0..=MAX_SEQUENCES {
            devices.observe_announcement(&endpoint(id), &sequence(1, 5));
        }

        assert_eq!(
            devices.observe_announcement(&endpoint(1), &sequence(1, 4)),
            Observation::Stale
        );

        assert_eq!(
            devices.observe_announcement(&endpoint(0), &sequence(1, 4)),
            Observation::Current
        );
    }

    #[test]
    fn advanced_entry_keeps_its_place() {
        let mut devices = Devices::default();

        for id in 0..MAX_SEQUENCES {
            devices.observe_announcement(&endpoint(id), &sequence(1, 5));
        }

        devices.observe_announcement(&endpoint(0), &sequence(1, 6));

        devices.observe_announcement(&endpoint(MAX_SEQUENCES), &sequence(1, 5));

        assert_eq!(
            devices.observe_announcement(&endpoint(0), &sequence(1, 5)),
            Observation::Current
        );
    }

    #[test]
    fn bye_during_an_exchange_departs() {
        let mut devices = Devices::default();

        let exchange = devices.start_exchange(&endpoint(1));

        devices.depart(&endpoint(1));

        assert!(devices.finish_exchange(&endpoint(1), exchange));
    }

    #[tokio::test]
    async fn bye_stops_a_running_exchange() {
        let mut devices = Devices::default();

        let exchange = devices.start_exchange(&endpoint(1));

        let (output, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                exchange.run_until_bye(std::future::pending::<()>()),
                async {
                    devices.depart(&endpoint(1));
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

        let before = devices.start_exchange(&endpoint(1));

        devices.depart(&endpoint(1));

        let after = devices.start_exchange(&endpoint(1));

        assert_eq!(before.run_until_bye(async { 1 }).await, None);
        assert_eq!(after.run_until_bye(async { 1 }).await, Some(1));
    }

    #[test]
    fn bye_before_an_exchange_does_not_depart() {
        let mut devices = Devices::default();

        devices.depart(&endpoint(1));

        let exchange = devices.start_exchange(&endpoint(1));

        assert!(!devices.finish_exchange(&endpoint(1), exchange));
    }

    #[test]
    fn exchange_started_after_a_bye_does_not_depart() {
        let mut devices = Devices::default();

        let before = devices.start_exchange(&endpoint(1));

        devices.depart(&endpoint(1));

        let after = devices.start_exchange(&endpoint(1));

        assert!(devices.finish_exchange(&endpoint(1), before));
        assert!(!devices.finish_exchange(&endpoint(1), after));
    }

    #[test]
    fn finished_exchanges_leave_no_state() {
        let mut devices = Devices::default();

        let first = devices.start_exchange(&endpoint(1));
        let second = devices.start_exchange(&endpoint(1));

        devices.depart(&endpoint(1));

        devices.finish_exchange(&endpoint(1), first);

        assert!(devices.has_running_exchanges());

        devices.finish_exchange(&endpoint(1), second);

        assert!(!devices.has_running_exchanges());
    }

    #[test]
    fn bye_without_an_exchange_leaves_no_state() {
        let mut devices = Devices::default();

        devices.depart(&endpoint(1));

        assert!(!devices.has_running_exchanges());
    }
}
