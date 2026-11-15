use std::cmp::Ordering;

use color_eyre::eyre;
use hashbrown::HashMap;
use hashbrown::hash_map::{Entry, EntryRef};
use ringmap::{Equivalent, RingMap};
use tokio_util::sync::CancellationToken;
use vec1::Vec1;

use crate::network_address::NetworkAddress;
use crate::network_interface::NetworkInterface;
use crate::soap::parser::app_sequence::AppSequence;
use crate::soap::parser::xaddrs::XAddr;
use crate::soap::{InstanceId, MessageNumber};
use crate::wsd::device::{DeviceUri, WSDDiscoveredDevice};

/// The most sequences tracked, across all Target Services.
const MAX_SEQUENCES: usize = 128;

/// The discovered devices, shared by the clients of every interface.
/// It also orders the messages of each Target Service, see documentation/ws-discovery.pdf, Appendix I.
#[derive(Default)]
pub(crate) struct Devices {
    discovered: HashMap<DeviceUri, WSDDiscoveredDevice>,
    /// The last `MessageNumber` of each sequence.
    sequences: RingMap<SequenceKey, MessageNumber>,
    /// The Target Services in `sequences`.
    targets: HashMap<DeviceUri, Target>,
    /// The metadata exchanges in progress of each Target Service, by interface index.
    exchanges: HashMap<DeviceUri, HashMap<u32, RunningExchange>>,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct SequenceKey {
    endpoint: DeviceUri,
    instance_id: InstanceId,
    sequence_id: Option<Box<str>>,
}

impl SequenceKey {
    fn new(endpoint: &DeviceUri, app_sequence: &AppSequence) -> Self {
        Self {
            endpoint: endpoint.clone(),
            instance_id: app_sequence.instance_id(),
            sequence_id: app_sequence.sequence_id().map(Box::from),
        }
    }
}

/// Borrows the fields of a `SequenceKey` in the same order, so both hash alike.
#[derive(Hash)]
struct SequenceKeyRef<'a> {
    endpoint: &'a str,
    instance_id: InstanceId,
    sequence_id: Option<&'a str>,
}

impl<'a> SequenceKeyRef<'a> {
    fn new(endpoint: &'a DeviceUri, app_sequence: &'a AppSequence) -> Self {
        Self {
            endpoint,
            instance_id: app_sequence.instance_id(),
            sequence_id: app_sequence.sequence_id(),
        }
    }
}

impl Equivalent<SequenceKey> for SequenceKeyRef<'_> {
    fn equivalent(&self, key: &SequenceKey) -> bool {
        self.endpoint == &*key.endpoint
            && self.instance_id == key.instance_id
            && self.sequence_id == key.sequence_id.as_deref()
    }
}

/// The entries of one Target Service in `sequences`.
struct Target {
    /// The highest `InstanceId`.
    instance_id: InstanceId,
    /// How many entries that instance has.
    current: usize,
    /// How many entries older instances have.
    older: usize,
}

/// A Target Service whose message `Devices::observe` recorded as current.
pub(crate) struct Current<'d> {
    devices: &'d mut Devices,
    endpoint: &'d DeviceUri,
}

/// A metadata exchange in progress on one interface.
struct RunningExchange {
    /// Cancelled by a Bye on the interface and then replaced, so a rerun queued after the Bye runs.
    bye: CancellationToken,
    /// The `XAddrs` of the last trigger that arrived while the exchange ran.
    rerun: Option<Vec1<XAddr>>,
}

/// The result of `Current::depart`.
pub(crate) enum Departure {
    /// No device is recorded.
    Unknown,
    /// The device has addresses on other interfaces, and is kept.
    Kept,
    /// The device had no addresses on other interfaces, and is removed.
    Removed,
}

/// A metadata exchange started with `Current::start_exchange`.
pub(crate) struct Exchange {
    endpoint: DeviceUri,
    bye: CancellationToken,
    interface_index: u32,
}

/// A metadata exchange to run, and the `XAddrs` it fetches from.
pub(crate) struct Fetch {
    pub exchange: Exchange,
    pub xaddrs: Vec1<XAddr>,
}

impl Exchange {
    /// The Target Service whose metadata the exchange fetches.
    pub(crate) fn endpoint(&self) -> &DeviceUri {
        &self.endpoint
    }

    /// A Bye of the Target Service arrived on the interface of the exchange since the exchange started.
    pub(crate) fn departed(&self) -> bool {
        self.bye.is_cancelled()
    }

    /// Runs `future` unless a Bye of the Target Service arrives on the interface of the exchange first, then returns `None`.
    pub(crate) async fn run_until_bye<F: Future>(&self, future: F) -> Option<F::Output> {
        self.bye.run_until_cancelled(future).await
    }
}

impl Current<'_> {
    /// Starts a metadata exchange with the Target Service on the interface with `interface_index`.
    /// Returns `None` while one already runs there, that one then runs once more with `xaddrs`.
    pub(crate) fn start_exchange(self, interface_index: u32, xaddrs: Vec1<XAddr>) -> Option<Fetch> {
        let running = match self.devices.exchanges.entry_ref(self.endpoint) {
            EntryRef::Occupied(occupied_entry) => occupied_entry.into_mut(),
            EntryRef::Vacant(vacant_entry_ref) => {
                vacant_entry_ref.insert_with_key(self.endpoint.clone(), HashMap::new())
            },
        };

        match running.entry(interface_index) {
            Entry::Occupied(mut occupied_entry) => {
                occupied_entry.get_mut().rerun = Some(xaddrs);

                None
            },
            Entry::Vacant(vacant_entry) => {
                let running_exchange = vacant_entry.insert(RunningExchange {
                    bye: CancellationToken::new(),
                    rerun: None,
                });

                Some(Fetch {
                    exchange: Exchange {
                        endpoint: self.endpoint.clone(),
                        bye: running_exchange.bye.clone(),
                        interface_index,
                    },
                    xaddrs,
                })
            },
        }
    }

    /// Removes the addresses of the device on `interface`, stops its metadata exchange on `interface`, and drops the pending rerun of that exchange.
    /// The addresses on other interfaces stay, because a Target Service sends a Bye when it leaves a network, see documentation/ws-discovery.pdf, 4.2.
    /// Removes the device once no addresses remain.
    pub(crate) fn depart(self, interface: &NetworkInterface) -> Departure {
        if let Some(running_exchange) = self
            .devices
            .exchanges
            .get_mut(self.endpoint)
            .and_then(|running| running.get_mut(&interface.index()))
        {
            std::mem::take(&mut running_exchange.bye).cancel();

            running_exchange.rerun = None;
        }

        let EntryRef::Occupied(mut occupied_entry) =
            self.devices.discovered.entry_ref(self.endpoint)
        else {
            return Departure::Unknown;
        };

        if occupied_entry.get_mut().leave(interface) {
            Departure::Kept
        } else {
            occupied_entry.remove();

            Departure::Removed
        }
    }
}

impl Devices {
    /// Ends `exchange`, and returns the exchange to run next, for the triggers that arrived while it ran.
    pub(crate) fn finish_exchange(
        &mut self,
        Exchange {
            endpoint,
            interface_index,
            ..
        }: Exchange,
    ) -> Option<Fetch> {
        let EntryRef::Occupied(mut occupied_entry) = self.exchanges.entry_ref(&endpoint) else {
            return None;
        };

        let running = occupied_entry.get_mut();

        let pending = running
            .get_mut(&interface_index)
            .and_then(|running_exchange| {
                running_exchange
                    .rerun
                    .take()
                    .map(|xaddrs| (running_exchange.bye.clone(), xaddrs))
            });

        let Some((bye, xaddrs)) = pending else {
            running.remove(&interface_index);

            if running.is_empty() {
                occupied_entry.remove();
            }

            return None;
        };

        Some(Fetch {
            exchange: Exchange {
                endpoint,
                bye,
                interface_index,
            },
            xaddrs,
        })
    }

    /// Ends `exchange`, and drops its pending rerun.
    pub(crate) fn cancel_exchange(
        &mut self,
        Exchange {
            endpoint,
            interface_index,
            ..
        }: Exchange,
    ) {
        let EntryRef::Occupied(mut occupied_entry) = self.exchanges.entry_ref(&endpoint) else {
            return;
        };

        let running = occupied_entry.get_mut();

        running.remove(&interface_index);

        if running.is_empty() {
            occupied_entry.remove();
        }
    }

    /// Records the `AppSequence` of a message of the Target Service at `endpoint`, unless it is older than the recorded order.
    /// Returns `None` for an older message.
    pub(crate) fn observe<'d>(
        &'d mut self,
        endpoint: &'d DeviceUri,
        app_sequence: &AppSequence,
    ) -> Option<Current<'d>> {
        let take_over = match self.targets.get_mut(endpoint) {
            None => false,
            Some(target) => match app_sequence.instance_id().cmp(&target.instance_id) {
                Ordering::Less => return None,
                Ordering::Equal => {
                    let key = SequenceKeyRef::new(endpoint, app_sequence);

                    if let Some(last) = self.sequences.get_mut(&key) {
                        if app_sequence.message_number() < *last {
                            return None;
                        }

                        *last = app_sequence.message_number();

                        return Some(Current {
                            devices: self,
                            endpoint,
                        });
                    }

                    target.older > 0
                },
                Ordering::Greater => {
                    target.instance_id = app_sequence.instance_id();
                    target.older += target.current;
                    target.current = 0;

                    true
                },
            },
        };

        if take_over {
            self.take_over(endpoint, app_sequence);
        } else {
            self.push(endpoint, app_sequence);
        }

        Some(Current {
            devices: self,
            endpoint,
        })
    }

    /// Records a `ProbeMatch` or `ResolveMatch` of the Target Service at `endpoint`.
    /// A match is never stale, and an older one leaves the order as it is.
    pub(crate) fn observe_match<'d>(
        &'d mut self,
        endpoint: &'d DeviceUri,
        app_sequence: &AppSequence,
    ) -> Current<'d> {
        self.observe(endpoint, app_sequence);

        Current {
            devices: self,
            endpoint,
        }
    }

    pub(crate) fn store(
        &mut self,
        endpoint: &DeviceUri,
        meta: &[u8],
        xaddr: &XAddr,
        bound_to: &NetworkAddress,
    ) -> Result<(), eyre::Report> {
        match self.discovered.entry_ref(endpoint) {
            EntryRef::Occupied(occupied_entry) => {
                occupied_entry
                    .into_mut()
                    .update(endpoint, meta, xaddr, bound_to)?;
            },
            EntryRef::Vacant(vacant_entry_ref) => {
                let new = WSDDiscoveredDevice::new(endpoint, meta, xaddr, bound_to)?;

                vacant_entry_ref.insert_with_key(endpoint.clone(), new);
            },
        }

        Ok(())
    }

    pub(crate) fn clear_discovered(&mut self) {
        self.discovered.clear();
    }

    /// Removes the addresses on `interface` from every device, and removes the devices without addresses on other interfaces.
    pub(crate) fn forget_interface(&mut self, interface: &NetworkInterface) {
        self.discovered.retain(|_, device| device.leave(interface));
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = (&DeviceUri, &WSDDiscoveredDevice)> {
        self.discovered.iter()
    }

    #[cfg(test)]
    pub(crate) fn get(&self, endpoint: &DeviceUri) -> Option<&WSDDiscoveredDevice> {
        self.discovered.get(endpoint)
    }

    #[cfg(test)]
    pub(crate) fn contains_key(&self, endpoint: &DeviceUri) -> bool {
        self.discovered.contains_key(endpoint)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.discovered.is_empty()
    }

    #[cfg(test)]
    pub(crate) fn has_running_exchanges(&self) -> bool {
        !self.exchanges.is_empty()
    }

    /// Replaces the newest entry of an older instance of the Target Service at `endpoint`, in place.
    fn take_over(&mut self, endpoint: &DeviceUri, app_sequence: &AppSequence) {
        let index = self
            .sequences
            .iter()
            .rposition(|(key, _)| {
                key.endpoint == *endpoint && key.instance_id < app_sequence.instance_id()
            })
            .expect("`Target::older` counts an entry of an older instance");

        self.sequences
            .replace_index(index, SequenceKey::new(endpoint, app_sequence))
            .expect("the key is not in `sequences`");

        self.sequences[index] = app_sequence.message_number();

        let target = self
            .targets
            .get_mut(endpoint)
            .expect("`take_over` replaces an entry of a known Target Service");

        target.older -= 1;
        target.current += 1;
    }

    fn push(&mut self, endpoint: &DeviceUri, app_sequence: &AppSequence) {
        if self.sequences.len() == MAX_SEQUENCES
            && let Some((evicted, _)) = self.sequences.pop_front()
        {
            self.forget(&evicted);
        }

        self.sequences.push_back(
            SequenceKey::new(endpoint, app_sequence),
            app_sequence.message_number(),
        );

        match self.targets.entry_ref(endpoint) {
            EntryRef::Occupied(occupied_entry) => occupied_entry.into_mut().current += 1,
            EntryRef::Vacant(vacant_entry_ref) => {
                vacant_entry_ref.insert_with_key(
                    endpoint.clone(),
                    Target {
                        instance_id: app_sequence.instance_id(),
                        current: 1,
                        older: 0,
                    },
                );
            },
        }
    }

    fn forget(&mut self, evicted: &SequenceKey) {
        let target = self
            .targets
            .get_mut(&evicted.endpoint)
            .expect("every entry in `sequences` has a `Target`");

        if evicted.instance_id < target.instance_id {
            target.older -= 1;
        } else {
            target.current -= 1;
        }

        if target.current == 0 && target.older == 0 {
            self.targets.remove(&evicted.endpoint);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use libc::RT_SCOPE_SITE;
    use pretty_assertions::assert_eq;
    use url::Url;
    use vec1::{Vec1, vec1};

    use crate::network_address::NetworkAddress;
    use crate::network_interface::NetworkInterface;
    use crate::soap::parser::app_sequence::AppSequence;
    use crate::soap::parser::xaddrs::XAddr;
    use crate::test_utils::synology_metadata;
    use crate::wsd::device::DeviceUri;
    use crate::wsd::devices::{Devices, Exchange, Fetch, MAX_SEQUENCES};

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

        assert!(devices.observe(&endpoint(1), &sequence(1, 5)).is_some());
    }

    #[test]
    fn lower_message_number_is_stale() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(1, 5));

        assert!(devices.observe(&endpoint(1), &sequence(1, 4)).is_none());
    }

    #[test]
    fn equal_message_is_current() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(1, 5));

        assert!(devices.observe(&endpoint(1), &sequence(1, 5)).is_some());
    }

    #[test]
    fn clear_discovered_keeps_the_order() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(1, 5));

        devices.clear_discovered();

        assert!(devices.observe(&endpoint(1), &sequence(1, 4)).is_none());
    }

    #[test]
    fn stale_message_does_not_move_the_last_message() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(1, 5));
        devices.observe(&endpoint(1), &sequence(1, 3));

        assert!(devices.observe(&endpoint(1), &sequence(1, 4)).is_none());
    }

    #[test]
    fn lower_instance_is_stale() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(2, 0));

        assert!(devices.observe(&endpoint(1), &sequence(1, 9)).is_none());
    }

    #[test]
    fn different_sequences_are_current() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 5));

        assert!(
            devices
                .observe(&endpoint(1), &in_sequence(Some("urn:uuid:b"), 3))
                .is_some()
        );
    }

    #[test]
    fn each_sequence_keeps_its_order() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 5));
        devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:b"), 3));

        assert!(
            devices
                .observe(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 4))
                .is_none()
        );
    }

    #[test]
    fn null_sequence_keeps_its_order() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &in_sequence(None, 5));
        devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 3));

        assert!(
            devices
                .observe(&endpoint(1), &in_sequence(None, 4))
                .is_none()
        );

        assert!(
            devices
                .observe(&endpoint(1), &in_sequence(Some("urn:uuid:b"), 1))
                .is_some()
        );

        assert!(
            devices
                .observe(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 2))
                .is_none()
        );
    }

    #[test]
    fn newer_instance_restarts_the_sequences() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &AppSequence::new(1, Some("urn:uuid:a"), 5));
        devices.observe(&endpoint(1), &AppSequence::new(2, Some("urn:uuid:b"), 5));

        assert!(
            devices
                .observe(&endpoint(1), &AppSequence::new(2, Some("urn:uuid:a"), 0))
                .is_some()
        );

        assert!(
            devices
                .observe(&endpoint(1), &AppSequence::new(1, Some("urn:uuid:a"), 9))
                .is_none()
        );
    }

    #[test]
    fn newer_instance_replaces_the_newest_entry_it_orders_after() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:a"), 5));
        devices.observe(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:b"), 5));

        for id in 1..MAX_SEQUENCES - 1 {
            devices.observe(&endpoint(id), &sequence(1, 5));
        }

        devices.observe(&endpoint(0), &AppSequence::new(2, Some("urn:uuid:c"), 0));

        // evicts the entry of sequence a
        devices.observe(&endpoint(MAX_SEQUENCES - 1), &sequence(1, 5));

        assert!(
            devices
                .observe(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:d"), 9))
                .is_none()
        );

        // evicts the entry that sequence c replaced
        devices.observe(&endpoint(MAX_SEQUENCES), &sequence(1, 5));

        assert!(
            devices
                .observe(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:d"), 9))
                .is_some()
        );
    }

    #[test]
    fn new_sequence_takes_over_an_older_instance_entry() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:a"), 5));
        devices.observe(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:b"), 5));

        for id in 1..MAX_SEQUENCES - 1 {
            devices.observe(&endpoint(id), &sequence(1, 5));
        }

        // takes over the entry of sequence b
        devices.observe(&endpoint(0), &AppSequence::new(2, Some("urn:uuid:c"), 5));

        // takes over the entry of sequence a, the first inserted
        devices.observe(&endpoint(0), &AppSequence::new(2, Some("urn:uuid:d"), 0));

        // evicts the entry of sequence d
        devices.observe(&endpoint(MAX_SEQUENCES - 1), &sequence(1, 5));

        assert!(
            devices
                .observe(&endpoint(0), &AppSequence::new(2, Some("urn:uuid:c"), 4))
                .is_none()
        );
    }

    #[test]
    fn second_newer_instance_counts_every_older_entry() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:a"), 5));
        devices.observe(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:b"), 5));

        // takes over the entry of sequence b
        devices.observe(&endpoint(0), &AppSequence::new(2, Some("urn:uuid:c"), 5));

        // takes over the entry of sequence c, the entry of sequence a stays
        devices.observe(&endpoint(0), &AppSequence::new(3, Some("urn:uuid:d"), 5));

        // the last one evicts the entry of sequence a
        for id in 1..MAX_SEQUENCES {
            devices.observe(&endpoint(id), &sequence(1, 5));
        }

        assert!(
            devices
                .observe(&endpoint(0), &AppSequence::new(3, Some("urn:uuid:d"), 4))
                .is_none()
        );
    }

    #[test]
    fn full_state_forgets_the_first_inserted() {
        let mut devices = Devices::default();

        for id in 0..=MAX_SEQUENCES {
            devices.observe(&endpoint(id), &sequence(1, 5));
        }

        assert!(devices.observe(&endpoint(1), &sequence(1, 4)).is_none());

        assert!(devices.observe(&endpoint(0), &sequence(1, 4)).is_some());
    }

    #[test]
    fn advanced_entry_keeps_its_place() {
        let mut devices = Devices::default();

        for id in 0..MAX_SEQUENCES {
            devices.observe(&endpoint(id), &sequence(1, 5));
        }

        devices.observe(&endpoint(0), &sequence(1, 6));

        devices.observe(&endpoint(MAX_SEQUENCES), &sequence(1, 5));

        assert!(devices.observe(&endpoint(0), &sequence(1, 5)).is_some());
    }

    #[test]
    fn newer_match_advances_the_order() {
        let mut devices = Devices::default();

        devices.observe_match(&endpoint(1), &sequence(1, 7));

        assert!(devices.observe(&endpoint(1), &sequence(1, 6)).is_none());
    }

    #[test]
    fn older_match_leaves_the_order() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(1, 10));

        devices.observe_match(&endpoint(1), &sequence(1, 5));

        assert!(devices.observe(&endpoint(1), &sequence(1, 7)).is_none());
    }

    fn xaddrs(path: &str) -> Vec1<XAddr> {
        vec1![XAddr::try_from(format!("http://192.168.100.5:5357/{}", path).as_str()).unwrap()]
    }

    fn urls(xaddrs: &[XAddr]) -> Vec<&Url> {
        xaddrs.iter().map(XAddr::url).collect()
    }

    fn trigger(devices: &mut Devices, interface_index: u32, path: &str) -> Option<Fetch> {
        devices
            .observe_match(&endpoint(1), &sequence(1, 5))
            .start_exchange(interface_index, xaddrs(path))
    }

    fn start(devices: &mut Devices, interface_index: u32) -> Exchange {
        let Fetch { exchange, .. } =
            trigger(devices, interface_index, "first").expect("no exchange runs on this interface");

        exchange
    }

    fn interface(interface_index: u32) -> NetworkInterface {
        NetworkInterface::new_with_index(
            format!("eth{}", interface_index),
            RT_SCOPE_SITE,
            interface_index,
        )
    }

    fn depart(devices: &mut Devices, interface_index: u32) {
        devices
            .observe(&endpoint(1), &sequence(1, 5))
            .expect("a Bye equal to the last message is current")
            .depart(&interface(interface_index));
    }

    /// Stores the device at `endpoint(1)` with an address on the interface with `interface_index`.
    fn store(devices: &mut Devices, interface_index: u32) {
        let bound_to = NetworkAddress::new(
            "192.0.2.1/24".parse().unwrap(),
            Arc::new(interface(interface_index)),
        );

        devices
            .store(
                &endpoint(1),
                synology_metadata().as_bytes(),
                &XAddr::try_from("http://diskstation:5357/2e91b960-d258-43d6-989b-a24f108f1721")
                    .unwrap(),
                &bound_to,
            )
            .unwrap();
    }

    #[test]
    fn bye_during_an_exchange_departs() {
        let mut devices = Devices::default();

        let exchange = start(&mut devices, 1);

        depart(&mut devices, 1);

        assert!(exchange.departed());
    }

    #[tokio::test]
    async fn bye_stops_a_running_exchange() {
        let mut devices = Devices::default();

        let exchange = start(&mut devices, 1);

        let (output, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(
                exchange.run_until_bye(std::future::pending::<()>()),
                async {
                    depart(&mut devices, 1);
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

        let before = start(&mut devices, 1);

        depart(&mut devices, 1);

        let after = start(&mut devices, 2);

        assert_eq!(before.run_until_bye(async { 1 }).await, None);
        assert_eq!(after.run_until_bye(async { 1 }).await, Some(1));
    }

    #[test]
    fn bye_before_an_exchange_does_not_depart() {
        let mut devices = Devices::default();

        depart(&mut devices, 1);

        let exchange = start(&mut devices, 1);

        assert!(!exchange.departed());
    }

    #[test]
    fn exchange_started_after_a_bye_does_not_depart() {
        let mut devices = Devices::default();

        let before = start(&mut devices, 1);

        depart(&mut devices, 1);

        let after = start(&mut devices, 2);

        assert!(before.departed());
        assert!(!after.departed());
    }

    #[test]
    fn finished_exchanges_leave_no_state() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);
        let second = start(&mut devices, 2);

        depart(&mut devices, 1);

        devices.finish_exchange(first);

        assert!(devices.has_running_exchanges());

        devices.finish_exchange(second);

        assert!(!devices.has_running_exchanges());
    }

    #[test]
    fn bye_without_an_exchange_leaves_no_state() {
        let mut devices = Devices::default();

        depart(&mut devices, 1);

        assert!(!devices.has_running_exchanges());
    }

    #[test]
    fn exchanges_on_different_interfaces_run_side_by_side() {
        let mut devices = Devices::default();

        let _first = start(&mut devices, 1);

        assert!(trigger(&mut devices, 2, "second").is_some());
    }

    #[test]
    fn bye_keeps_the_exchange_on_another_interface() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);
        let second = start(&mut devices, 2);

        depart(&mut devices, 1);

        assert!(first.departed());
        assert!(!second.departed());
    }

    #[test]
    fn bye_keeps_the_rerun_on_another_interface() {
        let mut devices = Devices::default();

        let _first = start(&mut devices, 1);
        let second = start(&mut devices, 2);

        assert!(trigger(&mut devices, 2, "second").is_none());

        depart(&mut devices, 1);

        assert!(devices.finish_exchange(second).is_some());
    }

    #[test]
    fn forgetting_an_interface_keeps_the_addresses_on_another_interface() {
        let mut devices = Devices::default();

        store(&mut devices, 1);
        store(&mut devices, 2);

        devices.forget_interface(&interface(1));

        let interfaces = devices.get(&endpoint(1)).map(|device| {
            device
                .addresses()
                .keys()
                .map(|name| &**name)
                .collect::<Vec<_>>()
        });

        assert_eq!(interfaces, Some(vec!["eth2"]));
    }

    #[test]
    fn forgetting_the_last_interface_of_a_device_removes_it() {
        let mut devices = Devices::default();

        store(&mut devices, 1);

        devices.forget_interface(&interface(1));

        assert!(!devices.contains_key(&endpoint(1)));
    }

    #[test]
    fn triggers_during_an_exchange_rerun_it_once_with_the_last_xaddrs() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);

        assert!(trigger(&mut devices, 1, "second").is_none());
        assert!(trigger(&mut devices, 1, "third").is_none());

        let Fetch {
            exchange: rerun,
            xaddrs: rerun_xaddrs,
        } = devices
            .finish_exchange(first)
            .expect("triggers arrived while the exchange ran");

        assert_eq!(urls(&rerun_xaddrs), urls(&xaddrs("third")));

        assert!(devices.finish_exchange(rerun).is_none());

        assert!(!devices.has_running_exchanges());
    }

    #[test]
    fn bye_drops_the_rerun_of_an_earlier_trigger() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);

        assert!(trigger(&mut devices, 1, "second").is_none());

        depart(&mut devices, 1);

        assert!(first.departed());
        assert!(devices.finish_exchange(first).is_none());

        assert!(!devices.has_running_exchanges());
    }

    #[test]
    fn cancelled_exchange_frees_its_slot_and_drops_its_rerun() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);

        assert!(trigger(&mut devices, 1, "second").is_none());

        devices.cancel_exchange(first);

        assert!(!devices.has_running_exchanges());

        assert!(trigger(&mut devices, 1, "third").is_some());
    }

    #[tokio::test]
    async fn trigger_after_a_bye_reruns() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);

        depart(&mut devices, 1);

        assert!(trigger(&mut devices, 1, "second").is_none());

        assert!(first.departed());

        let Fetch {
            exchange: rerun, ..
        } = devices
            .finish_exchange(first)
            .expect("a trigger arrived after the Bye");

        assert_eq!(rerun.run_until_bye(async { 1 }).await, Some(1));
    }
}
