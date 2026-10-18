use std::cmp::Ordering;

use color_eyre::eyre;
use hashbrown::HashMap;
use hashbrown::hash_map::{Entry, EntryRef};
use ringmap::{Equivalent, RingMap};
use tokio_util::sync::CancellationToken;

use crate::network_address::NetworkAddress;
use crate::soap::parser::app_sequence::AppSequence;
use crate::soap::parser::xaddrs::XAddr;
use crate::wsd::device::{DeviceUri, WSDDiscoveredDevice};

/// The most sequences tracked, across all Target Services.
const MAX_SEQUENCES: usize = 128;

/// The discovered devices, shared by the clients of every interface.
/// It also orders the messages of each Target Service, see documentation/ws-discovery.pdf, Appendix I.
#[derive(Default)]
pub struct Devices {
    discovered: HashMap<DeviceUri, WSDDiscoveredDevice>,
    /// The last `MessageNumber` of each sequence.
    sequences: RingMap<SequenceKey, u64>,
    /// The Target Services in `sequences`.
    targets: HashMap<DeviceUri, Target>,
    /// The Target Services with a metadata exchange in progress.
    exchanges: HashMap<DeviceUri, Exchanges>,
}

#[derive(Debug, Hash, PartialEq, Eq)]
struct SequenceKey {
    endpoint: DeviceUri,
    instance_id: u64,
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
    instance_id: u64,
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
    instance_id: u64,
    /// How many entries that instance has.
    current: usize,
    /// How many entries older instances have.
    older: usize,
}

#[derive(Debug, PartialEq)]
pub enum Observation {
    Current,
    /// Older than an earlier message of the same Target Service.
    Stale,
}

#[derive(Default)]
struct Exchanges {
    /// Cancelled by a Bye and then replaced, so an exchange that starts after the Bye runs.
    bye: CancellationToken,
    /// The interface index of each running exchange, with the `XAddrs` of the last trigger that arrived while it ran.
    running: HashMap<u32, Option<Vec<XAddr>>>,
}

/// A metadata exchange started with `Devices::start_exchange`.
pub struct Exchange {
    bye: CancellationToken,
    interface_index: u32,
}

/// A metadata exchange to run, and the `XAddrs` it fetches from.
pub struct Fetch {
    pub exchange: Exchange,
    pub xaddrs: Vec<XAddr>,
}

/// The outcome of `Devices::finish_exchange`.
pub struct Finished {
    /// The Target Service sent a Bye while the exchange ran.
    pub departed: bool,
    /// The exchange to run next, for the triggers that arrived while it ran.
    pub rerun: Option<Fetch>,
}

impl Exchange {
    /// Runs `future` unless the Target Service sends a Bye first, then returns `None`.
    pub async fn run_until_bye<F: Future>(&self, future: F) -> Option<F::Output> {
        self.bye.run_until_cancelled(future).await
    }
}

impl Devices {
    /// Starts a metadata exchange with the Target Service at `endpoint` on the interface with `interface_index`.
    /// Returns `None` while one already runs there, that one then runs once more with `xaddrs`.
    pub fn start_exchange(
        &mut self,
        endpoint: &DeviceUri,
        interface_index: u32,
        xaddrs: Vec<XAddr>,
    ) -> Option<Fetch> {
        let exchanges = match self.exchanges.entry_ref(endpoint) {
            EntryRef::Occupied(occupied_entry) => occupied_entry.into_mut(),
            EntryRef::Vacant(vacant_entry_ref) => {
                vacant_entry_ref.insert_with_key(endpoint.clone(), Exchanges::default())
            },
        };

        match exchanges.running.entry(interface_index) {
            Entry::Occupied(mut occupied_entry) => {
                *occupied_entry.get_mut() = Some(xaddrs);

                None
            },
            Entry::Vacant(vacant_entry) => {
                vacant_entry.insert(None);

                Some(Fetch {
                    exchange: Exchange {
                        bye: exchanges.bye.clone(),
                        interface_index,
                    },
                    xaddrs,
                })
            },
        }
    }

    pub fn finish_exchange(
        &mut self,
        endpoint: &DeviceUri,
        Exchange {
            bye,
            interface_index,
        }: Exchange,
    ) -> Finished {
        let departed = bye.is_cancelled();

        let EntryRef::Occupied(mut occupied_entry) = self.exchanges.entry_ref(endpoint) else {
            return Finished {
                departed,
                rerun: None,
            };
        };

        let exchanges = occupied_entry.get_mut();

        let pending = exchanges
            .running
            .get_mut(&interface_index)
            .and_then(Option::take);

        let Some(xaddrs) = pending else {
            exchanges.running.remove(&interface_index);

            if exchanges.running.is_empty() {
                occupied_entry.remove();
            }

            return Finished {
                departed,
                rerun: None,
            };
        };

        Finished {
            departed,
            rerun: Some(Fetch {
                exchange: Exchange {
                    bye: exchanges.bye.clone(),
                    interface_index,
                },
                xaddrs,
            }),
        }
    }

    /// Ends `exchange` of the Target Service at `endpoint`, and drops its pending rerun.
    pub fn cancel_exchange(
        &mut self,
        endpoint: &DeviceUri,
        Exchange {
            interface_index, ..
        }: Exchange,
    ) {
        let EntryRef::Occupied(mut occupied_entry) = self.exchanges.entry_ref(endpoint) else {
            return;
        };

        let running = &mut occupied_entry.get_mut().running;

        running.remove(&interface_index);

        if running.is_empty() {
            occupied_entry.remove();
        }
    }

    /// Records the `AppSequence` of a message of the Target Service at `endpoint`, unless it is older than the recorded order.
    pub fn observe(&mut self, endpoint: &DeviceUri, app_sequence: &AppSequence) -> Observation {
        let take_over = match self.targets.get_mut(endpoint) {
            None => false,
            Some(target) => match app_sequence.instance_id().cmp(&target.instance_id) {
                Ordering::Less => return Observation::Stale,
                Ordering::Equal => {
                    let key = SequenceKeyRef::new(endpoint, app_sequence);

                    if let Some(last) = self.sequences.get_mut(&key) {
                        if app_sequence.message_number() < *last {
                            return Observation::Stale;
                        }

                        *last = app_sequence.message_number();

                        return Observation::Current;
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

        Observation::Current
    }

    /// Records a `ProbeMatch` or `ResolveMatch` of the Target Service at `endpoint`.
    /// A match is never stale, and an older one leaves the order as it is.
    pub fn observe_match(&mut self, endpoint: &DeviceUri, app_sequence: &AppSequence) {
        self.observe(endpoint, app_sequence);
    }

    pub fn store(
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

    /// Removes the device at `endpoint`, stops its running metadata exchanges, and drops their pending reruns.
    pub fn depart(&mut self, endpoint: &DeviceUri) -> Option<WSDDiscoveredDevice> {
        if let Some(exchanges) = self.exchanges.get_mut(endpoint) {
            std::mem::take(&mut exchanges.bye).cancel();

            for rerun in exchanges.running.values_mut() {
                *rerun = None;
            }
        }

        self.discovered.remove(endpoint)
    }

    pub fn clear_discovered(&mut self) {
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
    use std::time::Duration;

    use pretty_assertions::assert_eq;
    use url::Url;

    use crate::soap::parser::app_sequence::AppSequence;
    use crate::soap::parser::xaddrs::XAddr;
    use crate::wsd::device::DeviceUri;
    use crate::wsd::devices::{Devices, Exchange, Fetch, MAX_SEQUENCES, Observation};

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
            devices.observe(&endpoint(1), &sequence(1, 5)),
            Observation::Current
        );
    }

    #[test]
    fn lower_message_number_is_stale() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(1, 5));

        assert_eq!(
            devices.observe(&endpoint(1), &sequence(1, 4)),
            Observation::Stale
        );
    }

    #[test]
    fn equal_message_is_current() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(1, 5));

        assert_eq!(
            devices.observe(&endpoint(1), &sequence(1, 5)),
            Observation::Current
        );
    }

    #[test]
    fn clear_discovered_keeps_the_order() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(1, 5));

        devices.clear_discovered();

        assert_eq!(
            devices.observe(&endpoint(1), &sequence(1, 4)),
            Observation::Stale
        );
    }

    #[test]
    fn stale_message_does_not_move_the_last_message() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(1, 5));
        devices.observe(&endpoint(1), &sequence(1, 3));

        assert_eq!(
            devices.observe(&endpoint(1), &sequence(1, 4)),
            Observation::Stale
        );
    }

    #[test]
    fn lower_instance_is_stale() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(2, 0));

        assert_eq!(
            devices.observe(&endpoint(1), &sequence(1, 9)),
            Observation::Stale
        );
    }

    #[test]
    fn different_sequences_are_current() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 5));

        assert_eq!(
            devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:b"), 3)),
            Observation::Current
        );
    }

    #[test]
    fn each_sequence_keeps_its_order() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 5));
        devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:b"), 3));

        assert_eq!(
            devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 4)),
            Observation::Stale
        );
    }

    #[test]
    fn null_sequence_keeps_its_order() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &in_sequence(None, 5));
        devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 3));

        assert_eq!(
            devices.observe(&endpoint(1), &in_sequence(None, 4)),
            Observation::Stale
        );

        assert_eq!(
            devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:b"), 1)),
            Observation::Current
        );

        assert_eq!(
            devices.observe(&endpoint(1), &in_sequence(Some("urn:uuid:a"), 2)),
            Observation::Stale
        );
    }

    #[test]
    fn newer_instance_restarts_the_sequences() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &AppSequence::new(1, Some("urn:uuid:a"), 5));
        devices.observe(&endpoint(1), &AppSequence::new(2, Some("urn:uuid:b"), 5));

        assert_eq!(
            devices.observe(&endpoint(1), &AppSequence::new(2, Some("urn:uuid:a"), 0)),
            Observation::Current
        );

        assert_eq!(
            devices.observe(&endpoint(1), &AppSequence::new(1, Some("urn:uuid:a"), 9)),
            Observation::Stale
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

        assert_eq!(
            devices.observe(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:d"), 9)),
            Observation::Stale
        );

        // evicts the entry that sequence c replaced
        devices.observe(&endpoint(MAX_SEQUENCES), &sequence(1, 5));

        assert_eq!(
            devices.observe(&endpoint(0), &AppSequence::new(1, Some("urn:uuid:d"), 9)),
            Observation::Current
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

        assert_eq!(
            devices.observe(&endpoint(0), &AppSequence::new(2, Some("urn:uuid:c"), 4)),
            Observation::Stale
        );
    }

    #[test]
    fn full_state_forgets_the_first_inserted() {
        let mut devices = Devices::default();

        for id in 0..=MAX_SEQUENCES {
            devices.observe(&endpoint(id), &sequence(1, 5));
        }

        assert_eq!(
            devices.observe(&endpoint(1), &sequence(1, 4)),
            Observation::Stale
        );

        assert_eq!(
            devices.observe(&endpoint(0), &sequence(1, 4)),
            Observation::Current
        );
    }

    #[test]
    fn advanced_entry_keeps_its_place() {
        let mut devices = Devices::default();

        for id in 0..MAX_SEQUENCES {
            devices.observe(&endpoint(id), &sequence(1, 5));
        }

        devices.observe(&endpoint(0), &sequence(1, 6));

        devices.observe(&endpoint(MAX_SEQUENCES), &sequence(1, 5));

        assert_eq!(
            devices.observe(&endpoint(0), &sequence(1, 5)),
            Observation::Current
        );
    }

    #[test]
    fn newer_match_advances_the_order() {
        let mut devices = Devices::default();

        devices.observe_match(&endpoint(1), &sequence(1, 7));

        assert_eq!(
            devices.observe(&endpoint(1), &sequence(1, 6)),
            Observation::Stale
        );
    }

    #[test]
    fn older_match_leaves_the_order() {
        let mut devices = Devices::default();

        devices.observe(&endpoint(1), &sequence(1, 10));

        devices.observe_match(&endpoint(1), &sequence(1, 5));

        assert_eq!(
            devices.observe(&endpoint(1), &sequence(1, 7)),
            Observation::Stale
        );
    }

    fn xaddrs(path: &str) -> Vec<XAddr> {
        vec![XAddr::try_from(format!("http://192.168.100.5:5357/{}", path).as_str()).unwrap()]
    }

    fn urls(xaddrs: &[XAddr]) -> Vec<&Url> {
        xaddrs.iter().map(XAddr::url).collect()
    }

    fn start(devices: &mut Devices, interface_index: u32) -> Exchange {
        let Fetch { exchange, .. } = devices
            .start_exchange(&endpoint(1), interface_index, xaddrs("first"))
            .expect("no exchange runs on this interface");

        exchange
    }

    #[test]
    fn bye_during_an_exchange_departs() {
        let mut devices = Devices::default();

        let exchange = start(&mut devices, 1);

        devices.depart(&endpoint(1));

        assert!(devices.finish_exchange(&endpoint(1), exchange).departed);
    }

    #[tokio::test]
    async fn bye_stops_a_running_exchange() {
        let mut devices = Devices::default();

        let exchange = start(&mut devices, 1);

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

        let before = start(&mut devices, 1);

        devices.depart(&endpoint(1));

        let after = start(&mut devices, 2);

        assert_eq!(before.run_until_bye(async { 1 }).await, None);
        assert_eq!(after.run_until_bye(async { 1 }).await, Some(1));
    }

    #[test]
    fn bye_before_an_exchange_does_not_depart() {
        let mut devices = Devices::default();

        devices.depart(&endpoint(1));

        let exchange = start(&mut devices, 1);

        assert!(!devices.finish_exchange(&endpoint(1), exchange).departed);
    }

    #[test]
    fn exchange_started_after_a_bye_does_not_depart() {
        let mut devices = Devices::default();

        let before = start(&mut devices, 1);

        devices.depart(&endpoint(1));

        let after = start(&mut devices, 2);

        assert!(devices.finish_exchange(&endpoint(1), before).departed);
        assert!(!devices.finish_exchange(&endpoint(1), after).departed);
    }

    #[test]
    fn finished_exchanges_leave_no_state() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);
        let second = start(&mut devices, 2);

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

    #[test]
    fn exchanges_on_different_interfaces_run_side_by_side() {
        let mut devices = Devices::default();

        let _first = start(&mut devices, 1);

        assert!(
            devices
                .start_exchange(&endpoint(1), 2, xaddrs("second"))
                .is_some()
        );
    }

    #[test]
    fn triggers_during_an_exchange_rerun_it_once_with_the_last_xaddrs() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);

        assert!(
            devices
                .start_exchange(&endpoint(1), 1, xaddrs("second"))
                .is_none()
        );
        assert!(
            devices
                .start_exchange(&endpoint(1), 1, xaddrs("third"))
                .is_none()
        );

        let Fetch {
            exchange: rerun,
            xaddrs: rerun_xaddrs,
        } = devices
            .finish_exchange(&endpoint(1), first)
            .rerun
            .expect("triggers arrived while the exchange ran");

        assert_eq!(urls(&rerun_xaddrs), urls(&xaddrs("third")));

        assert!(devices.finish_exchange(&endpoint(1), rerun).rerun.is_none());

        assert!(!devices.has_running_exchanges());
    }

    #[test]
    fn bye_drops_the_rerun_of_an_earlier_trigger() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);

        assert!(
            devices
                .start_exchange(&endpoint(1), 1, xaddrs("second"))
                .is_none()
        );

        devices.depart(&endpoint(1));

        let finished = devices.finish_exchange(&endpoint(1), first);

        assert!(finished.departed);
        assert!(finished.rerun.is_none());

        assert!(!devices.has_running_exchanges());
    }

    #[test]
    fn cancelled_exchange_frees_its_slot_and_drops_its_rerun() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);

        assert!(
            devices
                .start_exchange(&endpoint(1), 1, xaddrs("second"))
                .is_none()
        );

        devices.cancel_exchange(&endpoint(1), first);

        assert!(!devices.has_running_exchanges());

        assert!(
            devices
                .start_exchange(&endpoint(1), 1, xaddrs("third"))
                .is_some()
        );
    }

    #[tokio::test]
    async fn trigger_after_a_bye_reruns() {
        let mut devices = Devices::default();

        let first = start(&mut devices, 1);

        devices.depart(&endpoint(1));

        assert!(
            devices
                .start_exchange(&endpoint(1), 1, xaddrs("second"))
                .is_none()
        );

        let finished = devices.finish_exchange(&endpoint(1), first);

        assert!(finished.departed);

        let Fetch {
            exchange: rerun, ..
        } = finished.rerun.expect("a trigger arrived after the Bye");

        assert_eq!(rerun.run_until_bye(async { 1 }).await, Some(1));
    }
}
