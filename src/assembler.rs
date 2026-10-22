//! Turns a stream of shred packets into decoded transactions and block markers, with timing.
//!
//! push takes one packet, parses it and puts the shred into its FEC set.
//! A set decodes as soon as it has 32 shreds, the earliest moment the data can be known.
//! Sets go to the slot's Batcher strictly in order, because a batch can start in one set and end in the next.
//! Each finished batch is decoded into events, one per transaction or marker.
//! A slot ends when its last shred is decoded, but it closes only when its Alpenglow skip deadline
//! has passed on the capture clock, 1.45 s after its first shred with 200 ms slots.
//! Data shreds keep arriving after a slot ends, and the slot's events are held until it closes,
//! so they can say which data shreds never arrived and only exist because Reed-Solomon rebuilt them.
//! Every event carries t0 (first shred of the set), t1 (32nd shred) and t2 (the batch could decode).

use crate::block::{Batcher, Component, decode_component, is_last_in_slot};
use crate::error::Error;
use crate::fec::{DATA_SHREDS, FecSet, TOTAL_SHREDS};
use crate::footer::{Footer, decode_footer};
use crate::leaders::{LeaderSchedule, Pubkey, signed_by};
use crate::merkle::shred_root;
use crate::shred::{Kind, Shred};
use crate::wire;
use solana_transaction::Signature;
use std::collections::{BTreeMap, HashMap};
use std::ops::Range;

// Alpenglow timing, from Agave votor/src/common.rs and timer_manager/timers.rs.
// A validator votes skip on slot i of a leader window at
// ParentReady + DELTA_TIMEOUT + (i + 1) * slot duration, so by
// first shred + DELTA_TIMEOUT + LEADER_WINDOW_SLOTS * slot + DELTA every honest
// validator has passed the slot's skip deadline and its shreds are no longer coming.

/// Network delay bound, Agave DELTA.
pub const DELTA_NS: u64 = 250_000_000;
/// Base leader handover timeout, Agave DELTA_TIMEOUT.
pub const DELTA_TIMEOUT_NS: u64 = 400_000_000;
/// Slots per leader window, Agave NUM_CONSECUTIVE_LEADER_SLOTS.
pub const LEADER_WINDOW_SLOTS: u64 = 4;
/// Slot duration on mainnet and testnet. Agave reads it from the bank per epoch.
pub const DEFAULT_SLOT_NS: u64 = 200_000_000;

/// Closed slots remembered so shreds arriving after them are counted, not reopened. About 14 minutes of slots.
const CLOSED_SLOTS_KEPT: usize = 4096;
/// A shred for a slot this far behind the newest one is stale, about a minute of slots.
/// It is counted and dropped, so a straggler never opens a long gone slot again.
pub const STALE_SLOTS: u64 = 300;

/// When each part of a transaction's journey happened, all in capture nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timing {
    /// FEC set the batch finished in.
    pub fec_set_index: u32,
    /// First shred of that set arrived (t0).
    pub first_shred_ns: u64,
    /// That set had 32 unique shreds, so it could be rebuilt (t1).
    pub decodable_ns: u64,
    /// The packet that let the batch decode arrived (t2).
    pub decoded_ns: u64,
}

/// What the assembler hands out.
#[derive(Debug)]
pub enum Event {
    /// One transaction, keyed by its first signature.
    Tx {
        slot: u64,
        signature: Signature,
        timing: Timing,
        /// Its batch holds a data shred that never arrived, so part of it was only rebuilt.
        rebuilt: bool,
    },
    /// A block marker, variant 0 footer, 1 header, 2 update parent, 3 genesis certificate.
    Marker {
        slot: u64,
        variant: u8,
        data: Vec<u8>,
        timing: Timing,
        /// Its batch holds a data shred that never arrived, so part of it was only rebuilt.
        rebuilt: bool,
    },
    /// One FEC set, either decoded or given up on. Comes before anything decoded from it.
    Set {
        slot: u64,
        fec_set_index: u32,
        /// First shred of the set arrived (t0).
        first_shred_ns: u64,
        /// The set reached 32 shreds (t1), None if it never did.
        decodable_ns: Option<u64>,
        /// Data shreds the set held when it was decoded or given up on.
        /// Below 32 on a decoded set means Reed-Solomon rebuilt the rest.
        data_at_decode: u64,
        /// Data shreds that never arrived by the time the slot closed, by place in the set.
        /// Their bytes only exist because Reed-Solomon rebuilt them. Empty for a lost set.
        rebuilt: Vec<u8>,
        /// False when the set was given up on.
        decoded: bool,
    },
    /// One slot, once it is closed. Comes after every other event of the slot.
    Slot {
        slot: u64,
        /// The slot's leader, None without a leader schedule or if the schedule doesn't cover it.
        leader: Option<Pubkey>,
        /// First shred of any of its sets arrived.
        first_shred_ns: u64,
        /// The last batch of the slot decoded, None if nothing decoded.
        done_ns: Option<u64>,
        sets_decoded: u32,
        sets_lost: u32,
        txs: u64,
        /// Data shreds whose first copy came after their set was decoded.
        late_data: u32,
        /// The block footer, None if it never decoded.
        footer: Option<Footer>,
        end: SlotEnd,
    },
}

/// Why a slot was closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotEnd {
    /// Its last shred was decoded.
    Complete,
    /// Its skip deadline passed, or a set could not be rebuilt.
    GivenUp,
    /// The input ended while it was still open.
    EndOfInput,
}

impl SlotEnd {
    /// The name written in the output.
    pub fn as_str(self) -> &'static str {
        match self {
            SlotEnd::Complete => "complete",
            SlotEnd::GivenUp => "given_up",
            SlotEnd::EndOfInput => "end_of_input",
        }
    }
}

/// Shred health counters for the report.
#[derive(Debug, Default, Clone, PartialEq, Eq, serde::Serialize)]
pub struct Stats {
    pub packets: u64,
    /// Packets that are not a shred we can read, like the wrong size or an unknown variant.
    pub not_shreds: u64,
    /// Shreds seen before, wherever their slot or set was when the copy arrived.
    pub duplicates: u64,
    /// First copies of shreds that arrived after their slot was finished or given up on, mostly leftover coding shreds.
    pub after_slot_done: u64,
    /// First copies of shreds whose set was already decoded from the first 32 that arrived.
    pub after_decode: u64,
    /// Shreds a FEC set refused, like an out of range index or a config other than 32 and 32.
    pub rejected: u64,
    /// Shreds whose Merkle proof does not climb to their FEC set's root, so they were changed or forged.
    pub bad_proof: u64,
    /// Shreds not signed by their slot's leader, or signed differently from the rest of their set.
    pub bad_signature: u64,
    /// Shreds of slots the leader schedule doesn't cover, so their signature can't be checked.
    pub no_leader: u64,
    /// Sets whose data shards went to the decoder.
    pub sets_decoded: u64,
    /// Of those, sets rebuilt with Reed-Solomon because some data shreds weren't in yet at t1.
    /// Most of those data shreds still arrive later, so this is not loss.
    pub sets_rebuilt_at_t1: u64,
    /// Decoded sets whose 32 data shreds had not all arrived when their slot closed,
    /// real data loss on the wire.
    pub sets_data_never_complete: u64,
    /// Sets that never reached 32 shreds, or waited behind one that didn't.
    pub sets_lost: u64,
    pub batches: u64,
    /// Batches that didn't decode as entries or a marker.
    pub decode_errors: u64,
    pub slots_complete: u64,
    /// Transactions handed out, one per first signature.
    pub txs: u64,
    /// Of those, transactions whose batch holds a data shred that never arrived.
    pub txs_rebuilt: u64,
    /// Block markers handed out.
    pub markers: u64,
    /// Footer markers whose bytes don't follow Agave's footer layout.
    pub bad_footers: u64,
    /// Shreds for slots more than STALE_SLOTS behind the newest one, dropped.
    pub stale: u64,
}

/// Which shreds of one FEC set have arrived, kept after the set is decoded and its slot closed.
#[derive(Default)]
struct Seen {
    /// Bit i is set once shard index i has arrived, data at bits 0..32 and coding at 32..64.
    shreds: u64,
}

/// Everything in flight for one slot.
struct SlotState {
    /// Earliest arrival of any shred of this slot, the start of its give up clock.
    first_seen_ns: u64,
    sets: BTreeMap<u32, FecSet>,
    /// fec_set_index of the next set to hand to the batcher, sets must go in order
    /// because a batch can start in one set and end in the next.
    next_set: u32,
    batcher: Batcher,
    sets_decoded: u32,
    /// Sets that failed to rebuild, the ones still waiting are added when the slot closes.
    sets_lost: u32,
    txs: u64,
    /// Data shreds whose first copy came after their set was decoded.
    late_data: u32,
    footer: Option<Footer>,
    /// When the slot's latest batch decoded.
    done_ns: Option<u64>,
    /// Index of the first data shred of the batch being filled.
    batch_start: Option<u32>,
    /// Events held until the slot closes, each transaction and marker with the data shreds of its batch.
    pending: Vec<(Event, Range<u32>)>,
    /// Shreds seen per set, by fec_set_index.
    seen: BTreeMap<u32, Seen>,
    /// Set once the slot is decoded or can't be, it then only records late shreds until it closes.
    ended: Option<SlotEnd>,
}

pub struct Assembler {
    slots: HashMap<u64, SlotState>,
    /// Slots finished or given up on, with the shreds they saw,
    /// so shreds arriving after them are counted and not reopened.
    closed: BTreeMap<u64, BTreeMap<u32, Seen>>,
    /// Capture clock, the newest recv_ns seen, so a reordered packet can't move time backwards.
    now_ns: u64,
    /// The newest slot that completed. Only a complete slot moves it, so a junk or straggler can't.
    tip: u64,
    /// How long after its first shred a slot is given up on.
    give_up_ns: u64,
    /// Who led each slot. Without it signatures are not checked.
    leaders: Option<LeaderSchedule>,
    stats: Stats,
}

impl Default for Assembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Assembler {
    /// An assembler for 200 ms slots.
    pub fn new() -> Self {
        Self::with_slot_duration_ns(DEFAULT_SLOT_NS)
    }

    /// An assembler for another slot duration, which moves the give up deadline with it.
    pub fn with_slot_duration_ns(slot_ns: u64) -> Self {
        Self {
            slots: HashMap::new(),
            closed: BTreeMap::new(),
            now_ns: 0,
            tip: 0,
            give_up_ns: DELTA_TIMEOUT_NS + LEADER_WINDOW_SLOTS * slot_ns + DELTA_NS,
            leaders: None,
            stats: Stats::default(),
        }
    }

    /// Checks every FEC set's signature against its slot's leader from this schedule.
    pub fn with_leaders(mut self, leaders: LeaderSchedule) -> Self {
        self.leaders = Some(leaders);
        self
    }

    /// Swaps in a new schedule while running. An empty one turns the check off rather than
    /// turning every shred away, so a folder with no files yet does not stop the decoding.
    pub fn set_leaders(&mut self, leaders: LeaderSchedule) {
        self.leaders = (!leaders.is_empty()).then_some(leaders);
    }

    /// Feeds one UDP payload. Returns whatever this packet made decodable.
    pub fn push(&mut self, payload: &[u8], recv_ns: u64) -> Vec<Event> {
        self.stats.packets += 1;

        let Some(shred) = parse_full_shred(payload, recv_ns) else {
            self.stats.not_shreds += 1;
            return Vec::new();
        };
        let slot = shred.slot;

        // time moves on even for a shred we end up dropping
        self.now_ns = self.now_ns.max(recv_ns);
        let events = self.give_up_expired_slots();

        let Some(bit) = shard_bit(&shred) else {
            self.stats.rejected += 1;
            return events;
        };

        // the seen bits are checked first, so a copy is a duplicate however late it comes
        if let Some(sets) = self.closed.get_mut(&slot) {
            seen_late(sets, shred.fec_set_index, bit, &mut self.stats);
            return events;
        }

        if slot.saturating_add(STALE_SLOTS) < self.tip {
            self.stats.stale += 1;
            return events;
        }

        let state = self.slots.entry(slot).or_insert_with(|| SlotState {
            first_seen_ns: recv_ns,
            sets: BTreeMap::new(),
            next_set: 0,
            batcher: Batcher::new(),
            sets_decoded: 0,
            sets_lost: 0,
            txs: 0,
            late_data: 0,
            footer: None,
            done_ns: None,
            batch_start: None,
            pending: Vec::new(),
            seen: BTreeMap::new(),
            ended: None,
        });
        let is_data = shred.variant.kind == Kind::Data;
        if state.ended.is_some() {
            if seen_late(&mut state.seen, shred.fec_set_index, bit, &mut self.stats) && is_data {
                state.late_data += 1;
            }
            return events;
        }
        state.first_seen_ns = state.first_seen_ns.min(recv_ns);
        let seen = state.seen.entry(shred.fec_set_index).or_default();
        if seen.shreds & bit != 0 {
            self.stats.duplicates += 1;
            return events;
        }
        if shred.fec_set_index < state.next_set {
            // its set was already decoded, the shred is no longer needed
            seen.shreds |= bit;
            self.stats.after_decode += 1;
            state.late_data += u32::from(is_data);
            return events;
        }

        // the first shred of a set decides its root, so it must be signed by the slot's leader.
        // The rest only have to match it, one signature check per set like Agave's cache
        if let Some(leaders) = &self.leaders
            && !state.sets.contains_key(&shred.fec_set_index)
        {
            let Some(leader) = leaders.leader(slot) else {
                self.stats.no_leader += 1;
                return events;
            };
            if !shred_root(&shred).is_ok_and(|root| signed_by(&shred, &root, leader)) {
                self.stats.bad_signature += 1;
                return events;
            }
        }

        let set = state
            .sets
            .entry(shred.fec_set_index)
            .or_insert_with(|| FecSet::new(slot, shred.fec_set_index));
        match set.push(shred) {
            Ok(_) => {}
            Err(Error::InvalidMerkleProof { .. } | Error::MerkleRootMismatch { .. }) => {
                self.stats.bad_proof += 1;
                return events;
            }
            Err(Error::SignatureMismatch { .. }) => {
                self.stats.bad_signature += 1;
                return events;
            }
            Err(_) => {
                self.stats.rejected += 1;
                return events;
            }
        }
        seen.shreds |= bit;

        self.drain(slot, recv_ns);
        events
    }

    /// Hands every rebuildable set, in order, to the slot's batcher and decodes finished batches.
    /// What it decodes is held in the slot until the slot closes.
    fn drain(&mut self, slot: u64, now_ns: u64) {
        let mut slot_done = false;
        let mut end = SlotEnd::GivenUp;

        let Some(state) = self.slots.get_mut(&slot) else {
            return;
        };

        while let Some(set) = state.sets.get_mut(&state.next_set) {
            if !set.can_recover() {
                break;
            }
            let Some(mut set) = state.sets.remove(&state.next_set) else {
                break;
            };
            state.next_set += DATA_SHREDS as u32;

            // counted before recover, which fills the missing data places
            let data_at_decode = set.data_received() as u64;
            if set.recover().is_err() {
                self.stats.sets_lost += 1;
                state.sets_lost += 1;
                state
                    .pending
                    .push((set_event(&set, data_at_decode, false), 0..0));
                // later sets can't be decoded without this one's bytes
                slot_done = true;
                break;
            }
            self.stats.sets_decoded += 1;
            state.sets_decoded += 1;
            if set.recovered {
                self.stats.sets_rebuilt_at_t1 += 1;
            }
            state
                .pending
                .push((set_event(&set, data_at_decode, true), 0..0));

            let timing = Timing {
                fec_set_index: set.fec_set_index,
                first_shred_ns: set.first_seen_ns.unwrap_or(now_ns),
                decodable_ns: set.decodable_ns.unwrap_or(now_ns),
                decoded_ns: now_ns,
            };

            let Ok(shards) = set.data_shards() else {
                self.stats.sets_lost += 1;
                state.sets_lost += 1;
                slot_done = true;
                break;
            };
            for (i, shard) in (set.fec_set_index..).zip(shards) {
                let start = *state.batch_start.get_or_insert(i);
                let batch = match state.batcher.push(shard) {
                    Ok(Some(batch)) => batch,
                    Ok(None) => continue,
                    Err(_) => {
                        self.stats.decode_errors += 1;
                        continue;
                    }
                };
                self.stats.batches += 1;
                state.batch_start = None;
                match decode_component(&batch) {
                    Ok(component) => {
                        let mut decoded = Vec::new();
                        push_events(&mut decoded, &mut self.stats, slot, component, timing);
                        for event in decoded {
                            match &event {
                                Event::Tx { .. } => state.txs += 1,
                                Event::Marker {
                                    variant: 0, data, ..
                                } => match decode_footer(data) {
                                    Ok(footer) => state.footer = Some(footer),
                                    Err(_) => self.stats.bad_footers += 1,
                                },
                                _ => {}
                            }
                            state.pending.push((event, start..i + 1));
                        }
                        state.done_ns = Some(now_ns);
                    }
                    Err(_) => self.stats.decode_errors += 1,
                }
                if is_last_in_slot(shard).unwrap_or(false) {
                    self.stats.slots_complete += 1;
                    slot_done = true;
                    end = SlotEnd::Complete;
                }
            }
            if slot_done {
                break;
            }
        }

        if slot_done {
            state.ended = Some(end);
        }
    }

    /// Closes every slot whose deadline has passed on the capture clock, giving up on the ones still open.
    fn give_up_expired_slots(&mut self) -> Vec<Event> {
        let mut expired: Vec<u64> = self
            .slots
            .iter()
            .filter(|(_, state)| self.now_ns > state.first_seen_ns.saturating_add(self.give_up_ns))
            .map(|(slot, _)| *slot)
            .collect();
        // HashMap order changes from run to run, sorting keeps the output the same every time
        expired.sort_unstable();
        let mut events = Vec::new();
        for slot in expired {
            events.extend(self.close(slot, SlotEnd::GivenUp));
        }
        events
    }

    /// Drops a slot's state. Hands out its held events, marked with the data shreds that never arrived,
    /// then every set it never decoded as lost, then the slot itself.
    fn close(&mut self, slot: u64, end: SlotEnd) -> Vec<Event> {
        let Some(mut state) = self.slots.remove(&slot) else {
            self.remember_closed(slot, BTreeMap::new());
            return Vec::new();
        };
        let end = state.ended.unwrap_or(end);
        if end == SlotEnd::Complete {
            self.tip = self.tip.max(slot);
        }
        let seen = std::mem::take(&mut state.seen);
        let arrived = |index: u32| {
            let place = index % DATA_SHREDS as u32;
            seen.get(&(index - place))
                .is_some_and(|s| s.shreds & 1 << place != 0)
        };
        let mut events = Vec::with_capacity(state.pending.len() + state.sets.len() + 1);
        for (mut event, mut shreds) in std::mem::take(&mut state.pending) {
            match &mut event {
                Event::Set {
                    fec_set_index,
                    rebuilt,
                    decoded: true,
                    ..
                } => {
                    *rebuilt = (0..DATA_SHREDS as u8)
                        .filter(|place| !arrived(*fec_set_index + u32::from(*place)))
                        .collect();
                    self.stats.sets_data_never_complete += u64::from(!rebuilt.is_empty());
                }
                Event::Tx { rebuilt, .. } => {
                    *rebuilt = !shreds.all(arrived);
                    self.stats.txs_rebuilt += u64::from(*rebuilt);
                }
                Event::Marker { rebuilt, .. } => *rebuilt = !shreds.all(arrived),
                _ => {}
            }
            events.push(event);
        }
        self.remember_closed(slot, seen);
        self.stats.sets_lost += state.sets.len() as u64;
        events.extend(
            state
                .sets
                .values()
                .map(|set| set_event(set, set.data_received() as u64, false)),
        );
        events.push(Event::Slot {
            slot,
            leader: self.leaders.as_ref().and_then(|l| l.leader(slot)).copied(),
            first_shred_ns: state.first_seen_ns,
            done_ns: state.done_ns,
            sets_decoded: state.sets_decoded,
            sets_lost: state.sets_lost + state.sets.len() as u32,
            txs: state.txs,
            late_data: state.late_data,
            footer: state.footer,
            end,
        });
        events
    }

    /// Keeps a closed slot's seen shreds, forgetting the oldest slots first.
    /// A junk slot number only takes one place.
    fn remember_closed(&mut self, slot: u64, seen: BTreeMap<u32, Seen>) {
        self.closed.insert(slot, seen);
        while self.closed.len() > CLOSED_SLOTS_KEPT {
            self.closed.pop_first();
        }
    }

    /// End of input. Every slot is closed, and every set still waiting is handed out as lost.
    pub fn finish(&mut self) -> Vec<Event> {
        let mut slots: Vec<u64> = self.slots.keys().copied().collect();
        slots.sort_unstable();
        let mut events = Vec::new();
        for slot in slots {
            events.extend(self.close(slot, SlotEnd::EndOfInput));
        }
        events
    }

    /// Counters so far.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }
}

/// Counts a shred that came after its slot ended, as a duplicate or as a first copy.
/// True for a first copy.
fn seen_late(
    sets: &mut BTreeMap<u32, Seen>,
    fec_set_index: u32,
    bit: u64,
    stats: &mut Stats,
) -> bool {
    let seen = sets.entry(fec_set_index).or_default();
    if seen.shreds & bit != 0 {
        stats.duplicates += 1;
        false
    } else {
        seen.shreds |= bit;
        stats.after_slot_done += 1;
        true
    }
}

/// Parses a payload only if it is a whole shred of the right size for its kind.
fn parse_full_shred(payload: &[u8], recv_ns: u64) -> Option<Shred> {
    let shred = Shred::parse(payload, recv_ns).ok()?;
    let expected = match shred.variant.kind {
        Kind::Data => wire::DATA_PAYLOAD_SIZE,
        Kind::Code => wire::CODING_PAYLOAD_SIZE,
    };
    (payload.len() == expected).then_some(shred)
}

/// The seen bit for a shred's place in its set, None if the place is outside its kind's range.
/// A coding shred's place only means something with 32 data shreds, so that is checked too.
fn shard_bit(shred: &Shred) -> Option<u64> {
    let range = match shred.variant.kind {
        Kind::Data => 0..DATA_SHREDS,
        Kind::Code => {
            let num_data = wire::num_data(&shred.bytes).ok()?;
            if usize::from(num_data) != DATA_SHREDS {
                return None;
            }
            DATA_SHREDS..TOTAL_SHREDS
        }
    };
    range
        .contains(&shred.shard_index)
        .then(|| 1u64 << shred.shard_index)
}

/// The Set event for a set, decoded or not. Its rebuilt shreds are filled in when the slot closes.
fn set_event(set: &FecSet, data_at_decode: u64, decoded: bool) -> Event {
    Event::Set {
        slot: set.slot,
        fec_set_index: set.fec_set_index,
        first_shred_ns: set.first_seen_ns.unwrap_or(0),
        decodable_ns: set.decodable_ns,
        data_at_decode,
        rebuilt: Vec::new(),
        decoded,
    }
}

/// One event per transaction (by first signature), or one for a marker.
fn push_events(
    events: &mut Vec<Event>,
    stats: &mut Stats,
    slot: u64,
    component: Component,
    timing: Timing,
) {
    match component {
        Component::Entries(entries) => {
            for entry in entries {
                for tx in entry.transactions {
                    if let Some(signature) = tx.signatures.first() {
                        stats.txs += 1;
                        events.push(Event::Tx {
                            slot,
                            signature: *signature,
                            timing,
                            rebuilt: false,
                        });
                    }
                }
            }
        }
        Component::Marker { variant, data, .. } => {
            stats.markers += 1;
            events.push(Event::Marker {
                slot,
                variant,
                data,
                timing,
                rebuilt: false,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Every shred of slot 449661788 in the order and at the times they reached the node,
    // taken from real-10s.pcap. Each record is recv_ns (u64), length (u16), then the shred.
    // 255 shreds, 128 data and 127 coding. getBlock reports 26 transactions.
    const ARRIVALS: &[u8] = include_bytes!("../tests/fixtures/real-slot-arrivals.bin");
    const SLOT: u64 = 449_661_788;

    // From getBlock 449661788 on the public testnet RPC.
    const FIRST_SIG: &str =
        "4AbpiMLynSZh6xhuKRvFVYWv56nAdgtiJ17kHMeTeHbjgAP4SQXxn6CBRzkF2TukHjAhaDappzuDgkZ9gXfmuNBu";
    const LAST_SIG: &str =
        "2Q6fhMTitpBvyP5WzzowF6EWCoQgRqh1tZxSi6rgBeaVxT3nGYHbMGgenT3tjXRw8ummmLmwkSdiT6JntDeJfL8Z";

    fn arrivals() -> Vec<(u64, &'static [u8])> {
        let mut out = Vec::new();
        let mut at = 0;
        while at < ARRIVALS.len() {
            let recv_ns = u64::from_le_bytes(ARRIVALS[at..at + 8].try_into().unwrap());
            let len = usize::from(u16::from_le_bytes([ARRIVALS[at + 8], ARRIVALS[at + 9]]));
            out.push((recv_ns, &ARRIVALS[at + 10..at + 10 + len]));
            at += 10 + len;
        }
        out
    }

    fn is_data(shred: &[u8]) -> bool {
        matches!(shred[64] >> 4, 0x9 | 0xB)
    }

    fn run(packets: &[(u64, &[u8])]) -> (Assembler, Vec<Event>) {
        let mut asm = Assembler::new();
        let mut events = Vec::new();
        for (recv_ns, payload) in packets {
            events.extend(asm.push(payload, *recv_ns));
        }
        (asm, events)
    }

    // run, then the end of input, which closes the slot and hands out its events
    fn run_to_end(packets: &[(u64, &[u8])]) -> (Assembler, Vec<Event>) {
        let (mut asm, mut events) = run(packets);
        events.extend(asm.finish());
        (asm, events)
    }

    fn signatures(events: &[Event]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Tx { signature, .. } => Some(signature.to_string()),
                _ => None,
            })
            .collect()
    }

    fn marker_variants(events: &[Event]) -> Vec<u8> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::Marker { variant, .. } => Some(*variant),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn test_real_arrival_order() {
        let (asm, events) = run_to_end(&arrivals());
        let sigs = signatures(&events);
        assert_eq!(sigs.len(), 26);
        assert_eq!(sigs.first().unwrap(), FIRST_SIG);
        assert_eq!(sigs.last().unwrap(), LAST_SIG);
        // header first, footer near the end
        assert_eq!(marker_variants(&events), [1, 0]);

        let s = asm.stats();
        assert_eq!(s.packets, 255);
        assert_eq!(s.not_shreds, 0);
        assert_eq!(s.sets_decoded, 4);
        assert_eq!(s.slots_complete, 1);
        assert_eq!(s.batches, 4);
        assert_eq!(s.decode_errors, 0);
    }

    #[test]
    fn test_reverse_order() {
        // the last set completes first, nothing may decode until set 0 is in
        let mut packets = arrivals();
        packets.reverse();
        let (_, events) = run_to_end(&packets);
        let sigs = signatures(&events);
        assert_eq!(sigs.len(), 26);
        assert_eq!(sigs.first().unwrap(), FIRST_SIG);
        assert_eq!(sigs.last().unwrap(), LAST_SIG);
    }

    #[test]
    fn test_sets_wait_for_earlier_set() {
        // every shred except those of set 0, then set 0
        let packets = arrivals();
        let set0 = |p: &[u8]| wire::fec_set_index(p).unwrap() == 0;
        let (mut asm, events) = run(&packets
            .iter()
            .copied()
            .filter(|(_, p)| !set0(p))
            .collect::<Vec<_>>());
        assert!(events.is_empty());
        let mut late = Vec::new();
        for (t, p) in packets.iter().filter(|(_, p)| set0(p)) {
            late.extend(asm.push(p, *t));
        }
        late.extend(asm.finish());
        assert_eq!(signatures(&late).len(), 26);
    }

    #[test]
    fn test_recovers_lost_data_shreds() {
        // drop 10 data shreds of set 32, the coding shreds rebuild them
        let packets: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| {
                let index = wire::index(p).unwrap();
                !(is_data(p) && (40..50).contains(&index))
            })
            .collect();
        let (mut asm, events) = run_to_end(&packets);
        assert_eq!(signatures(&events).len(), 26);
        assert_eq!(asm.stats().sets_decoded, 4);
        assert_eq!(asm.stats().sets_lost, 0);
        // set 32 says which places were rebuilt, and the transactions they carried say so too
        let Some(Event::Set { rebuilt, .. }) = events.iter().find(|e| {
            matches!(
                e,
                Event::Set {
                    fec_set_index: 32,
                    ..
                }
            )
        }) else {
            unreachable!()
        };
        assert!((8..18).all(|i| rebuilt.contains(&i)));
        assert!(asm.stats().txs_rebuilt > 0);
        // those 10 never arrive, so set 32 never had all its data
        asm.finish();
        assert_eq!(asm.stats().sets_data_never_complete, 1);
    }

    #[test]
    fn test_nothing_rebuilt_when_data_comes_first() {
        let mut packets = arrivals();
        packets.sort_by_key(|(_, p)| (!is_data(p), wire::index(p).unwrap()));
        let (asm, events) = run_to_end(&packets);
        assert_eq!(signatures(&events).len(), 26);
        assert_eq!(asm.stats().txs_rebuilt, 0);
        for e in &events {
            match e {
                Event::Set { rebuilt, .. } => assert!(rebuilt.is_empty()),
                Event::Tx { rebuilt, .. } | Event::Marker { rebuilt, .. } => assert!(!rebuilt),
                Event::Slot { .. } => {}
            }
        }
    }

    #[test]
    fn test_rebuilt_at_t1_is_not_loss() {
        // sets decode before all their data is in, but every data shred of the slot arrives in the end
        let (mut asm, _) = run(&arrivals());
        assert!(asm.stats().sets_rebuilt_at_t1 > 0);
        asm.finish();
        assert_eq!(asm.stats().sets_data_never_complete, 0);
    }

    #[test]
    fn test_duplicates_and_junk() {
        let mut packets = Vec::new();
        for (t, p) in arrivals() {
            packets.push((t, p));
            packets.push((t + 1, p)); // every shred twice
        }
        let mut stray = vec![0u8; 1203];
        stray[64] = 0x19; // not a shred variant
        let cut = &arrivals()[0].1[..500]; // right variant, wrong size
        packets.insert(3, (0, &stray[..]));
        packets.insert(7, (0, cut));
        packets.insert(9, (0, &[][..]));

        let (asm, events) = run_to_end(&packets);
        assert_eq!(signatures(&events).len(), 26);
        let s = asm.stats();
        assert_eq!(s.not_shreds, 3);
        // every second copy is a duplicate, even the ones after their set or slot was done
        assert_eq!(s.duplicates, 255);
        assert_eq!(s.rejected, 0);
        assert_eq!(s.bad_proof, 0);
        // only first copies count as late
        let (clean, _) = run(&arrivals());
        assert_eq!(s.after_decode, clean.stats().after_decode);
        assert_eq!(s.after_slot_done, clean.stats().after_slot_done);
    }

    #[test]
    fn test_changed_shred_dropped() {
        // the second shred of set 32 to arrive has one byte changed on the way
        let mut packets: Vec<(u64, Vec<u8>)> = arrivals()
            .into_iter()
            .map(|(t, p)| (t, p.to_vec()))
            .collect();
        let at = packets
            .iter()
            .enumerate()
            .filter(|(_, (_, p))| wire::fec_set_index(p).unwrap() == 32)
            .nth(1)
            .unwrap()
            .0;
        packets[at].1[200] ^= 1;

        let mut asm = Assembler::new();
        let mut events = Vec::new();
        for (t, p) in &packets {
            events.extend(asm.push(p, *t));
        }
        events.extend(asm.finish());
        assert_eq!(asm.stats().bad_proof, 1);
        assert_eq!(asm.stats().rejected, 0);
        // the set still has 63 good shreds, so the slot decodes as before
        assert_eq!(signatures(&events).len(), 26);
    }

    // From solana leader-schedule for testnet epoch 1053, covering every slot of real-10s.pcap.
    const LEADERS: &str = include_str!("../tests/fixtures/real-leaders.txt");

    fn leaders() -> LeaderSchedule {
        let mut schedule = LeaderSchedule::default();
        schedule.read(LEADERS.as_bytes()).unwrap();
        schedule
    }

    fn run_with(asm: &mut Assembler, packets: &[(u64, &[u8])]) -> Vec<Event> {
        let mut events: Vec<Event> = packets.iter().flat_map(|(t, p)| asm.push(p, *t)).collect();
        events.extend(asm.finish());
        events
    }

    #[test]
    fn test_signatures_checked_against_the_leader() {
        let mut asm = Assembler::new().with_leaders(leaders());
        let events = run_with(&mut asm, &arrivals());
        assert_eq!(signatures(&events).len(), 26);
        assert_eq!(asm.stats().bad_signature, 0);
        assert_eq!(asm.stats().no_leader, 0);

        // a schedule that doesn't cover the slot lets nothing in
        let mut asm = Assembler::new().with_leaders(LeaderSchedule::default());
        assert!(signatures(&run_with(&mut asm, &arrivals())).is_empty());
        assert_eq!(asm.stats().no_leader, 255);

        // swapping in an empty schedule while running turns the check off instead
        let mut asm = Assembler::new().with_leaders(leaders());
        asm.set_leaders(LeaderSchedule::default());
        assert_eq!(signatures(&run_with(&mut asm, &arrivals())).len(), 26);
        assert_eq!(asm.stats().no_leader, 0);
    }

    #[test]
    fn test_forged_first_shred_dropped() {
        // a changed copy of set 0's first shred arrives before everything else
        let mut forged = arrivals()[0].1.to_vec();
        forged[200] ^= 1;
        let mut packets = vec![(arrivals()[0].0, &forged[..])];
        packets.extend(arrivals());

        // without a schedule it decides set 0's root and the real shreds of set 0 are refused
        let mut asm = Assembler::new();
        assert!(signatures(&run_with(&mut asm, &packets)).len() < 26);

        // with one its signature fails, so it never gets in and the slot decodes as usual
        let mut asm = Assembler::new().with_leaders(leaders());
        assert_eq!(signatures(&run_with(&mut asm, &packets)).len(), 26);
        assert_eq!(asm.stats().bad_signature, 1);
        assert_eq!(asm.stats().bad_proof, 0);
    }

    #[test]
    fn test_duplicate_after_decode() {
        // set 0 decodes from its first 32 shreds, then a copy of one of them arrives
        let set0: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() == 0)
            .collect();
        let (mut asm, _) = run(&set0[..32]);
        assert_eq!(asm.stats().sets_decoded, 1);
        let (t, p) = set0[0];
        asm.push(p, t);
        assert_eq!(asm.stats().duplicates, 1);
        assert_eq!(asm.stats().after_decode, 0);
        // a shred of the set not seen before is late, not a duplicate
        let (t, p) = set0[32];
        asm.push(p, t);
        assert_eq!(asm.stats().duplicates, 1);
        assert_eq!(asm.stats().after_decode, 1);
    }

    #[test]
    fn test_timing() {
        let (_, events) = run_to_end(&arrivals());
        for e in &events {
            if let Event::Tx { timing, .. } | Event::Marker { timing, .. } = e {
                assert!(timing.first_shred_ns <= timing.decodable_ns);
                assert!(timing.decodable_ns <= timing.decoded_ns);
            }
        }
        // the header marker decodes from set 0 alone
        let Some(Event::Marker { timing, slot, .. }) =
            events.iter().find(|e| matches!(e, Event::Marker { .. }))
        else {
            panic!("expected a header marker");
        };
        assert_eq!(*slot, SLOT);
        assert_eq!(timing.fec_set_index, 0);
    }

    #[test]
    fn test_late_shreds_after_slot_done() {
        let packets = arrivals();
        let (mut asm, _) = run(&packets);
        let late = asm.stats().after_slot_done;
        assert!(late > 0);
        // a copy of a shred the slot already had is a duplicate, not late
        assert!(asm.push(packets[0].1, 0).is_empty());
        assert_eq!(asm.stats().duplicates, 1);
        assert_eq!(asm.stats().after_slot_done, late);
    }

    // a valid shred of some other slot arriving at `at_ns`, which moves the capture clock
    fn tick(asm: &mut Assembler, at_ns: u64) -> Vec<Event> {
        let mut other = arrivals()[0].1.to_vec();
        other[65..73].copy_from_slice(&(SLOT + 1_000).to_le_bytes());
        asm.push(&other, at_ns)
    }

    // half of set 0's data shreds, arriving at their real times
    fn half_set_0() -> Vec<(u64, &'static [u8])> {
        arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() == 0 && is_data(p))
            .take(16)
            .collect()
    }

    #[test]
    fn test_give_up_deadline_is_alpenglow_skip_timeout() {
        // 400 ms DELTA_TIMEOUT + 4 slots of 200 ms + 250 ms DELTA
        assert_eq!(Assembler::new().give_up_ns, 1_450_000_000);
        // the deadline moves with the slot duration, 400 ms slots give 2.25 s
        assert_eq!(
            Assembler::with_slot_duration_ns(400_000_000).give_up_ns,
            2_250_000_000
        );
    }

    #[test]
    fn test_old_slot_given_up() {
        let packets = half_set_0();
        let first = packets.iter().map(|(t, _)| *t).min().unwrap();
        let (mut asm, events) = run(&packets);
        assert!(events.is_empty());

        // just before the deadline the slot is still open
        tick(&mut asm, first + 1_440_000_000);
        assert_eq!(asm.stats().sets_lost, 0);

        // just after it, the slot is given up on
        tick(&mut asm, first + 1_460_000_000);
        assert_eq!(asm.stats().sets_lost, 1);

        // the old slot is closed now, a new shred of it only counts as after_slot_done
        let (_, unseen) = arrivals()
            .into_iter()
            .find(|(_, p)| wire::fec_set_index(p).unwrap() == 32)
            .unwrap();
        let before = asm.stats().after_slot_done;
        asm.push(unseen, first + 1_470_000_000);
        assert_eq!(asm.stats().after_slot_done, before + 1);
    }

    #[test]
    fn test_longer_slots_wait_longer() {
        let packets = half_set_0();
        let first = packets.iter().map(|(t, _)| *t).min().unwrap();
        let mut asm = Assembler::with_slot_duration_ns(400_000_000);
        for (t, p) in &packets {
            asm.push(p, *t);
        }
        tick(&mut asm, first + 2_000_000_000);
        assert_eq!(asm.stats().sets_lost, 0);
        tick(&mut asm, first + 2_300_000_000);
        assert_eq!(asm.stats().sets_lost, 1);
    }

    #[test]
    fn test_junk_slot_does_not_block() {
        // a shred with an absurd slot number arrives first, the real slot must still decode
        let mut junk = arrivals()[0].1.to_vec();
        junk[65..73].copy_from_slice(&u64::MAX.to_le_bytes());
        let mut packets = vec![(arrivals()[0].0, &junk[..])];
        packets.extend(arrivals());
        let (mut asm, mut events) = run(&packets);
        // both slots close once their deadline passes, the junk one given up on
        let last = arrivals().iter().map(|(t, _)| *t).max().unwrap();
        events.extend(tick(&mut asm, last + 1_500_000_000));
        assert_eq!(signatures(&events).len(), 26);
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::Set { slot: u64::MAX, .. }))
        );
        // the real slot is handled exactly as without the junk shred
        let (clean, _) = run(&arrivals());
        assert_eq!(asm.stats().after_slot_done, clean.stats().after_slot_done);
        assert_eq!(asm.stats().sets_decoded, clean.stats().sets_decoded);
    }

    #[test]
    fn test_reordered_packet_does_not_rewind_the_clock() {
        // a packet stamped earlier than the newest one must not reopen the deadline
        let packets = half_set_0();
        let first = packets.iter().map(|(t, _)| *t).min().unwrap();
        let (mut asm, _) = run(&packets);
        tick(&mut asm, first + 1_460_000_000);
        assert_eq!(asm.stats().sets_lost, 1);
        tick(&mut asm, first);
        assert_eq!(asm.stats().sets_lost, 1);
    }

    #[test]
    fn test_finish_counts_unfinished_sets() {
        let packets: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() != 0)
            .collect();
        let (mut asm, events) = run(&packets);
        assert!(events.is_empty());
        asm.finish();
        assert_eq!(asm.stats().sets_lost, 3);
    }

    // Set events, one per FEC set, decoded or lost

    fn set_events(events: &[Event]) -> Vec<&Event> {
        events
            .iter()
            .filter(|e| matches!(e, Event::Set { .. }))
            .collect()
    }

    #[test]
    fn test_set_event_per_decoded_set() {
        let (asm, events) = run_to_end(&arrivals());
        let sets = set_events(&events);
        assert_eq!(sets.len(), 4);
        let mut indexes = Vec::new();
        for e in sets {
            let Event::Set {
                slot,
                fec_set_index,
                first_shred_ns,
                decodable_ns,
                data_at_decode,
                rebuilt,
                decoded,
            } = e
            else {
                unreachable!()
            };
            assert_eq!(*slot, SLOT);
            assert!(*decoded);
            assert!(decodable_ns.unwrap() >= *first_shred_ns);
            // a shred that never arrived was also missing at decode
            assert!(rebuilt.len() <= 32 - *data_at_decode as usize);
            indexes.push(*fec_set_index);
        }
        assert_eq!(indexes, [0, 32, 64, 96]);
        assert_eq!(asm.stats().txs, 26);
        assert_eq!(asm.stats().markers, 2);
    }

    #[test]
    fn test_set_event_comes_before_its_transactions() {
        // a reader of the event stream learns about the set before what was decoded from it
        let (_, events) = run_to_end(&arrivals());
        let first_set = events.iter().position(|e| matches!(e, Event::Set { .. }));
        let first_other = events.iter().position(|e| !matches!(e, Event::Set { .. }));
        assert!(first_set.unwrap() < first_other.unwrap());
    }

    #[test]
    fn test_finish_emits_lost_sets() {
        let packets: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() != 0)
            .collect();
        let (mut asm, _) = run(&packets);
        let events = asm.finish();
        let lost = set_events(&events);
        assert_eq!(lost.len(), 3);
        for e in lost {
            let Event::Set {
                decoded,
                decodable_ns,
                ..
            } = e
            else {
                unreachable!()
            };
            assert!(!decoded);
            // these sets had 32 shreds but waited behind set 0, which never came
            assert!(decodable_ns.is_some());
        }
        // then the slot itself, last
        assert!(matches!(
            events.last(),
            Some(Event::Slot {
                sets_decoded: 0,
                sets_lost: 3,
                end: SlotEnd::EndOfInput,
                ..
            })
        ));
    }

    // Slot events, one per slot when it closes

    #[test]
    fn test_slot_event_complete() {
        let (_, events) = run_to_end(&arrivals());
        let slots: Vec<_> = events
            .iter()
            .filter(|e| matches!(e, Event::Slot { .. }))
            .collect();
        assert_eq!(slots.len(), 1);
        let Event::Slot {
            slot,
            leader,
            first_shred_ns,
            done_ns,
            sets_decoded,
            sets_lost,
            txs,
            late_data,
            footer,
            end,
        } = slots[0]
        else {
            unreachable!()
        };
        assert_eq!(*slot, SLOT);
        assert_eq!(*first_shred_ns, arrivals()[0].0);
        assert!(done_ns.unwrap() > *first_shred_ns);
        assert_eq!((*sets_decoded, *sets_lost, *txs), (4, 0, 26));
        // no schedule, so no leader
        assert_eq!(*leader, None);
        // the slot decodes before all its data is in, the rest still arrives
        assert!(*late_data > 0);
        assert_eq!(
            footer.as_ref().unwrap().final_cert.as_ref().unwrap().slot,
            SLOT - 1
        );
        assert_eq!(*end, SlotEnd::Complete);
        // it closes the slot, so it is the last event
        assert!(matches!(events.last(), Some(Event::Slot { .. })));
    }

    #[test]
    fn test_slot_event_given_up() {
        let packets = half_set_0();
        let first = packets.iter().map(|(t, _)| *t).min().unwrap();
        let (mut asm, _) = run(&packets);
        let events = tick(&mut asm, first + 1_460_000_000);
        assert!(events.iter().any(|e| matches!(
            e,
            Event::Slot {
                slot: SLOT,
                done_ns: None,
                sets_lost: 1,
                end: SlotEnd::GivenUp,
                ..
            }
        )));
    }

    #[test]
    fn test_finish_order_is_stable() {
        // lost sets from several slots come out by slot, then by set, on every run
        let packets: Vec<_> = arrivals()
            .into_iter()
            .filter(|(_, p)| wire::fec_set_index(p).unwrap() != 0)
            .collect();
        let mut asm = Assembler::new();
        for offset in [5u64, 1, 9, 3] {
            for (t, p) in &packets {
                let mut shred = p.to_vec();
                shred[65..73].copy_from_slice(&(SLOT + offset).to_le_bytes());
                asm.push(&shred, *t);
            }
        }
        let order: Vec<(u64, u32)> = asm
            .finish()
            .iter()
            .filter_map(|e| match e {
                Event::Set {
                    slot,
                    fec_set_index,
                    ..
                } => Some((*slot, *fec_set_index)),
                _ => None,
            })
            .collect();
        let mut sorted = order.clone();
        sorted.sort_unstable();
        assert_eq!(order.len(), 12);
        assert_eq!(order, sorted);
    }

    #[test]
    fn test_eviction_emits_lost_set() {
        let packets = half_set_0();
        let first = packets.iter().map(|(t, _)| *t).min().unwrap();
        let (mut asm, _) = run(&packets);
        let events = tick(&mut asm, first + 1_460_000_000);
        let lost = set_events(&events);
        assert_eq!(lost.len(), 1);
        let Event::Set {
            slot,
            decodable_ns,
            data_at_decode,
            decoded,
            ..
        } = lost[0]
        else {
            unreachable!()
        };
        assert_eq!(*slot, SLOT);
        assert!(!decoded);
        assert_eq!(*decodable_ns, None); // never reached 32 shreds
        assert_eq!(*data_at_decode, 16); // data shreds it held when given up on
    }

    // Real capture, runs only where the raw pcap is present (it is never committed)

    #[test]
    #[cfg(feature = "pcap")]
    fn test_real_capture() {
        use crate::pcap::{PacketSource, PcapReader, udp_payload};
        let Ok(file) = std::fs::File::open("tests/fixtures/real-10s.pcap") else {
            return;
        };
        let mut reader = PcapReader::new(std::io::BufReader::new(file)).unwrap();
        let mut asm = Assembler::new().with_leaders(leaders());
        let mut events = Vec::new();
        while let Some(rec) = reader.next_record().unwrap() {
            if let Some(payload) = udp_payload(&rec.frame) {
                events.extend(asm.push(payload, rec.recv_ns));
            }
        }
        events.extend(asm.finish());
        let txs = signatures(&events).len();
        // every footer that decoded reads as one, and finalizes the slot before
        let mut footers = 0;
        for e in &events {
            if let Event::Marker {
                slot,
                variant: 0,
                data,
                ..
            } = e
            {
                let footer = crate::footer::decode_footer(data).unwrap();
                assert_eq!(footer.final_cert.unwrap().slot, slot - 1);
                footers += 1;
            }
        }
        assert_eq!(footers, 45);
        let s = asm.stats().clone();
        assert_eq!(s.packets, 15_907);
        assert_eq!(s.not_shreds, 1);
        assert_eq!(s.slots_complete, 45);
        assert_eq!(s.sets_decoded, 246);
        assert_eq!(s.decode_errors, 0);
        // every real shred climbs to its set's root, and every set is signed by its slot's leader
        assert_eq!(s.bad_proof, 0);
        assert_eq!(s.bad_signature, 0);
        assert_eq!(s.no_leader, 0);
        assert_eq!(txs, 2_394);
        assert_eq!(s.txs, 2_394);
        assert_eq!(s.bad_footers, 0);
    }
}
