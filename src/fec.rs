//! Collects the shreds of one FEC set and rebuilds missing data shards with Reed-Solomon.
//!
//! A set has 64 places, 32 data shards then 32 coding shards, filled by shard index as shreds arrive.
//! push checks each shred belongs here, drops duplicates and keeps only its shard bytes.
//! Belonging includes the Merkle proof, every shred must climb to the same root as the first one,
//! and carry the same signature, since the leader signs the root once for the whole set.
//! Any 32 of the 64 are enough, so once 32 are in, recover fills the missing places.
//! A rebuilt shard has no proof, so recover then builds the whole Merkle tree and checks its root.
//! data_shards then hands the 32 data shards over in order for the block decoder.
//! The set also records when its first shred arrived (t0) and when it became rebuildable (t1).

use crate::error::{Error, Result};
use crate::merkle::{self, Hash, shred_root};
use crate::shred::{Kind, Shred, layout};
use crate::wire;
use reed_solomon_erasure::galois_8::ReedSolomon;

/// Agave only builds and recovers 32 data + 32 coding sets.
pub const DATA_SHREDS: usize = 32;
pub const CODING_SHREDS: usize = 32;
pub const TOTAL_SHREDS: usize = DATA_SHREDS + CODING_SHREDS;

/// One FEC set as it fills up, with 64 places, data shards at 0..32 and coding at 32..64.
pub struct FecSet {
    pub slot: u64,
    pub fec_set_index: u32,
    /// Shard bytes by shard index. None means not arrived (yet).
    shards: Vec<Option<Vec<u8>>>,
    /// When the first shred of this set arrived (t0).
    pub first_seen_ns: Option<u64>,
    /// When the 32nd unique shred arrived, the moment the set became rebuildable (t1).
    pub decodable_ns: Option<u64>,
    /// True if Reed-Solomon had to rebuild missing data shards.
    pub recovered: bool,
    /// Merkle root of the set, from the first shred that was let in.
    pub root: Option<Hash>,
    /// The leader's signature over the root, the first 64 bytes of every shred of the set.
    signature: Option<Vec<u8>>,
    /// Root of the previous set, the same in every shred of this one.
    chained_root: Option<Vec<u8>>,
    /// The first 89 bytes of a coding shred, signature and headers.
    /// Rebuilt coding shreds get the same headers with their own index and position.
    coding_header: Option<Vec<u8>>,
}

impl FecSet {
    pub fn new(slot: u64, fec_set_index: u32) -> Self {
        Self {
            slot,
            fec_set_index,
            shards: vec![None; TOTAL_SHREDS],
            first_seen_ns: None,
            decodable_ns: None,
            recovered: false,
            root: None,
            signature: None,
            chained_root: None,
            coding_header: None,
        }
    }

    /// Adds one shred. Ok(true) if new, Ok(false) if we already had it.
    pub fn push(&mut self, shred: Shred) -> Result<bool> {
        if shred.fec_key() != (self.slot, self.fec_set_index) {
            return Err(Error::WrongFecSet {
                expected: (self.slot, self.fec_set_index),
                got: shred.fec_key(),
            });
        }

        // check the config first, a coding shred's shard index is num_data + position,
        // so it only means something once num_data is known to be 32
        if shred.variant.kind == Kind::Code {
            let num_data = wire::num_data(&shred.bytes)?;
            let num_coding = wire::num_coding(&shred.bytes)?;
            if usize::from(num_data) != DATA_SHREDS || usize::from(num_coding) != CODING_SHREDS {
                return Err(Error::UnsupportedErasureConfig {
                    num_data,
                    num_coding,
                });
            }
        }

        // data shards must sit in 0..32, coding shards in 32..64
        let range = match shred.variant.kind {
            Kind::Data => 0..DATA_SHREDS,
            Kind::Code => DATA_SHREDS..TOTAL_SHREDS,
        };
        if !range.contains(&shred.shard_index) {
            return Err(Error::ShardIndexOutOfRange(shred.shard_index));
        }

        // a shred whose proof leads somewhere else does not belong to this set
        let root = shred_root(&shred)?;
        if self.root.is_some_and(|expected| expected != root) {
            return Err(Error::MerkleRootMismatch {
                shard_index: shred.shard_index,
            });
        }
        let signature = shred.bytes.get(wire::SIGNATURE).ok_or(Error::TooShort {
            expected: wire::SIGNATURE.end,
            actual: shred.bytes.len(),
        })?;
        if self
            .signature
            .as_deref()
            .is_some_and(|expected| expected != signature)
        {
            return Err(Error::SignatureMismatch {
                shard_index: shred.shard_index,
            });
        }

        if self.shards[shred.shard_index].is_some() {
            return Ok(false);
        }

        // keep the shard bytes, which is all Reed-Solomon works on,
        // plus what a rebuilt shred's leaf needs and the shard doesn't hold
        let parts = layout(shred.variant)?;
        let too_short = || Error::TooShort {
            expected: parts.proof.start,
            actual: shred.bytes.len(),
        };
        let bytes = shred.bytes.get(parts.shard.clone()).ok_or_else(too_short)?;
        let chained = shred
            .bytes
            .get(parts.chained_merkle_root.clone())
            .ok_or_else(too_short)?;
        if shred.variant.kind == Kind::Code && self.coding_header.is_none() {
            let header = shred.bytes.get(..parts.shard.start).ok_or_else(too_short)?;
            self.coding_header = Some(header.to_vec());
        }
        self.shards[shred.shard_index] = Some(bytes.to_vec());
        self.root.get_or_insert(root);
        self.signature.get_or_insert_with(|| signature.to_vec());
        self.chained_root.get_or_insert_with(|| chained.to_vec());

        // t0 is the earliest arrival, even if shreds are pushed out of order
        self.first_seen_ns = Some(match self.first_seen_ns {
            Some(t) => t.min(shred.recv_ns),
            None => shred.recv_ns,
        });
        // t1 is set once, by the shred that brings the count to 32
        if self.decodable_ns.is_none() && self.received() == DATA_SHREDS {
            self.decodable_ns = Some(shred.recv_ns);
        }

        Ok(true)
    }

    /// Unique shreds held, data and coding.
    pub fn received(&self) -> usize {
        self.shards.iter().filter(|s| s.is_some()).count()
    }

    /// Data shreds held.
    pub fn data_received(&self) -> usize {
        self.shards[..DATA_SHREDS]
            .iter()
            .filter(|s| s.is_some())
            .count()
    }

    /// All 32 data shards present, nothing to rebuild.
    pub fn is_complete(&self) -> bool {
        self.data_received() == DATA_SHREDS
    }

    /// Any 32 of the 64 are enough to rebuild the data.
    pub fn can_recover(&self) -> bool {
        self.received() >= DATA_SHREDS
    }

    /// Rebuilds missing shards and checks the result against the set's root.
    /// Does nothing if the data is already complete.
    pub fn recover(&mut self) -> Result<()> {
        if self.is_complete() {
            return Ok(());
        }
        if !self.can_recover() {
            return Err(self.too_few());
        }
        // built per call rather than once in a static, so nothing here can panic
        let rs = ReedSolomon::new(DATA_SHREDS, CODING_SHREDS)?;
        // fills every None place, coding too, since the tree needs all 64 leaves
        rs.reconstruct(&mut self.shards)?;
        self.recovered = true;
        self.check_rebuilt_root()
    }

    /// Builds the whole Merkle tree from the 64 shards and checks it ends at the set's root.
    fn check_rebuilt_root(&self) -> Result<()> {
        let mismatch = Error::RebuiltRootMismatch;
        let (Some(root), Some(chained), Some(header)) =
            (self.root, &self.chained_root, &self.coding_header)
        else {
            return Err(mismatch);
        };

        // coding shreds of a set differ only in index and position, so the first one's
        // index is this header's index minus its position
        let first_index = wire::index(header)?
            .checked_sub(u32::from(wire::position(header)?))
            .ok_or(Error::RebuiltRootMismatch)?;

        let mut leaves = Vec::with_capacity(TOTAL_SHREDS);
        for (i, shard) in self.shards.iter().enumerate() {
            let shard = shard.as_deref().ok_or(self.too_few())?;
            // a data shard starts right after the signature, so it already holds its headers
            if i < DATA_SHREDS {
                leaves.push(merkle::leaf(&[shard, chained]));
                continue;
            }
            let position = (i - DATA_SHREDS) as u16;
            let index = first_index
                .checked_add(u32::from(position))
                .ok_or(Error::RebuiltRootMismatch)?;
            let mut own = header.clone();
            own[wire::INDEX].copy_from_slice(&index.to_le_bytes());
            own[wire::POSITION].copy_from_slice(&position.to_le_bytes());
            // the leaf starts after the signature, like every other leaf
            leaves.push(merkle::leaf(&[&own[wire::SIGNATURE.end..], shard, chained]));
        }

        if merkle::tree_root(&leaves) == Some(root) {
            Ok(())
        } else {
            Err(mismatch)
        }
    }

    /// The 32 data shards in order, ready for the block decoder.
    pub fn data_shards(&self) -> Result<Vec<&[u8]>> {
        self.shards[..DATA_SHREDS]
            .iter()
            .map(|s| s.as_deref().ok_or(self.too_few()))
            .collect()
    }

    fn too_few(&self) -> Error {
        Error::TooFewShreds {
            have: self.received(),
            need: DATA_SHREDS,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::shred::Shred;

    // One complete real FEC set from real-10s.pcap, slot 449661784, fec_set_index 96.
    // 32 data shreds (1203 bytes) then 32 coding shreds (1228 bytes), in shard index order.
    const SET: &[u8] = include_bytes!("../tests/fixtures/real-fec-set.bin");

    fn raw(shard_index: usize) -> &'static [u8] {
        if shard_index < 32 {
            &SET[shard_index * 1203..(shard_index + 1) * 1203]
        } else {
            let start = 32 * 1203 + (shard_index - 32) * 1228;
            &SET[start..start + 1228]
        }
    }

    // shred with shard index i arrives at 1000 + 10 * i ns
    fn shred(shard_index: usize) -> Shred {
        Shred::parse(raw(shard_index), 1_000 + 10 * shard_index as u64).unwrap()
    }

    fn new_set() -> FecSet {
        FecSet::new(449_661_784, 96)
    }

    // original data shard bytes at 64..1051, to compare recovery against
    fn original_data_shard(shard_index: usize) -> &'static [u8] {
        &raw(shard_index)[64..1051]
    }

    #[test]
    fn test_new_set_is_empty() {
        let set = new_set();
        assert_eq!(set.received(), 0);
        assert!(!set.is_complete());
        assert!(!set.can_recover());
        assert_eq!(set.first_seen_ns, None);
        assert_eq!(set.decodable_ns, None);
        assert!(!set.recovered);
    }

    #[test]
    fn test_all_data_is_complete() {
        let mut set = new_set();
        for i in 0..32 {
            assert!(set.push(shred(i)).unwrap());
        }
        assert_eq!(set.received(), 32);
        assert_eq!(set.data_received(), 32);
        assert!(set.is_complete());

        let shards = set.data_shards().unwrap();
        assert_eq!(shards.len(), 32);
        for (i, s) in shards.iter().enumerate() {
            assert_eq!(*s, original_data_shard(i));
        }
    }

    #[test]
    fn test_complete_needs_no_recovery() {
        let mut set = new_set();
        for i in 0..64 {
            set.push(shred(i)).unwrap();
        }
        set.recover().unwrap();
        assert!(!set.recovered);
    }

    #[test]
    fn test_duplicate_is_ignored() {
        let mut set = new_set();
        assert!(set.push(shred(5)).unwrap());
        assert!(!set.push(shred(5)).unwrap());
        assert_eq!(set.received(), 1);
    }

    #[test]
    fn test_changed_shred_refused() {
        let mut set = new_set();
        set.push(shred(0)).unwrap();
        // one flipped byte in the block data of shard 5
        let mut changed = shred(5);
        changed.bytes[200] ^= 1;
        assert!(matches!(
            set.push(changed),
            Err(Error::MerkleRootMismatch { shard_index: 5 })
        ));
        assert_eq!(set.received(), 1);
        // the real shard 5 still gets in afterwards
        assert!(set.push(shred(5)).unwrap());
    }

    #[test]
    fn test_wrong_set_rejected() {
        let mut set = FecSet::new(449_661_784, 128);
        assert!(matches!(set.push(shred(0)), Err(Error::WrongFecSet { .. })));
        assert_eq!(set.received(), 0);
    }

    #[test]
    fn test_first_seen_is_earliest() {
        let mut set = new_set();
        set.push(shred(20)).unwrap(); // 1200 ns
        set.push(shred(3)).unwrap(); // 1030 ns
        assert_eq!(set.first_seen_ns, Some(1_030));
    }

    #[test]
    fn test_decodable_when_32nd_shred_arrives() {
        // any 32 of the 64 rebuild the set, so t1 is when the 32nd unique shred lands
        let mut set = new_set();
        for i in 33..64 {
            set.push(shred(i)).unwrap();
        }
        assert_eq!(set.decodable_ns, None);
        set.push(shred(0)).unwrap(); // the 32nd, at 1000 ns
        assert_eq!(set.decodable_ns, Some(1_000));
        set.push(shred(1)).unwrap(); // later shreds don't move t1
        assert_eq!(set.decodable_ns, Some(1_000));
    }

    #[test]
    fn test_recover_missing_data() {
        // drop 5 data and 3 coding shreds, rebuild, compare with the real bytes
        let dropped = [0, 3, 10, 17, 31, 33, 40, 50];
        let mut set = new_set();
        for i in (0..64).filter(|i| !dropped.contains(i)) {
            set.push(shred(i)).unwrap();
        }
        assert!(!set.is_complete());
        assert!(set.can_recover());

        set.recover().unwrap();
        assert!(set.recovered);
        assert!(set.is_complete());

        let shards = set.data_shards().unwrap();
        for (i, s) in shards.iter().enumerate() {
            assert_eq!(*s, original_data_shard(i), "data shard {i}");
        }
    }

    #[test]
    fn test_recover_from_coding_only() {
        // every data shred lost, all 32 rebuilt from parity
        let mut set = new_set();
        for i in 32..64 {
            set.push(shred(i)).unwrap();
        }
        assert_eq!(set.data_received(), 0);
        set.recover().unwrap();

        let shards = set.data_shards().unwrap();
        for (i, s) in shards.iter().enumerate() {
            assert_eq!(*s, original_data_shard(i), "data shard {i}");
        }
    }

    #[test]
    fn test_wrong_rebuild_caught_by_the_root() {
        // a shard that changed after its proof was checked, so Reed-Solomon rebuilds wrong data
        let mut set = new_set();
        for i in (0..16).chain(32..48) {
            set.push(shred(i)).unwrap();
        }
        if let Some(shard) = set.shards[40].as_mut() {
            shard[100] ^= 1;
        }
        assert!(matches!(set.recover(), Err(Error::RebuiltRootMismatch)));
    }

    #[test]
    fn test_too_few_shreds() {
        let mut set = new_set();
        for i in 1..32 {
            set.push(shred(i)).unwrap();
        }
        assert!(!set.can_recover());
        assert!(matches!(
            set.recover(),
            Err(Error::TooFewShreds { have: 31, need: 32 })
        ));
        assert!(matches!(
            set.data_shards(),
            Err(Error::TooFewShreds { have: 31, need: 32 })
        ));
    }

    #[test]
    fn test_unsupported_erasure_config() {
        // Agave only recovers 32 data and 32 coding sets, so we only accept those
        let mut bytes = raw(40).to_vec();
        bytes[83..85].copy_from_slice(&16u16.to_le_bytes());
        let s = Shred::parse(&bytes, 0).unwrap();
        let mut set = new_set();
        assert!(matches!(
            set.push(s),
            Err(Error::UnsupportedErasureConfig {
                num_data: 16,
                num_coding: 32
            })
        ));
    }

    #[test]
    fn test_shard_index_out_of_range() {
        // a data shred claiming to be the 41st data shred of a 32 data shred set
        let mut bytes = raw(0).to_vec();
        bytes[73..77].copy_from_slice(&(96u32 + 40).to_le_bytes());
        let s = Shred::parse(&bytes, 0).unwrap();
        let mut set = new_set();
        assert!(matches!(set.push(s), Err(Error::ShardIndexOutOfRange(40))));
    }
}
