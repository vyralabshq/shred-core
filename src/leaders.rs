//! Who led each slot, and whether a shred really comes from that leader.
//!
//! The leader signs the Merkle root of every FEC set it makes, once, and every shred of
//! the set carries that signature in its first 64 bytes. Checking it against the slot
//! leader's public key proves the whole set came from the leader, as Agave's sigverify does.
//! The schedule is read from the text that solana leader-schedule prints,
//! one slot and one base58 public key per line. Any other line is skipped.
//! A LeaderDir is a folder of such files, one per epoch, that a live run reads again
//! whenever a file in it is added, replaced or removed, so a new epoch needs no restart.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::str::FromStr;
use std::time::SystemTime;

use solana_address::Address;
use solana_signature::Signature;

use crate::error::Result;
use crate::merkle::Hash;
use crate::shred::Shred;
use crate::wire;

/// An Ed25519 public key.
pub type Pubkey = [u8; 32];

/// The leader of every slot the schedule covers.
#[derive(Debug, Default, Clone)]
pub struct LeaderSchedule {
    leaders: HashMap<u64, Pubkey>,
}

impl LeaderSchedule {
    /// Reads a schedule, adding to the slots already known, so several epochs can be loaded.
    pub fn read(&mut self, reader: impl BufRead) -> Result<()> {
        for line in reader.lines() {
            let line = line?;
            let mut words = line.split_whitespace();
            let (Some(slot), Some(key), None) = (words.next(), words.next(), words.next()) else {
                continue;
            };
            let (Ok(slot), Ok(key)) = (slot.parse::<u64>(), Address::from_str(key)) else {
                continue;
            };
            self.leaders.insert(slot, key.to_bytes());
        }
        Ok(())
    }

    /// The leader of a slot, None if the schedule doesn't cover it.
    pub fn leader(&self, slot: u64) -> Option<&Pubkey> {
        self.leaders.get(&slot)
    }

    /// How many slots the schedule covers.
    pub fn len(&self) -> usize {
        self.leaders.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leaders.is_empty()
    }
}

/// A folder of schedule files ending in .txt. Anything else, like a file still being written, is skipped.
pub struct LeaderDir {
    path: PathBuf,
    /// Name, change time and size of every file at the last read.
    stamp: Vec<(PathBuf, SystemTime, u64)>,
}

impl LeaderDir {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            stamp: Vec::new(),
        }
    }

    /// Reads every file again if the folder changed since the last call, None if it did not.
    /// Looking costs one stat per file, so it can be called often.
    pub fn changed(&mut self) -> Result<Option<LeaderSchedule>> {
        let mut stamp = Vec::new();
        for entry in std::fs::read_dir(&self.path)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            let path = entry.path();
            if meta.is_file() && path.extension().is_some_and(|e| e == "txt") {
                stamp.push((path, meta.modified()?, meta.len()));
            }
        }
        stamp.sort();
        if stamp == self.stamp {
            return Ok(None);
        }
        let mut schedule = LeaderSchedule::default();
        for (path, ..) in &stamp {
            schedule.read(BufReader::new(File::open(path)?))?;
        }
        self.stamp = stamp;
        Ok(Some(schedule))
    }
}

/// True if the shred's signature is the leader's signature over this Merkle root.
pub fn signed_by(shred: &Shred, root: &Hash, leader: &Pubkey) -> bool {
    let Some(bytes) = shred.bytes.get(wire::SIGNATURE) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(bytes) else {
        return false;
    };
    signature.verify(leader, root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::shred_root;

    // From solana leader-schedule for testnet epoch 1053, the slots around the 10 second capture.
    const LEADERS: &str = include_str!("../tests/fixtures/real-leaders.txt");
    // Every data shred of slot 449661788 in index order.
    const SLOT: &[u8] = include_bytes!("../tests/fixtures/real-slot.bin");

    fn schedule() -> LeaderSchedule {
        let mut schedule = LeaderSchedule::default();
        schedule.read(LEADERS.as_bytes()).unwrap();
        schedule
    }

    #[test]
    fn test_read_schedule() {
        let mut s = schedule();
        assert_eq!(s.len(), 57);
        let leader = Address::from_str("F1jcLYJ1s8k4oYVy51J2RvYGh4sB1kWsUB2NaDrg6ejL").unwrap();
        assert_eq!(s.leader(449_661_788), Some(&leader.to_bytes()));
        assert_eq!(s.leader(1), None);
        // headers, blank lines and junk are skipped, a second file adds to the first
        s.read(
            "Leader schedule\n\n  12  notakey\n  5  F1jcLYJ1s8k4oYVy51J2RvYGh4sB1kWsUB2NaDrg6ejL\n"
                .as_bytes(),
        )
        .unwrap();
        assert_eq!(s.len(), 58);
    }

    #[test]
    fn test_folder_read_again_only_when_it_changes() {
        let dir = std::env::temp_dir().join(format!("shredtap-leaders-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut leaders = LeaderDir::new(&dir);
        // nothing to read yet, so there is no schedule and nothing is checked
        assert!(leaders.changed().unwrap().is_none());

        std::fs::write(dir.join("epoch-1053.txt"), LEADERS).unwrap();
        assert_eq!(leaders.changed().unwrap().unwrap().len(), 57);
        assert!(leaders.changed().unwrap().is_none());

        // a file still being written is skipped, a finished one is added
        std::fs::write(
            dir.join("epoch-1054.txt.tmp"),
            "  5  F1jcLYJ1s8k4oYVy51J2RvYGh4sB1kWsUB2NaDrg6ejL\n",
        )
        .unwrap();
        assert!(leaders.changed().unwrap().is_none());
        std::fs::rename(dir.join("epoch-1054.txt.tmp"), dir.join("epoch-1054.txt")).unwrap();
        assert_eq!(leaders.changed().unwrap().unwrap().len(), 58);

        // a past epoch removed
        std::fs::remove_file(dir.join("epoch-1053.txt")).unwrap();
        assert_eq!(leaders.changed().unwrap().unwrap().len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn test_real_shred_signed_by_its_leader() {
        let shred = Shred::parse(&SLOT[..1203], 0).unwrap();
        let root = shred_root(&shred).unwrap();
        let s = schedule();
        assert!(signed_by(&shred, &root, s.leader(449_661_788).unwrap()));
        // not by the leader of the slot before, and not over another root
        assert!(!signed_by(&shred, &root, s.leader(449_661_784).unwrap()));
        assert!(!signed_by(
            &shred,
            &[0u8; 32],
            s.leader(449_661_788).unwrap()
        ));
    }
}
