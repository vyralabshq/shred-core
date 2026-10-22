//! Climbs a shred's Merkle proof up to the root of its FEC set.
//!
//! The leader hashes every shred of a set into a leaf, joins the leaves in pairs level by level
//! until one hash is left, the root, and signs only that root.
//! Each shred carries its proof, the sibling hash at every level on the way up,
//! so one shred alone is enough to climb back to the root.
//!
//! The functions below run in this order.
//! 1. shred_root cuts a shred into the bytes it commits to and its proof.
//! 2. leaf hashes those bytes, from just after the signature to just before the proof.
//! 3. root_from_proof does the climb. The shard index says at each level whether the shred is
//!    the left child (even) or the right child (odd), then it is halved for the next level up.
//! 4. join hashes two children into their parent, entry and sha256 are its helpers.
//!
//! tree_root builds the whole tree from all 64 leaves instead, the way the leader does.
//! A shred rebuilt by Reed-Solomon has no proof of its own, so this is how a rebuilt set is checked.
//!
//! The prefixes and the 20 byte cut follow Agave merkle_tree.rs and merkle.rs.

use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::shred::{Shred, layout};
use crate::wire;

/// Leaves and parents hash with different prefixes, so a parent can never pass as a leaf.
const LEAF_PREFIX: &[u8] = b"\x00SOLANA_MERKLE_SHREDS_LEAF";
const NODE_PREFIX: &[u8] = b"\x01SOLANA_MERKLE_SHREDS_NODE";

/// Parents join only the first 20 bytes of each child, which is why proof entries are 20 bytes.
pub const PROOF_ENTRY_SIZE: usize = 20;

/// A SHA-256 hash, a leaf, a parent or a root.
pub type Hash = [u8; 32];

/// The root of the FEC set this shred claims to belong to, from the shred alone.
pub fn shred_root(shred: &Shred) -> Result<Hash> {
    let parts = layout(shred.variant)?;
    // the signature signs the root and the proof can't cover itself, so both are left out
    let covered = wire::SIGNATURE.end..parts.proof.start;
    let too_short = || Error::TooShort {
        expected: parts.proof.end,
        actual: shred.bytes.len(),
    };
    let covered = shred.bytes.get(covered).ok_or_else(too_short)?;
    let proof = shred.bytes.get(parts.proof.clone()).ok_or_else(too_short)?;
    root_from_proof(shred.shard_index, leaf(&[covered]), proof)
}

/// The leaf of a shred from the bytes it commits to, given in one or more parts.
pub fn leaf(covered: &[&[u8]]) -> Hash {
    let mut parts = vec![LEAF_PREFIX];
    parts.extend_from_slice(covered);
    sha256(&parts)
}

/// The root reached by climbing from a leaf at shard_index with its proof.
/// The proof must be whole 20 byte entries and exactly long enough to bring the index to 0.
pub fn root_from_proof(shard_index: usize, leaf: Hash, proof: &[u8]) -> Result<Hash> {
    let (entries, rest) = proof.as_chunks::<PROOF_ENTRY_SIZE>();
    if !rest.is_empty() {
        return Err(Error::InvalidMerkleProof { shard_index });
    }

    let mut node = leaf;
    let mut index = shard_index;
    for sibling in entries {
        let me = entry(&node);
        // even means we are the left child, odd the right one
        node = if index.is_multiple_of(2) {
            join(&me, sibling)
        } else {
            join(sibling, &me)
        };
        index >>= 1;
    }

    // a proof too short for the index never reaches the top
    if index != 0 {
        return Err(Error::InvalidMerkleProof { shard_index });
    }
    Ok(node)
}

/// The parent of two sibling nodes, left first.
pub fn join(left: &[u8; PROOF_ENTRY_SIZE], right: &[u8; PROOF_ENTRY_SIZE]) -> Hash {
    sha256(&[NODE_PREFIX, left, right])
}

/// The root of the tree over these leaves, None if there are none.
/// Each level pairs neighbours, and a last node without a neighbour is paired with itself.
pub fn tree_root(leaves: &[Hash]) -> Option<Hash> {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| {
                let left = entry(&pair[0]);
                let right = pair.get(1).map_or(left, entry);
                join(&left, &right)
            })
            .collect();
    }
    level.first().copied()
}

/// The first 20 bytes of a node, the part a parent joins.
fn entry(node: &Hash) -> [u8; PROOF_ENTRY_SIZE] {
    let mut out = [0u8; PROOF_ENTRY_SIZE];
    out.copy_from_slice(&node[..PROOF_ENTRY_SIZE]);
    out
}

/// SHA-256 over several byte strings, as if they were one.
fn sha256(parts: &[&[u8]]) -> Hash {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    // One complete real FEC set, slot 449661784 set 96, 32 data then 32 coding shreds in shard order.
    const SET: &[u8] = include_bytes!("../tests/fixtures/real-fec-set.bin");
    // Every data shred of slot 449661788 in index order, 4 FEC sets, the last one resigned.
    const SLOT: &[u8] = include_bytes!("../tests/fixtures/real-slot.bin");

    fn set_shred(shard_index: usize) -> Shred {
        let bytes = if shard_index < 32 {
            &SET[shard_index * 1203..(shard_index + 1) * 1203]
        } else {
            let start = 32 * 1203 + (shard_index - 32) * 1228;
            &SET[start..start + 1228]
        };
        Shred::parse(bytes, 0).unwrap()
    }

    fn slot_shred(index: usize) -> Shred {
        Shred::parse(&SLOT[index * 1203..(index + 1) * 1203], 0).unwrap()
    }

    #[test]
    fn test_every_shred_of_a_set_climbs_to_one_root() {
        let root = shred_root(&set_shred(0)).unwrap();
        let mut leaves = Vec::new();
        for i in 0..64 {
            let shred = set_shred(i);
            assert_eq!(shred_root(&shred).unwrap(), root, "shard {i}");
            let covered = wire::SIGNATURE.end..layout(shred.variant).unwrap().proof.start;
            leaves.push(leaf(&[&shred.bytes[covered]]));
        }
        // building the whole tree from the 64 leaves ends at the same root
        assert_eq!(tree_root(&leaves), Some(root));
    }

    #[test]
    fn test_root_matches_the_next_sets_chained_root() {
        // each set stores the root of the set before it, written by the leader.
        // set 96 is resigned, its retransmitter signature sits outside what the leaf covers
        let roots: Vec<Hash> = (0..4)
            .map(|set| shred_root(&slot_shred(set * 32)).unwrap())
            .collect();
        for i in 0..128 {
            let shred = slot_shred(i);
            assert_eq!(shred_root(&shred).unwrap(), roots[i / 32], "index {i}");
            if i >= 32 {
                let chained = &shred.bytes[layout(shred.variant).unwrap().chained_merkle_root];
                assert_eq!(chained, roots[i / 32 - 1], "index {i}");
            }
        }
    }

    #[test]
    fn test_what_the_root_covers() {
        let root = shred_root(&set_shred(5)).unwrap();
        let parts = layout(set_shred(5).variant).unwrap();
        // one changed byte in the shard, the chained root or the proof leads somewhere else
        for at in [100, parts.chained_merkle_root.start, parts.proof.start + 3] {
            let mut shred = set_shred(5);
            shred.bytes[at] ^= 1;
            assert_ne!(shred_root(&shred).unwrap(), root, "byte {at}");
        }
        // so does the right shred at the wrong place in the tree
        let mut shred = set_shred(5);
        shred.shard_index = 4;
        assert_ne!(shred_root(&shred).unwrap(), root);
        // the signature signs the root, so it is not part of it
        let mut shred = set_shred(5);
        shred.bytes[0] ^= 1;
        assert_eq!(shred_root(&shred).unwrap(), root);
    }

    #[test]
    fn test_bad_proofs() {
        let l = leaf(&[b"x"]);
        // not whole entries
        assert!(matches!(
            root_from_proof(0, l, &[0u8; 30]),
            Err(Error::InvalidMerkleProof { shard_index: 0 })
        ));
        // 6 entries only reach the top from shard indexes below 64
        assert!(root_from_proof(63, l, &[0u8; 120]).is_ok());
        assert!(root_from_proof(64, l, &[0u8; 120]).is_err());
    }
}
