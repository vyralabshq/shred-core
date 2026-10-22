//! Turns data shards into block components, either entry batches or block markers.
//!
//! data_payload takes the block bytes out of one data shard, skipping its headers and padding.
//! The flags say whether a shard ends a batch or ends the slot.
//! Batcher joins payloads in index order and hands over a batch when a shard ends one.
//! decode_component reads the batch, an entry count above 0 means entries with transactions,
//! 0 means a block marker such as the header or the footer.
//! Data shards start at packet byte 64, so packet offsets are shifted by 64 in here.

use crate::error::{Error, Result};
use crate::wire;
use solana_hash::Hash;
use solana_transaction::versioned::VersionedTransaction;
use wincode::SchemaRead;

/// A data shard starts at packet byte 64 (right after the signature), so packet offsets shift by 64.
const SHARD_START: usize = wire::SIGNATURE.end;
/// Flag bit on the last data shred of an entry batch.
const DATA_COMPLETE: u8 = 0b0100_0000;
/// Flag bits on the last data shred of the slot (implies DATA_COMPLETE).
const LAST_IN_SLOT: u8 = 0b1100_0000;
/// A block component starts with an 8 byte entry count, 0 means a block marker follows.
const ENTRY_COUNT_SIZE: usize = 8;
/// End of the marker header, which follows the zero count as version (2), variant (1) and data length (2).
const MARKER_HEADER_END: usize = ENTRY_COUNT_SIZE + 5;

/// Returns the block bytes inside a data shard, from the end of the 88 byte headers up to the `size` field.
pub fn data_payload(shard: &[u8]) -> Result<&[u8]> {
    // the size field is packet bytes 86..88, which is shard bytes 22..24
    let size_range = wire::DATA_SIZE.start - SHARD_START..wire::DATA_SIZE.end - SHARD_START;
    let expected = size_range.end;
    let size_bytes = shard.get(size_range).ok_or(Error::TooShort {
        expected,
        actual: shard.len(),
    })?;
    let size = u16::from_le_bytes([size_bytes[0], size_bytes[1]]);

    // size counts from packet byte 0, so it must cover the headers and end inside the shard
    let start = wire::DATA_HEADER_SIZE - SHARD_START;
    let end = usize::from(size)
        .checked_sub(SHARD_START)
        .filter(|end| *end >= start && *end <= shard.len())
        .ok_or(Error::InvalidDataSize {
            size,
            shard_len: shard.len(),
        })?;

    Ok(&shard[start..end])
}

/// Reads the flags byte of a data shard, packet byte 85 or shard byte 21.
fn flags(shard: &[u8]) -> Result<u8> {
    let at = wire::FLAGS - SHARD_START;
    shard.get(at).copied().ok_or(Error::TooShort {
        expected: at + 1,
        actual: shard.len(),
    })
}

/// True on the last data shred of an entry batch.
pub fn is_batch_end(shard: &[u8]) -> Result<bool> {
    Ok(flags(shard)? & DATA_COMPLETE != 0)
}

/// True on the last data shred of the slot.
pub fn is_last_in_slot(shard: &[u8]) -> Result<bool> {
    Ok(flags(shard)? & LAST_IN_SLOT == LAST_IN_SLOT)
}

/// Joins data shard payloads in index order and hands over each finished batch.
#[derive(Debug, Default)]
pub struct Batcher {
    buf: Vec<u8>,
}

impl Batcher {
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds the next data shard of the slot. Some(batch) when this shard ends a batch.
    pub fn push(&mut self, shard: &[u8]) -> Result<Option<Vec<u8>>> {
        self.buf.extend_from_slice(data_payload(shard)?);
        if is_batch_end(shard)? {
            // take leaves an empty buffer behind, ready for the next batch
            Ok(Some(std::mem::take(&mut self.buf)))
        } else {
            Ok(None)
        }
    }
}

/// Entry count above 0 is an entry batch, 0 means a block marker follows.
pub fn decode_component(batch: &[u8]) -> Result<Component> {
    let count = batch.get(..ENTRY_COUNT_SIZE).ok_or(Error::TooShort {
        expected: ENTRY_COUNT_SIZE,
        actual: batch.len(),
    })?;

    if count != [0u8; ENTRY_COUNT_SIZE] {
        // the count is the Vec's own length prefix, so wincode reads it with the entries
        let entries = wincode::deserialize::<Vec<Entry>>(batch)?;
        return Ok(Component::Entries(entries));
    }

    let header = batch
        .get(ENTRY_COUNT_SIZE..MARKER_HEADER_END)
        .ok_or(Error::TooShort {
            expected: MARKER_HEADER_END,
            actual: batch.len(),
        })?;
    let version = u16::from_le_bytes([header[0], header[1]]);
    let variant = header[2];
    let len = usize::from(u16::from_le_bytes([header[3], header[4]]));

    let end = MARKER_HEADER_END + len;
    let data = batch.get(MARKER_HEADER_END..end).ok_or(Error::TooShort {
        expected: end,
        actual: batch.len(),
    })?;

    Ok(Component::Marker {
        version,
        variant,
        data: data.to_vec(),
    })
}

/// What one batch decodes to.
#[derive(Debug)]
pub enum Component {
    Entries(Vec<Entry>),
    /// Raw block marker. Variant 0 is the footer, 1 the header, 2 update parent, 3 genesis certificate.
    Marker {
        version: u16,
        variant: u8,
        data: Vec<u8>,
    },
}

/// One PoH entry, same wire layout as Agave's solana-entry Entry.
#[derive(Debug, SchemaRead)]
pub struct Entry {
    pub num_hashes: u64,
    pub hash: Hash,
    /// Empty for a tick entry.
    pub transactions: Vec<VersionedTransaction>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;
    use crate::shred::{Shred, layout};

    // Every data shred of slot 449661788 from real-10s.pcap, full 1203 byte packets in index order.
    // 128 data shreds, 4 FEC sets, the last set resigned. getBlock reports 26 transactions.
    const SLOT: &[u8] = include_bytes!("../tests/fixtures/real-slot.bin");
    const SLOT_SHREDS: usize = 128;

    // From getBlock 449661788 on the public testnet RPC.
    const FIRST_SIG: &str =
        "4AbpiMLynSZh6xhuKRvFVYWv56nAdgtiJ17kHMeTeHbjgAP4SQXxn6CBRzkF2TukHjAhaDappzuDgkZ9gXfmuNBu";
    const LAST_SIG: &str =
        "2Q6fhMTitpBvyP5WzzowF6EWCoQgRqh1tZxSi6rgBeaVxT3nGYHbMGgenT3tjXRw8ummmLmwkSdiT6JntDeJfL8Z";

    // the shard of data shred i, the same bytes a FecSet hands over
    fn shard(i: usize) -> &'static [u8] {
        let packet = &SLOT[i * 1203..(i + 1) * 1203];
        let shred = Shred::parse(packet, 0).unwrap();
        &packet[layout(shred.variant).unwrap().shard]
    }

    // every batch of the slot, in order, built with the Batcher
    fn batches() -> Vec<Vec<u8>> {
        let mut batcher = Batcher::new();
        (0..SLOT_SHREDS)
            .filter_map(|i| batcher.push(shard(i)).unwrap())
            .collect()
    }

    // data_payload returns the block bytes after the 88 byte headers, up to `size`

    #[test]
    fn test_payload_real() {
        // shred 0 has size 142, so it carries 54 bytes, the block header marker
        let p = data_payload(shard(0)).unwrap();
        assert_eq!(p.len(), 142 - 88);
        assert_eq!(p[..8], [0u8; 8]);
    }

    #[test]
    fn test_payload_empty() {
        // shred 1 has size 88, headers only, padding up to a full FEC set
        assert!(data_payload(shard(1)).unwrap().is_empty());
    }

    #[test]
    fn test_payload_bad_size() {
        // size field sits at shard bytes 22..24 (packet bytes 86..88)
        let mut s = shard(0).to_vec();
        s[22..24].copy_from_slice(&2000u16.to_le_bytes());
        assert!(matches!(
            data_payload(&s),
            Err(Error::InvalidDataSize { size: 2000, .. })
        ));
        s[22..24].copy_from_slice(&50u16.to_le_bytes());
        assert!(matches!(
            data_payload(&s),
            Err(Error::InvalidDataSize { size: 50, .. })
        ));
    }

    #[test]
    fn test_payload_too_short() {
        assert!(matches!(
            data_payload(&[0u8; 10]),
            Err(Error::TooShort { .. })
        ));
    }

    // flag 0b0100_0000 ends a batch, 0b1100_0000 marks the last shred of the slot
    #[test]
    fn test_flags_real() {
        assert!(!is_batch_end(shard(0)).unwrap());
        assert!(is_batch_end(shard(31)).unwrap());
        assert!(!is_last_in_slot(shard(31)).unwrap());
        // 0x7f is batch end plus a reference tick of 63 in the low bits
        assert!(is_batch_end(shard(95)).unwrap());
        assert!(!is_last_in_slot(shard(95)).unwrap());
        // 0xff on the resigned last shred
        assert!(is_batch_end(shard(127)).unwrap());
        assert!(is_last_in_slot(shard(127)).unwrap());
    }

    // Batcher joins payloads until a batch end flag, then hands the batch over
    #[test]
    fn test_batcher_splits_slot() {
        let mut batcher = Batcher::new();
        let mut ends = vec![];
        for i in 0..SLOT_SHREDS {
            if batcher.push(shard(i)).unwrap().is_some() {
                ends.push(i);
            }
        }
        assert_eq!(ends, [31, 63, 95, 127]);
    }

    #[test]
    fn test_batcher_joins_payloads() {
        // a batch is exactly the payloads of its shreds, back to back
        let mut joined = vec![];
        for i in 0..32 {
            joined.extend_from_slice(data_payload(shard(i)).unwrap());
        }
        assert_eq!(batches()[0], joined);
    }

    // entry count above 0 is an entry batch, 0 is a block marker
    #[test]
    fn test_first_batch_is_header_marker() {
        match decode_component(&batches()[0]).unwrap() {
            Component::Marker {
                version,
                variant,
                data,
            } => {
                assert_eq!(version, 1);
                assert_eq!(variant, 1); // 1 is the block header
                assert_eq!(data.len(), 41);
            }
            Component::Entries(_) => panic!("first batch should be the header marker"),
        }
    }

    #[test]
    fn test_footer_then_final_tick() {
        // footer is the third batch, one tick entry follows it
        let b = batches();
        assert_eq!(b.len(), 4);
        match decode_component(&b[2]).unwrap() {
            Component::Marker { variant, .. } => assert_eq!(variant, 0), // 0 is the footer
            Component::Entries(_) => panic!("third batch should be the footer marker"),
        }
        match decode_component(&b[3]).unwrap() {
            Component::Entries(e) => {
                assert_eq!(e.len(), 1);
                assert!(e[0].transactions.is_empty()); // a tick carries no transactions
            }
            Component::Marker { .. } => panic!("last batch should be the final tick"),
        }
    }

    #[test]
    fn test_slot_matches_get_block() {
        let mut entries = 0;
        let mut sigs = vec![];
        for batch in batches() {
            if let Component::Entries(e) = decode_component(&batch).unwrap() {
                entries += e.len();
                for entry in e {
                    for tx in entry.transactions {
                        sigs.push(tx.signatures[0].to_string());
                    }
                }
            }
        }
        assert_eq!(entries, 12);
        assert_eq!(sigs.len(), 26);
        assert_eq!(sigs.first().unwrap(), FIRST_SIG);
        assert_eq!(sigs.last().unwrap(), LAST_SIG);
    }

    #[test]
    fn test_decode_too_short() {
        assert!(matches!(
            decode_component(&[0u8; 5]),
            Err(Error::TooShort {
                expected: 8,
                actual: 5
            })
        ));
    }

    #[test]
    fn test_decode_marker_truncated() {
        // marker says 41 bytes of data but only 3 follow
        let mut b = vec![0u8; 8];
        b.extend_from_slice(&1u16.to_le_bytes());
        b.push(1);
        b.extend_from_slice(&41u16.to_le_bytes());
        b.extend_from_slice(&[0u8; 3]);
        assert!(matches!(
            decode_component(&b),
            Err(Error::TooShort {
                expected: 54,
                actual: 16
            })
        ));
    }

    #[test]
    fn test_decode_junk_entries() {
        // claims one entry, then garbage
        let mut b = 1u64.to_le_bytes().to_vec();
        b.extend_from_slice(&[0xFF; 20]);
        assert!(matches!(decode_component(&b), Err(Error::Decode(_))));
    }
}
