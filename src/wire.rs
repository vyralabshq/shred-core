//! Reads single fields straight from raw shred bytes, without parsing the whole shred.
//!
//! First come the byte offsets of every header field, the same for every Merkle shred.
//! Then small helpers that read 2, 4 or 8 little endian bytes and fail with TooShort instead of panicking.
//! Then one reader per field, in the order the fields sit in the shred.
//! The common header (signature to fec_set_index) is shared by data and coding shreds,
//! after it data shreds have a data header and coding shreds a coding header at the same offsets.

use crate::error::{Error, Result};
use std::ops::Range;

// Common header
pub const SIGNATURE: Range<usize> = 0..64;
pub const VARIANT: usize = 64;
pub const SLOT: Range<usize> = 65..73;
pub const INDEX: Range<usize> = 73..77;
pub const VERSION: Range<usize> = 77..79;
pub const FEC_SET_INDEX: Range<usize> = 79..83;
pub const COMMON_HEADER_SIZE: usize = 83;

// Data header
pub const PARENT_OFFSET: Range<usize> = 83..85;
pub const FLAGS: usize = 85;
pub const DATA_SIZE: Range<usize> = 86..88;
pub const DATA_HEADER_SIZE: usize = 88;
pub const DATA_PAYLOAD_SIZE: usize = 1203;

// Coding header
pub const NUM_DATA: Range<usize> = 83..85;
pub const NUM_CODING: Range<usize> = 85..87;
pub const POSITION: Range<usize> = 87..89;
pub const CODING_HEADER_SIZE: usize = 89;
pub const CODING_PAYLOAD_SIZE: usize = 1228;

/// Returns the bytes in `range`, or TooShort if the packet ends before it.
fn read_bytes(bytes: &[u8], range: Range<usize>) -> Result<&[u8]> {
    let expected = range.end;
    bytes.get(range).ok_or(Error::TooShort {
        expected,
        actual: bytes.len(),
    })
}

fn read_u16(bytes: &[u8], range: Range<usize>) -> Result<u16> {
    let bytes = read_bytes(bytes, range)?;
    let mut arr = [0u8; 2];
    arr.copy_from_slice(bytes);
    let value = u16::from_le_bytes(arr);
    Ok(value)
}

fn read_u32(bytes: &[u8], range: Range<usize>) -> Result<u32> {
    let bytes = read_bytes(bytes, range)?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(bytes);
    let value = u32::from_le_bytes(arr);
    Ok(value)
}

fn read_u64(bytes: &[u8], range: Range<usize>) -> Result<u64> {
    let bytes = read_bytes(bytes, range)?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(bytes);
    let value = u64::from_le_bytes(arr);
    Ok(value)
}

/// Raw variant byte, shred type in the high 4 bits and Merkle proof size in the low 4.
pub fn variant(bytes: &[u8]) -> Result<u8> {
    let variant = bytes.get(VARIANT).copied().ok_or(Error::TooShort {
        expected: VARIANT + 1,
        actual: bytes.len(),
    })?;

    Ok(variant)
}

/// Slot this shred belongs to.
pub fn slot(bytes: &[u8]) -> Result<u64> {
    let slot = read_u64(bytes, SLOT)?;
    Ok(slot)
}

/// Position of this shred within its slot.
pub fn index(bytes: &[u8]) -> Result<u32> {
    let index = read_u32(bytes, INDEX)?;
    Ok(index)
}

/// Shred version, which identifies the cluster the shred is for.
pub fn version(bytes: &[u8]) -> Result<u16> {
    let version = read_u16(bytes, VERSION)?;
    Ok(version)
}

/// Index of the first data shred in this shred's FEC set.
pub fn fec_set_index(bytes: &[u8]) -> Result<u32> {
    let fec_set_index = read_u32(bytes, FEC_SET_INDEX)?;
    Ok(fec_set_index)
}

/// How many slots back the parent slot is (data shreds).
pub fn parent_offset(bytes: &[u8]) -> Result<u16> {
    let parent_offset = read_u16(bytes, PARENT_OFFSET)?;
    Ok(parent_offset)
}

/// Reference tick plus the batch complete and last in slot bits (data shreds).
pub fn flags(bytes: &[u8]) -> Result<u8> {
    let flags = bytes.get(FLAGS).copied().ok_or(Error::TooShort {
        expected: FLAGS + 1,
        actual: bytes.len(),
    })?;
    Ok(flags)
}

/// End of the block data, counted from byte 0 with headers included (data shreds).
pub fn data_size(bytes: &[u8]) -> Result<u16> {
    let data_size = read_u16(bytes, DATA_SIZE)?;
    Ok(data_size)
}

/// Number of data shreds in the FEC set (coding shreds).
pub fn num_data(bytes: &[u8]) -> Result<u16> {
    let num_data = read_u16(bytes, NUM_DATA)?;
    Ok(num_data)
}

/// Number of coding shreds in the FEC set (coding shreds).
pub fn num_coding(bytes: &[u8]) -> Result<u16> {
    let num_coding = read_u16(bytes, NUM_CODING)?;
    Ok(num_coding)
}

/// Its place among the coding shreds of the set (coding shreds).
pub fn position(bytes: &[u8]) -> Result<u16> {
    let position = read_u16(bytes, POSITION)?;
    Ok(position)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    // First data shred (0x96) and first coding shred (0x66) from our sample data.
    // headers only. Same slot and FEC set, so the same signature.
    pub const REAL_DATA: [u8; 88] = [
        0x48, 0xfb, 0x02, 0xfc, 0xc0, 0x86, 0x6e, 0xf7, 0xff, 0x19, 0x7d, 0x95, 0x4e, 0xb7, 0xfc,
        0xd9, 0x6a, 0x6d, 0xf2, 0xda, 0x37, 0xc3, 0x0e, 0x4e, 0xdb, 0x6a, 0xa6, 0xa6, 0xc7, 0x0e,
        0xdc, 0x26, 0xa0, 0x3f, 0xfb, 0x2d, 0x95, 0x65, 0x34, 0xde, 0x45, 0x26, 0x4c, 0x6b, 0x65,
        0x9f, 0xc4, 0x55, 0x82, 0x32, 0x84, 0x8e, 0x63, 0xad, 0x13, 0x78, 0xbf, 0x59, 0x31, 0xbc,
        0xb8, 0x81, 0x8a, 0x00, 0x96, 0x41, 0x4b, 0xcd, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00,
        0x00, 0x00, 0x69, 0x11, 0x40, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x1b, 0x04,
    ];

    pub const REAL_CODE: [u8; 89] = [
        0x48, 0xfb, 0x02, 0xfc, 0xc0, 0x86, 0x6e, 0xf7, 0xff, 0x19, 0x7d, 0x95, 0x4e, 0xb7, 0xfc,
        0xd9, 0x6a, 0x6d, 0xf2, 0xda, 0x37, 0xc3, 0x0e, 0x4e, 0xdb, 0x6a, 0xa6, 0xa6, 0xc7, 0x0e,
        0xdc, 0x26, 0xa0, 0x3f, 0xfb, 0x2d, 0x95, 0x65, 0x34, 0xde, 0x45, 0x26, 0x4c, 0x6b, 0x65,
        0x9f, 0xc4, 0x55, 0x82, 0x32, 0x84, 0x8e, 0x63, 0xad, 0x13, 0x78, 0xbf, 0x59, 0x31, 0xbc,
        0xb8, 0x81, 0x8a, 0x00, 0x66, 0x41, 0x4b, 0xcd, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x57, 0x00,
        0x00, 0x00, 0x69, 0x11, 0x40, 0x00, 0x00, 0x00, 0x20, 0x00, 0x20, 0x00, 0x17, 0x00,
    ];

    #[test]
    fn test_byte_range() {
        let bytes = [0u8; 10];
        let range = 0..5;
        assert_eq!(read_bytes(&bytes, range).unwrap(), &bytes[0..5]);

        let range = 5..10;
        assert_eq!(read_bytes(&bytes, range).unwrap(), &bytes[5..10]);
    }

    #[test]
    fn test_fail_byte_range() {
        let bytes = [0u8; 5];
        let range = 0..10;
        assert!(read_bytes(&bytes, range).is_err());
    }

    #[test]
    fn test_slot() {
        let mut bytes = [0xFFu8; COMMON_HEADER_SIZE];
        bytes[SLOT].copy_from_slice(&444_700_123u64.to_le_bytes());
        assert_eq!(slot(&bytes).unwrap(), 444_700_123);
    }

    #[test]
    fn test_slot_fail() {
        let bytes = [0u8; 72];
        assert!(matches!(
            slot(&bytes),
            Err(Error::TooShort {
                expected: 73,
                actual: 72
            })
        ));
    }

    #[test]
    fn test_variant() {
        let mut bytes = [0xFFu8; COMMON_HEADER_SIZE];
        // literal 64, not VARIANT, so a wrong const fails here
        bytes[64] = 0x96;
        assert_eq!(variant(&bytes).unwrap(), 0x96);
    }

    #[test]
    fn test_variant_fail() {
        // 64 bytes is only the signature, the variant byte is missing
        let bytes = [0u8; 64];
        assert!(matches!(
            variant(&bytes),
            Err(Error::TooShort {
                expected: 65,
                actual: 64
            })
        ));
    }

    #[test]
    fn test_index() {
        let mut bytes = [0xFFu8; COMMON_HEADER_SIZE];
        bytes[INDEX].copy_from_slice(&0x0102_0304u32.to_le_bytes());
        assert_eq!(index(&bytes).unwrap(), 0x0102_0304);
    }

    #[test]
    fn test_index_fail() {
        let bytes = [0u8; 76];
        assert!(matches!(
            index(&bytes),
            Err(Error::TooShort {
                expected: 77,
                actual: 76
            })
        ));
    }

    #[test]
    fn test_version() {
        let mut bytes = [0xFFu8; COMMON_HEADER_SIZE];
        bytes[VERSION].copy_from_slice(&200u16.to_le_bytes());
        assert_eq!(version(&bytes).unwrap(), 200);
    }

    #[test]
    fn test_version_fail() {
        let bytes = [0u8; 78];
        assert!(matches!(
            version(&bytes),
            Err(Error::TooShort {
                expected: 79,
                actual: 78
            })
        ));
    }

    #[test]
    fn test_fec_set_index() {
        let mut bytes = [0xFFu8; COMMON_HEADER_SIZE];
        bytes[FEC_SET_INDEX].copy_from_slice(&96u32.to_le_bytes());
        assert_eq!(fec_set_index(&bytes).unwrap(), 96);
    }

    #[test]
    fn test_fec_set_index_fail() {
        let bytes = [0u8; 82];
        assert!(matches!(
            fec_set_index(&bytes),
            Err(Error::TooShort {
                expected: 83,
                actual: 82
            })
        ));
    }

    #[test]
    fn test_real_data_common_header() {
        assert_eq!(variant(&REAL_DATA).unwrap(), 0x96);
        assert_eq!(slot(&REAL_DATA).unwrap(), 449_661_761);
        assert_eq!(index(&REAL_DATA).unwrap(), 74);
        assert_eq!(version(&REAL_DATA).unwrap(), 4457);
        assert_eq!(fec_set_index(&REAL_DATA).unwrap(), 64);
    }

    #[test]
    fn test_real_code_common_header() {
        assert_eq!(variant(&REAL_CODE).unwrap(), 0x66);
        assert_eq!(slot(&REAL_CODE).unwrap(), 449_661_761);
        assert_eq!(index(&REAL_CODE).unwrap(), 87);
        assert_eq!(version(&REAL_CODE).unwrap(), 4457);
        assert_eq!(fec_set_index(&REAL_CODE).unwrap(), 64);
    }

    #[test]
    fn test_real_same_signature() {
        assert_eq!(REAL_DATA[SIGNATURE], REAL_CODE[SIGNATURE]);
    }

    #[test]
    fn test_real_data_header() {
        assert_eq!(parent_offset(&REAL_DATA).unwrap(), 1);
        assert_eq!(flags(&REAL_DATA).unwrap(), 0);
        assert_eq!(data_size(&REAL_DATA).unwrap(), 1051);
    }

    #[test]
    fn test_flags_last_in_slot() {
        let mut bytes = [0xFFu8; 88];
        bytes[85] = 0b1100_0000;
        assert_eq!(flags(&bytes).unwrap(), 0b1100_0000);
    }

    #[test]
    fn test_data_header_fail() {
        assert!(matches!(
            parent_offset(&[0u8; 84]),
            Err(Error::TooShort {
                expected: 85,
                actual: 84
            })
        ));
        assert!(matches!(
            flags(&[0u8; 85]),
            Err(Error::TooShort {
                expected: 86,
                actual: 85
            })
        ));
        assert!(matches!(
            data_size(&[0u8; 87]),
            Err(Error::TooShort {
                expected: 88,
                actual: 87
            })
        ));
    }

    // Coding header readers, yours to implement

    #[test]
    fn test_real_code_header() {
        assert_eq!(num_data(&REAL_CODE).unwrap(), 32);
        assert_eq!(num_coding(&REAL_CODE).unwrap(), 32);
        assert_eq!(position(&REAL_CODE).unwrap(), 23);
        // position is this shred's place among the coding shreds of the set
        assert_eq!(
            fec_set_index(&REAL_CODE).unwrap() + position(&REAL_CODE).unwrap() as u32,
            index(&REAL_CODE).unwrap()
        );
    }

    #[test]
    fn test_code_header_fail() {
        assert!(matches!(
            num_data(&[0u8; 84]),
            Err(Error::TooShort {
                expected: 85,
                actual: 84
            })
        ));
        assert!(matches!(
            num_coding(&[0u8; 86]),
            Err(Error::TooShort {
                expected: 87,
                actual: 86
            })
        ));
        assert!(matches!(
            position(&[0u8; 88]),
            Err(Error::TooShort {
                expected: 89,
                actual: 88
            })
        ));
    }
}
