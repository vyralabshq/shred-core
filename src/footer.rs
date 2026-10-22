//! Reads the block footer, the marker the leader puts near the end of every slot.
//!
//! The footer holds the bank hash, the leader's clock when it made the block, its client
//! and version, and up to three vote certificates for earlier slots.
//! Its layout comes from Agave entry/src/block_component.rs (BlockFooterV1, v4.4.0-beta.0).
//! The marker data starts with a version tag of 1, then:
//!
//! bank hash 32, producer time u64, user agent u8 length + bytes,
//! final cert Option, skip reward cert Option, notar reward cert Option.
//!
//! An Option is one byte, 0 or 1, then the value if 1.
//! The final cert is slot u64, block id 32, final aggregate, notar aggregate Option.
//! An aggregate is a 96 byte BLS signature and a bitmap with a u16 length.
//! A reward cert is slot u64, block id 32 (notar only), a 96 byte signature
//! and a bitmap whose length is a ShortU16, 1 to 3 bytes of 7 bits each.
//! A bitmap is solana-signer-store encoded, a version byte (0 base 2, 1 base 3),
//! a u16 count of bits, then the bits, one per validator by stake rank. Base 3 packs two votes
//! per validator, five validators to a byte. Agave cuts the bitmap after its last signer.

use crate::error::{Error, Result};

/// A 32 byte hash, the bank hash or a block id.
pub type Hash = [u8; 32];

/// The only footer version Agave writes.
const FOOTER_VERSION: u8 = 1;
/// A compressed BLS signature, which shredtap skips.
const BLS_SIGNATURE_SIZE: usize = 96;
/// Bitmap versions from solana-signer-store.
const BASE2: u8 = 0;
const BASE3: u8 = 1;
/// Base 3 digits that fit in one byte, 3^5 = 243.
const BASE3_PER_BYTE: usize = 5;
/// A ShortU16 takes at most 3 bytes.
const SHORT_U16_MAX_BYTES: usize = 3;

/// One block footer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Footer {
    pub bank_hash: Hash,
    /// The leader's wall clock when it made the block, in Unix nanoseconds.
    pub producer_time_ns: u64,
    /// The leader's client and version, like agave/4.4.0-beta.0.
    pub user_agent: String,
    /// The highest finalized block the leader knew of, mostly the slot before.
    pub final_cert: Option<FinalCert>,
    /// Who voted skip on the slot 8 back, for vote rewards.
    pub skip_reward: Option<RewardCert>,
    /// Who voted notarize on the slot 8 back, for vote rewards.
    pub notar_reward: Option<RewardCert>,
}

/// Proof that a block was finalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalCert {
    pub slot: u64,
    pub block_id: Hash,
    /// Finalized in one round by 80% of stake. Otherwise in two, with a notarize cert alongside.
    pub fast: bool,
    pub finalize: Signers,
    pub notarize: Option<Signers>,
}

/// A vote reward certificate, block_id is only there on the notarize one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RewardCert {
    pub slot: u64,
    pub block_id: Option<Hash>,
    pub signers: Signers,
}

/// How long a certificate's bitmap is and how many signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Signers {
    /// Length of the bitmap. Agave cuts it after the last signer, so it is not the validator count.
    pub bits: u16,
    pub voted: u16,
    /// Signed the fallback vote instead, only in base 3 bitmaps.
    pub fallback: u16,
}

/// Reads a footer from its marker data, which must be the whole footer and nothing more.
pub fn decode_footer(data: &[u8]) -> Result<Footer> {
    let mut r = Reader { bytes: data, at: 0 };
    if r.u8()? != FOOTER_VERSION {
        return Err(Error::InvalidFooter("unknown footer version"));
    }
    let bank_hash = r.array()?;
    let producer_time_ns = u64::from_le_bytes(r.array()?);
    let user_agent_len = r.u8()?;
    let user_agent = String::from_utf8_lossy(r.take(usize::from(user_agent_len))?).into_owned();

    let final_cert = if r.present()? {
        Some(read_final_cert(&mut r)?)
    } else {
        None
    };

    let skip_reward = if r.present()? {
        Some(read_reward_cert(&mut r, false)?)
    } else {
        None
    };

    let notar_reward = if r.present()? {
        Some(read_reward_cert(&mut r, true)?)
    } else {
        None
    };

    // Agave's length prefix must match the footer exactly
    if r.at != data.len() {
        return Err(Error::InvalidFooter("bytes left after the footer"));
    }
    Ok(Footer {
        bank_hash,
        producer_time_ns,
        user_agent,
        final_cert,
        skip_reward,
        notar_reward,
    })
}

fn read_final_cert(r: &mut Reader) -> Result<FinalCert> {
    let slot = u64::from_le_bytes(r.array()?);
    let block_id = r.array()?;
    let finalize = read_aggregate(r)?;
    let notarize = if r.present()? {
        Some(read_aggregate(r)?)
    } else {
        None
    };
    Ok(FinalCert {
        slot,
        block_id,
        fast: notarize.is_none(),
        finalize,
        notarize,
    })
}

/// A signature and a bitmap with a u16 length, inside the final cert.
fn read_aggregate(r: &mut Reader) -> Result<Signers> {
    r.take(BLS_SIGNATURE_SIZE)?;
    let len = u16::from_le_bytes(r.array()?);
    read_signers(r.take(usize::from(len))?)
}

/// Counts the signers in a solana-signer-store bitmap, a version byte,
/// a u16 count of bits, then the bits for exactly that many.
pub fn read_signers(bitmap: &[u8]) -> Result<Signers> {
    let mut r = Reader {
        bytes: bitmap,
        at: 0,
    };
    let version = r.u8()?;
    let bits = u16::from_le_bytes(r.array()?);
    let count = usize::from(bits);
    let body = r.rest();

    let (voted, fallback) = match version {
        BASE2 => {
            if body.len() != count.div_ceil(8) {
                return Err(Error::InvalidFooter(
                    "base 2 bitmap size does not match its count",
                ));
            }
            // bits past the count in the last byte are not validators
            let voted = body
                .iter()
                .enumerate()
                .map(|(i, byte)| {
                    let left = count - i * 8;
                    let mask = if left >= 8 { 0xff } else { (1u8 << left) - 1 };
                    (byte & mask).count_ones()
                })
                .sum::<u32>();
            (voted, 0)
        }
        BASE3 => {
            if body.len() != count.div_ceil(BASE3_PER_BYTE) {
                return Err(Error::InvalidFooter(
                    "base 3 bitmap size does not match its count",
                ));
            }
            // each byte holds 5 validators, the lowest digit first, 1 voted and 2 voted fallback
            let (mut voted, mut fallback) = (0u32, 0u32);
            for (i, &byte) in body.iter().enumerate() {
                let mut digits = byte;
                for _ in 0..BASE3_PER_BYTE.min(count - i * BASE3_PER_BYTE) {
                    match digits % 3 {
                        1 => voted += 1,
                        2 => fallback += 1,
                        _ => {}
                    }
                    digits /= 3;
                }
            }
            (voted, fallback)
        }
        _ => return Err(Error::InvalidFooter("unknown bitmap version")),
    };

    // never more than the count, which is a u16
    let to_u16 = |n: u32| u16::try_from(n).map_err(|_| Error::InvalidFooter("signer count"));
    Ok(Signers {
        bits,
        voted: to_u16(voted)?,
        fallback: to_u16(fallback)?,
    })
}

/// A reward cert, whose bitmap length is a ShortU16.
fn read_reward_cert(r: &mut Reader, has_block_id: bool) -> Result<RewardCert> {
    let slot = u64::from_le_bytes(r.array()?);
    let block_id = if has_block_id { Some(r.array()?) } else { None };
    r.take(BLS_SIGNATURE_SIZE)?;
    let (len, used) = read_short_u16(r.rest())?;
    r.take(used)?;
    let signers = read_signers(r.take(usize::from(len))?)?;
    Ok(RewardCert {
        slot,
        block_id,
        signers,
    })
}

/// Reads a ShortU16, 7 bits per byte from the lowest, the top bit set while more follow.
/// Returns the value and how many bytes it took. Like Agave, a padded form is refused.
pub fn read_short_u16(bytes: &[u8]) -> Result<(u16, usize)> {
    let mut value = 0u32;
    for (i, &byte) in bytes.iter().take(SHORT_U16_MAX_BYTES).enumerate() {
        if byte == 0 && i > 0 {
            return Err(Error::InvalidFooter("ShortU16 padded with a zero byte"));
        }
        value |= u32::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            let value = u16::try_from(value)
                .map_err(|_| Error::InvalidFooter("ShortU16 larger than u16"))?;
            return Ok((value, i + 1));
        }
    }
    if bytes.len() < SHORT_U16_MAX_BYTES {
        Err(Error::TooShort {
            expected: bytes.len() + 1,
            actual: bytes.len(),
        })
    } else {
        Err(Error::InvalidFooter("ShortU16 longer than 3 bytes"))
    }
}

/// Walks a byte slice field by field, every read checks the bytes are there.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.saturating_add(n);
        let part = self.bytes.get(self.at..end).ok_or(Error::TooShort {
            expected: end,
            actual: self.bytes.len(),
        })?;
        self.at = end;
        Ok(part)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let part = self.take(N)?;
        part.try_into().map_err(|_| Error::TooShort {
            expected: N,
            actual: part.len(),
        })
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    /// An Option tag, 0 for None and 1 for Some.
    fn present(&mut self) -> Result<bool> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Error::InvalidFooter("option byte is neither 0 nor 1")),
        }
    }

    fn rest(&self) -> &'a [u8] {
        self.bytes.get(self.at..).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{Batcher, Component, decode_component};

    // Every data shred of slot 449661788 in index order, its footer is 670 bytes.
    const SLOT: &[u8] = include_bytes!("../tests/fixtures/real-slot.bin");

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    // the footer's marker data, cut out of the slot the way the assembler does it
    fn real_footer() -> Vec<u8> {
        let mut batcher = Batcher::new();
        for packet in SLOT.chunks(1203) {
            let Some(batch) = batcher.push(&packet[64..1051]).unwrap() else {
                continue;
            };
            if let Component::Marker {
                variant: 0, data, ..
            } = decode_component(&batch).unwrap()
            {
                return data;
            }
        }
        panic!("slot has no footer");
    }

    // A footer built by hand, field by field, to reach the cases the capture never showed

    fn start() -> Vec<u8> {
        let mut b = vec![1]; // footer version
        b.extend([7u8; 32]); // bank hash
        b.extend(1_000u64.to_le_bytes()); // producer time
        b.push(5);
        b.extend(b"agave");
        b
    }

    fn base2(validators: u16, bits: &[u8]) -> Vec<u8> {
        let mut b = vec![0];
        b.extend(validators.to_le_bytes());
        b.extend(bits);
        b
    }

    // an aggregate inside the final cert, its bitmap length is a plain u16
    fn aggregate(bitmap: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 96];
        b.extend((bitmap.len() as u16).to_le_bytes());
        b.extend(bitmap);
        b
    }

    #[test]
    fn test_real_footer() {
        let footer = decode_footer(&real_footer()).unwrap();
        assert_eq!(
            hex(&footer.bank_hash),
            "a906c59b989b4dbc6bc25a9b5b96c303c705f2bad4e1ae52e06d3806cf91a2b2"
        );
        assert_eq!(footer.producer_time_ns, 1_791_382_355_389_894_810);
        assert_eq!(
            footer.user_agent,
            "agave/4.4.0-beta.0 (src:c2e16837; feat:6e955f07, client:JitoLabs)"
        );

        // the slot before was finalized in one round, so there is no notar aggregate
        let cert = footer.final_cert.unwrap();
        assert_eq!(cert.slot, 449_661_787);
        assert_eq!(
            hex(&cert.block_id),
            "77a68aca196281746e3dd0484fda34667bf968a6173f29d475e89ce5f87554ae"
        );
        assert!(cert.fast);
        assert_eq!(
            cert.finalize,
            Signers {
                bits: 473,
                voted: 355,
                fallback: 0
            }
        );
        assert_eq!(cert.notarize, None);

        // reward certs are for the slot 8 back
        let skip = footer.skip_reward.unwrap();
        assert_eq!(skip.slot, 449_661_780);
        assert_eq!(skip.block_id, None);
        assert_eq!(skip.signers.voted, 1);
        assert_eq!(skip.signers.bits, 398);
        let notar = footer.notar_reward.unwrap();
        assert_eq!(notar.slot, 449_661_780);
        assert_eq!(
            hex(&notar.block_id.unwrap()),
            "56110d79991146ec57a42f31eaf3bd130a7c3db46edb8ed4dcb3e7aa797fb5a4"
        );
        assert_eq!(notar.signers.voted, 458);
    }

    #[test]
    fn test_no_certificates() {
        let mut b = start();
        b.extend([0, 0, 0]);
        let footer = decode_footer(&b).unwrap();
        assert_eq!(footer.bank_hash, [7u8; 32]);
        assert_eq!(footer.producer_time_ns, 1_000);
        assert_eq!(footer.user_agent, "agave");
        assert!(footer.final_cert.is_none());
        assert!(footer.skip_reward.is_none());
        assert!(footer.notar_reward.is_none());
    }

    #[test]
    fn test_slow_finalization() {
        // finalized in two rounds, so a notar aggregate follows the final one
        let mut b = start();
        b.push(1);
        b.extend(41u64.to_le_bytes());
        b.extend([9u8; 32]);
        b.extend(aggregate(&base2(10, &[0b1111_1111, 0b01])));
        b.push(1);
        b.extend(aggregate(&base2(10, &[0b0000_0111, 0])));
        b.extend([0, 0]);

        let cert = decode_footer(&b).unwrap().final_cert.unwrap();
        assert_eq!(cert.slot, 41);
        assert!(!cert.fast);
        assert_eq!(cert.finalize.voted, 9);
        assert_eq!(cert.notarize.unwrap().voted, 3);
    }

    #[test]
    fn test_base3_bitmap() {
        // 5 validators voted (notar, none, fallback, none, notar),
        // digits 1, 0, 2, 0, 1 from the lowest, so 1 + 2 * 9 + 81 = 100
        let signers = read_signers(&[1, 5, 0, 100]).unwrap();
        assert_eq!(
            signers,
            Signers {
                bits: 5,
                voted: 2,
                fallback: 1
            }
        );
        // base 2 bits past the validator count are not votes
        assert_eq!(read_signers(&base2(3, &[0xff])).unwrap().voted, 3);
    }

    #[test]
    fn test_reward_bitmap_length_is_a_short_u16() {
        // the capture's bitmaps are all under 128 bytes, so their length fits in one byte.
        // 1100 validators need 138 bytes plus 3 of header, 141 takes two bytes
        let bitmap = base2(1_100, &[0xff; 138]);
        assert_eq!(bitmap.len(), 141);
        let mut b = start();
        b.extend([0, 1]); // no final cert, a skip reward cert
        b.extend(9u64.to_le_bytes());
        b.extend([0u8; 96]);
        b.extend([0x8d, 0x01]); // low 7 bits 0x0d with the more bit set, then 141 >> 7 = 1
        b.extend(&bitmap);
        b.push(0);

        let skip = decode_footer(&b).unwrap().skip_reward.unwrap();
        assert_eq!(skip.slot, 9);
        assert_eq!(skip.signers.bits, 1_100);
        assert_eq!(skip.signers.voted, 1_100);

        // a ShortU16 padded with a zero byte is refused, as Agave does
        assert_eq!(read_short_u16(&[0x8d, 0x01]).unwrap(), (141, 2));
        assert!(read_short_u16(&[0x81, 0x00]).is_err());
        assert!(read_short_u16(&[0x80, 0x80, 0x80]).is_err());
    }

    #[test]
    fn test_bad_footers_refused() {
        let mut good = start();
        good.extend([0, 0, 0]);
        assert!(decode_footer(&good).is_ok());

        // an unknown footer version
        let mut b = good.clone();
        b[0] = 2;
        assert!(decode_footer(&b).is_err());
        // cut short anywhere
        for len in 0..good.len() {
            assert!(decode_footer(&good[..len]).is_err(), "cut at {len}");
        }
        // bytes left over, Agave's length prefix must match the footer exactly
        let mut b = good.clone();
        b.push(0);
        assert!(decode_footer(&b).is_err());
        // an Option byte that is neither 0 nor 1
        let mut b = good.clone();
        let last = b.len() - 1;
        b[last] = 2;
        assert!(decode_footer(&b).is_err());
        // a bitmap whose bytes don't match its validator count
        assert!(read_signers(&base2(20, &[0xff])).is_err());
        assert!(read_signers(&[2, 1, 0, 0]).is_err());
    }
}
