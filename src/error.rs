//! The one Error type every module returns.
//!
//! Each variant names what went wrong with the input, so a caller can match on it.
//! The assembler, for example, drops an unknown variant quietly but counts a short packet.
//! thiserror writes the Display and std::error::Error impls from the attributes.

/// Result with the crate's own Error.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while reading shreds.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Packet ended before the field we wanted to read.
    #[error("packet too short: expected {expected}, got {actual} bytes")]
    TooShort { expected: usize, actual: usize },
    /// Variant byte is not a shred type we know, so the packet is not a shred we can read.
    #[error("unknown shred variant byte: {0:#04x}")]
    UnknownVariant(u8),
    /// Data shred whose index is below its FEC set start, so the packet is junk.
    #[error("data shred index {index} is below its fec_set_index {fec_set_index}")]
    IndexBelowFecSet { index: u32, fec_set_index: u32 },
    /// Merkle proof too long to fit in the shred, so the variant byte is junk.
    #[error("invalid proof size: {0}")]
    InvalidProofSize(u8),
    /// Shred pushed into a FEC set it does not belong to.
    #[error("shred for set {got:?} pushed into set {expected:?}")]
    WrongFecSet {
        expected: (u64, u32),
        got: (u64, u32),
    },
    /// Shard index outside the range its kind may use in a 32 data and 32 coding set.
    #[error("shard index {0} out of range for its kind")]
    ShardIndexOutOfRange(usize),
    /// Coding shred for a set that is not 32 data + 32 coding.
    #[error("unsupported erasure config: {num_data} data, {num_coding} coding")]
    UnsupportedErasureConfig { num_data: u16, num_coding: u16 },
    /// Fewer than 32 shreds, so the set can't be rebuilt yet.
    #[error("too few shreds: have {have}, need {need}")]
    TooFewShreds { have: usize, need: usize },
    /// Reed-Solomon failed, for example shards of different lengths.
    #[error("reed-solomon recovery failed: {0}")]
    Recovery(#[from] reed_solomon_erasure::Error),
    /// Data shred whose size field points before its headers end or past its shard.
    #[error("invalid data size {size} for a shard of {shard_len} bytes")]
    InvalidDataSize { size: u16, shard_len: usize },
    /// Merkle proof whose length is not whole 20 byte entries, or too short for the shard index.
    #[error("invalid merkle proof for shard index {shard_index}")]
    InvalidMerkleProof { shard_index: usize },
    /// Shred whose proof climbs to a different root than the rest of its FEC set.
    #[error("merkle root of shard index {shard_index} does not match its fec set")]
    MerkleRootMismatch { shard_index: usize },
    /// The tree built from a rebuilt set does not end at the set's root, so the rebuild is wrong.
    #[error("rebuilt fec set does not match its merkle root")]
    RebuiltRootMismatch,
    /// Shred whose signature differs from the rest of its FEC set, which all carry the leader's one signature.
    #[error("signature of shard index {shard_index} does not match its fec set")]
    SignatureMismatch { shard_index: usize },
    /// Entry batch bytes that don't decode as entries.
    #[error("entry decode failed: {0}")]
    Decode(#[from] wincode::ReadError),
    /// Block footer bytes that break Agave's footer layout.
    #[error("invalid block footer: {0}")]
    InvalidFooter(&'static str),
    /// File doesn't start with a pcap magic number, for example a pcapng file.
    #[error("not a pcap file, magic {0:#010x}")]
    BadPcapMagic(u32),
    /// Capture isn't Ethernet, for example `tcpdump -i any` writes Linux cooked (113).
    #[error("unsupported pcap link type {0}, expected Ethernet (1)")]
    UnsupportedLinkType(u32),
    /// Capture ends in the middle of a header or a frame.
    #[error("pcap file is truncated")]
    TruncatedPcap,
    /// Record longer than the capture's snaplen, so its length field is corrupt.
    #[error("pcap record of {len} bytes is longer than the snaplen {snaplen}")]
    PcapRecordTooLarge { len: usize, snaplen: usize },
    /// The live capture on a network interface failed, for example no permission to open it.
    #[error("live capture: {0}")]
    Capture(String),
    /// Reading the capture failed.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}
