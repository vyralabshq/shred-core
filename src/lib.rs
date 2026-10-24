//! shred-core reads Solana shreds and rebuilds the block data from them.
//!
//! The flow, one module per step.
//! 1. pcap pulls each shred out of a tcpdump capture, with the time it arrived.
//!    live reads the same frames straight from a network interface, behind the live feature.
//!    PacketSource is the same for any other source of frames.
//! 2. wire reads single header fields straight from the shred bytes.
//! 3. shred checks a packet once and works out its kind, its place in the FEC set and its byte layout.
//! 4. fec collects the shreds of one FEC set and rebuilds missing data shards with Reed-Solomon.
//!    merkle climbs a shred's Merkle proof to its set's root, to check the shred belongs there.
//!    leaders reads the leader schedule and checks the leader's signature on that root.
//! 5. block joins data shards into batches and decodes them into entries or block markers.
//!    footer reads the block footer marker, its bank hash, clock, client and certificates.
//! 6. assembler runs all of the above on a live or recorded stream, in the right order, with timing.
//!
//! assembler, pcap and footer are cargo features, all on by default. live is off by default.
//!
//! error holds the one Error type every module returns.
#[cfg(feature = "assembler")]
pub mod assembler;
pub mod block;
pub mod error;
pub mod fec;
#[cfg(feature = "footer")]
pub mod footer;
pub mod leaders;
#[cfg(feature = "live")]
pub mod live;
pub mod merkle;
#[cfg(feature = "pcap")]
pub mod pcap;
pub mod shred;
pub mod wire;
