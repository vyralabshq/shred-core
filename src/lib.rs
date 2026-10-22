//! shred-core reads Solana shreds and rebuilds the block data from them.
//!
//! The flow, one module per step.
//! 1. pcap pulls each shred out of a tcpdump capture, with the time it arrived.
//!    PacketSource is the same for any other source of frames, like a live interface.
//! 2. wire reads single header fields straight from the shred bytes.
//! 3. shred checks a packet once and works out its kind, its place in the FEC set and its byte layout.
//! 4. fec collects the shreds of one FEC set and rebuilds missing data shards with Reed-Solomon.
//!    merkle climbs a shred's Merkle proof to its set's root, to check the shred belongs there.
//!    leaders reads the leader schedule and checks the leader's signature on that root.
//! 5. block joins data shards into batches and decodes them into entries or block markers.
//!    footer reads the block footer marker, its bank hash, clock, client and certificates.
//!
//! error holds the one Error type every module returns.
pub mod block;
pub mod error;
pub mod fec;
pub mod footer;
pub mod leaders;
pub mod merkle;
pub mod pcap;
pub mod shred;
pub mod wire;
