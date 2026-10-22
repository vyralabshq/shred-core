# shred-core

Read Solana shreds and rebuild the block data from them.

shred-core parses Merkle shreds, puts FEC sets back together, rebuilds missing data shreds with Reed-Solomon and decodes the entries, transactions and block markers inside. Every shred's Merkle proof is checked against its set's root, and given the leader schedule, every set must carry its slot leader's signature over that root. It only reads bytes. It never talks to the network or a validator.

Tested on Solana testnet captures: blocks rebuilt from shreds match the same blocks fetched with getBlock, transaction for transaction.

## Modules

In the order a shred goes through them.

1. `pcap` reads a tcpdump capture and pulls out each UDP payload with the nanosecond time it arrived. `PacketSource` is the trait for any other source of frames.
2. `wire` reads single header fields straight from the shred bytes.
3. `shred` checks a packet once and works out its kind, its place in the FEC set and its byte layout.
4. `fec` collects the shreds of one FEC set and rebuilds missing data shards with Reed-Solomon. `merkle` checks each shred's proof against the set's root, and `leaders` checks the leader's signature on that root.
5. `block` joins data shards into batches and decodes them into entries or block markers. `footer` reads the block footer: bank hash, clock, client and the finalization certificates.

`error` holds the one `Error` type every module returns.

## Usage

```toml
[dependencies]
shred-core = { git = "https://github.com/vyralabshq/shred-core", tag = "v0.1.0" }
```

Rebuild every FEC set in a capture:

```rust
use std::collections::HashMap;
use std::fs::File;

use shred_core::fec::FecSet;
use shred_core::pcap::{PacketSource, PcapReader, udp_payload};
use shred_core::shred::Shred;

fn main() -> shred_core::error::Result<()> {
    let mut source = PcapReader::new(File::open("shreds.pcap")?)?;
    let mut sets: HashMap<(u64, u32), FecSet> = HashMap::new();

    while let Some(record) = source.next_record()? {
        let Some(payload) = udp_payload(&record.frame) else { continue };
        let Ok(shred) = Shred::parse(payload, record.recv_ns) else { continue };
        let (slot, fec_set_index) = shred.fec_key();
        let set = sets.entry((slot, fec_set_index)).or_insert_with(|| FecSet::new(slot, fec_set_index));
        // a shred whose Merkle proof doesn't lead to the set's root is refused
        let _ = set.push(shred);
    }

    for set in sets.values_mut().filter(|set| set.can_recover()) {
        set.recover()?;
        println!("slot {} set {} rebuilt: {}", set.slot, set.fec_set_index, set.recovered);
    }
    Ok(())
}
```

Capture the shreds on a node with nanosecond timestamps, for example:

```sh
sudo timeout 60 tcpdump -i <interface> -nn -s 1300 --time-stamp-precision=nano -w shreds.pcap \
  'udp and dst host <node ip> and (udp[4:2] = 1211 or udp[4:2] = 1236)'
```

A capture holds your peers' IP addresses, so keep it private.

## Tests

```sh
cargo test
```

The tests run against trimmed real shreds in `tests/fixtures/`. The pcap reader test also reads `tests/fixtures/real-10s.pcap` when it is there, and skips it otherwise, because a raw capture is never committed.

## License

Apache-2.0
