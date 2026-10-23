# shred-core

Read Solana shreds and rebuild the block data from them.

shred-core parses Merkle shreds, puts FEC sets back together, rebuilds missing data shreds with Reed-Solomon and decodes the entries, transactions and block markers inside. Every shred's Merkle proof is checked against its set's root, and given the leader schedule, every set must carry its slot leader's signature over that root. It only reads bytes. It never talks to the network or a validator.

Tested on Solana testnet captures: blocks rebuilt from shreds match the same blocks fetched with getBlock, transaction for transaction.

It runs live in [shredtap](https://github.com/jkrishnad/shred-tap), which decodes the shreds reaching a testnet validator and shows them at [shreds.vyralabs.fun](https://shreds.vyralabs.fun).

## Modules

In the order a shred goes through them.

1. `pcap` reads a tcpdump capture and pulls out each UDP payload with the nanosecond time it arrived. `PacketSource` is the trait for any other source of frames.
2. `wire` reads single header fields straight from the shred bytes.
3. `shred` checks a packet once and works out its kind, its place in the FEC set and its byte layout.
4. `fec` collects the shreds of one FEC set and rebuilds missing data shards with Reed-Solomon. `merkle` checks each shred's proof against the set's root, and `leaders` checks the leader's signature on that root.
5. `block` joins data shards into batches and decodes them into entries or block markers. `footer` reads the block footer: bank hash, clock, client and the finalization certificates.
6. `assembler` runs all of the above on a stream of packets: it drops duplicates, checks every shred, decodes sets in order and closes each slot at its Alpenglow skip deadline. Out come transactions, block markers, FEC sets and closed slots, each with its arrival times.

`error` holds the one `Error` type every module returns.

## Usage

```toml
[dependencies]
shred-core = { git = "https://github.com/vyralabshq/shred-core", tag = "v0.3.0" }
```

### Features

All on by default. Turn them off with `default-features = false` and pick the ones you need.

- `assembler`, the slot assembler. It needs `footer`.
- `pcap`, the capture file reader.
- `footer`, the Alpenglow block footer decoder. It brings in serde.

### Read every transaction in a capture

```rust
use std::fs::File;
use std::io::BufReader;

use shred_core::assembler::{Assembler, Event};
use shred_core::leaders::LeaderSchedule;
use shred_core::pcap::{PacketSource, PcapReader, udp_payload};

fn main() -> shred_core::error::Result<()> {
    let mut leaders = LeaderSchedule::default();
    leaders.read(BufReader::new(File::open("leaders.txt")?))?;
    let mut assembler = Assembler::new().with_leaders(leaders);

    let mut source = PcapReader::new(BufReader::new(File::open("shreds.pcap")?))?;
    while let Some(record) = source.next_record()? {
        let Some(payload) = udp_payload(&record.frame) else { continue };
        assembler.push(payload, record.recv_ns).into_iter().for_each(print);
    }
    // the input ended, close the slots still open
    assembler.finish().into_iter().for_each(print);
    Ok(())
}

fn print(event: Event) {
    match event {
        Event::Tx { slot, signature, rebuilt, .. } => println!("{slot} {signature} rebuilt {rebuilt}"),
        Event::Slot { slot, txs, end, .. } => println!("slot {slot} {} with {txs} txs", end.as_str()),
        _ => {}
    }
}
```

On a 10 second testnet capture this prints 2,394 transactions in 45 complete slots, the same as getBlock.

Any other source of shreds works the same way: a UDP socket, a relay or a replay. Hand each UDP payload to `push` with the time it arrived in nanoseconds. The assembler keeps no clock of its own, so a replay gives the same result every time. A slot's events come out when it closes, at its Alpenglow skip deadline, 1.45 s after its first shred with 200 ms slots, so shreds that arrive late still count.

To get transactions sooner, build it with `Assembler::new().emit_early()`. Each transaction and block marker then comes out as soon as its batch decodes, and the slot still closes at its deadline. A transaction is then marked rebuilt when one of its data shreds had not arrived yet at decode.

Every `Event::Tx` carries the full `VersionedTransaction`, its signature, the index of its entry in the slot and its place among that entry's transactions.

For a full program built on it, live capture, rollups and a NATS feed, see [shredtap](https://github.com/jkrishnad/shred-tap).

### Where shreds come from

Anywhere you receive them: a shred feed or relay sent to a UDP port you own, your own node, or a pcap file recorded from either. shred-core only needs the UDP payload and when it arrived. A pcap file holds the sender's IP addresses, so keep it private.

### Leader schedule

`LeaderSchedule::read` takes the text that `solana leader-schedule` prints. For any other source, like RPC `getLeaderSchedule`, set each slot with `insert(slot, pubkey)`.

## Tests

```sh
cargo test
```

The tests run against trimmed real shreds in `tests/fixtures/`. The pcap reader test also reads `tests/fixtures/real-10s.pcap` when it is there, and skips it otherwise, because a raw capture is never committed.

## License

Apache-2.0
