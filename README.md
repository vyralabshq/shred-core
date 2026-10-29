# shred-core

Read Solana shreds and rebuild the block data from them.

shred-core parses Merkle shreds, puts FEC sets back together, rebuilds missing data shreds with Reed-Solomon and decodes the entries, transactions and block markers inside. Every shred's Merkle proof is checked against its set's root, and given the leader schedule, every set must carry its slot leader's signature over that root. It only reads bytes. It never talks to the network or a validator.

Tested on Solana testnet captures: blocks rebuilt from shreds match the same blocks fetched with getBlock, transaction for transaction.

It ran live on a Solana testnet validator in [shredtap](https://github.com/jkrishnad/shred-tap) until 29 Oct 2026, and still reads recorded captures.

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
shred-core = { git = "https://github.com/vyralabshq/shred-core", tag = "v0.5.0" }
```

### Features

`assembler`, `pcap` and `footer` are on by default. Turn them off with `default-features = false` and pick the ones you need.

- `assembler`, the slot assembler. It needs `footer`.
- `pcap`, the capture file reader.
- `footer`, the Alpenglow block footer decoder. It brings in serde.
- `live`, off by default, reads shreds straight from a network interface with libpcap. It needs libpcap to build, and root or the `cap_net_raw` and `cap_net_admin` capabilities to run.

Building needs a C compiler, because Reed-Solomon and SHA-256 run on fast C and assembly code from `reed-solomon-erasure` and `sha2`.

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
    // hand out each transaction the moment its batch decodes
    let mut assembler = Assembler::new().with_leaders(leaders).emit_early();

    let mut source = PcapReader::new(BufReader::new(File::open("shreds.pcap")?))?;
    while let Some(record) = source.next_record()? {
        let Some(payload) = udp_payload(&record.frame) else { continue };
        for event in assembler.push(payload, record.recv_ns) {
            if let Event::Tx { slot, signature, timing, .. } = event {
                let us = timing.decoded_ns.saturating_sub(timing.first_shred_ns) / 1000;
                println!("{slot} {signature} {us} µs after its set's first shred");
            }
        }
    }
    Ok(())
}
```

On a 10 second testnet capture this prints 2,394 transactions, the same as getBlock. The time printed is how long the network took to deliver enough of the set's shreds, not time spent in shred-core.

To read live from a network interface instead, turn on the `live` feature and swap the source:

```rust
let mut source = shred_core::live::LiveCapture::open("eth0")?;
```

Any other source of shreds works the same way: a UDP socket, a relay or a replay. Hand each UDP payload to `push` with the time it arrived in nanoseconds. The assembler keeps no clock of its own, so a replay gives the same result every time.

Without `emit_early`, a slot's transactions come out together when it closes, at its Alpenglow skip deadline, 1.45 s after its first shred with 200 ms slots. That is slower, but each transaction's rebuilt flag is then final: it says which data shreds never arrived at all. With `emit_early` it says which had not arrived yet at decode. Either way, set and slot events come when the slot closes, and `finish` closes the slots still open when the input ends.

Every `Event::Tx` carries:

- `transaction`, the decoded `VersionedTransaction`
- `raw`, its bytes exactly as the leader encoded them, to send on without encoding again
- `signature`, `slot`, the index of its `entry` in the slot and its `position` in that entry
- `timing`, when its set's first shred arrived, when the set had 32 shreds and when the batch decoded
- `rebuilt`, whether any of its bytes only exist because Reed-Solomon rebuilt them

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
