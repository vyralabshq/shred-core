# Changelog

## v0.5.0

- Faster set rebuild. The Reed-Solomon codec is built once and reused, and `reed-solomon-erasure` runs with `simd-accel`. On an M1 a rebuild with its root check went from about 1.2 ms to 0.22 ms.
- `sha2` runs with `asm`, so SHA-256 uses the hardware on ARM too. x86 with SHA-NI already did.
- Building now needs a C compiler.
- `Event::Tx` and `Entry` carry `raw`, each transaction's bytes exactly as the leader encoded them. A breaking change for code that names every field or builds an `Entry`.

## v0.4.0

- `live`, off by default, moved from shredtap: `LiveCapture` reads shreds from a network interface with libpcap, as a `PacketSource`.

## v0.3.0

- `Assembler::emit_early`, off by default: transactions and markers come out the moment their batch decodes instead of when the slot closes. Their rebuilt flag then means a data shred had not arrived yet at decode.
- `Event::Tx` carries the whole `VersionedTransaction`, its entry index in the slot and its position in the entry. A breaking change for code that names every field.

## v0.2.0

- `assembler`, moved from shredtap: shreds in, transactions by signature, block markers, FEC sets and closed slots out.
- `LeaderSchedule::insert`, for a schedule from any source.
- `assembler`, `footer` and `pcap` features, all on by default.

## v0.1.0

Extracted from [shredtap](https://github.com/jkrishnad/shred-tap) at commit 394e36a, no behaviour change.
