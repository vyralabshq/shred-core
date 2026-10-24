//! Reads shreds straight from a network interface with libpcap, the live side of pcap.rs.
//!
//! It takes the same packets a tcpdump of shreds does: received, not sent, UDP with the length of a
//! data or a coding shred, stamped in nanoseconds, cut at 1300 bytes, through a 64 MB kernel
//! buffer, and handed over as soon as they arrive. Each one comes out as the same Record
//! the file reader gives, so the decoder can't tell a live interface from a capture file.
//! Opening an interface needs root or the cap_net_raw and cap_net_admin capabilities.

use crate::error::{Error, Result};
use crate::pcap::{Drops, PacketSource, Record};
use pcap::{Active, Capture, Direction, Precision};

/// UDP length field is the 8 byte header plus the payload, 1211 for a data shred, 1236 for coding.
pub const SHRED_FILTER: &str = "udp and (udp[4:2] = 1211 or udp[4:2] = 1236)";
/// Longest frame kept, enough for a coding shred with its Ethernet, IPv4 and UDP headers.
const SNAPLEN: i32 = 1300;
/// The kernel's buffer for packets not read yet.
const BUFFER_BYTES: i32 = 64 * 1024 * 1024;
/// How long a read waits before checking again. Packets still come out as soon as they arrive.
const READ_TIMEOUT_MS: i32 = 1000;

/// A live capture on one interface.
pub struct LiveCapture {
    cap: Capture<Active>,
}

impl LiveCapture {
    /// Opens the interface and starts capturing shreds.
    pub fn open(interface: &str) -> Result<Self> {
        let mut cap = Capture::from_device(interface)
            .map_err(capture_error)?
            .snaplen(SNAPLEN)
            .buffer_size(BUFFER_BYTES)
            .immediate_mode(true)
            .precision(Precision::Nano)
            .timeout(READ_TIMEOUT_MS)
            .open()
            .map_err(capture_error)?;
        cap.direction(Direction::In).map_err(capture_error)?;
        cap.filter(SHRED_FILTER, true).map_err(capture_error)?;
        Ok(Self { cap })
    }
}

impl PacketSource for LiveCapture {
    /// Waits for the next packet. A live interface never runs out, so this never returns None.
    fn next_record(&mut self) -> Result<Option<Record>> {
        loop {
            match self.cap.next_packet() {
                Ok(packet) => {
                    let ts = packet.header.ts;
                    // with nanosecond precision libpcap keeps nanoseconds in tv_usec,
                    // an i32 on macOS and an i64 on Linux, so the conversion is only needed on one
                    #[allow(clippy::useless_conversion)]
                    let nsec = i64::from(ts.tv_usec);
                    let recv_ns = recv_ns(ts.tv_sec, nsec)?;
                    return Ok(Some(Record {
                        recv_ns,
                        frame: packet.data.to_vec(),
                    }));
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => return Err(capture_error(e)),
            }
        }
    }

    /// What the kernel and the card have dropped since the capture opened.
    fn drops(&mut self) -> Option<Drops> {
        let stat = self.cap.stats().ok()?;
        Some(Drops {
            kernel: stat.dropped,
            interface: stat.if_dropped,
        })
    }
}

/// Seconds and nanoseconds since the Unix epoch, as one count of nanoseconds.
fn recv_ns(sec: i64, nsec: i64) -> Result<u64> {
    let bad = || Error::Capture(format!("timestamp out of range: {sec} s {nsec} ns"));
    let sec = u64::try_from(sec).map_err(|_| bad())?;
    let nsec = u64::try_from(nsec).map_err(|_| bad())?;
    sec.checked_mul(1_000_000_000)
        .and_then(|ns| ns.checked_add(nsec))
        .ok_or_else(bad)
}

/// A libpcap error, as the Capture error every packet source returns.
fn capture_error(e: pcap::Error) -> Error {
    Error::Capture(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pcap::Linktype;

    #[test]
    fn test_filter_compiles() {
        // checked without root, on a capture with no interface behind it
        let dead = Capture::dead_with_precision(Linktype::ETHERNET, Precision::Nano).unwrap();
        assert!(dead.compile(SHRED_FILTER, true).is_ok());
    }

    #[test]
    fn test_timestamp() {
        assert_eq!(
            recv_ns(1_791_382_349, 724_492_185).unwrap(),
            1_791_382_349_724_492_185
        );
        assert!(recv_ns(-1, 0).is_err());
    }
}
