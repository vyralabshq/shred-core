//! Reads a pcap capture and pulls the UDP payload out of each Ethernet frame.
//!
//! tcpdump does the capturing on the node, this module only reads what it wrote.
//! PcapReader checks the 24 byte file header, then reads one record at a time,
//! each a timestamp and one Ethernet frame. It reads from any Read, a file or a tcpdump pipe.
//! udp_payload strips the Ethernet, IPv4 and UDP headers off a frame and returns the shred inside.
//! pcap headers are little endian, network headers are big endian.

use crate::error::{Error, Result};
use std::io::Read;

/// File header magic, read little endian. The nanosecond kind is what our capture script writes.
const MAGIC_NANOS: u32 = 0xa1b2_3c4d;
const MAGIC_MICROS: u32 = 0xa1b2_c3d4;
const LINKTYPE_ETHERNET: u32 = 1;

const FILE_HEADER_SIZE: usize = 24;
const RECORD_HEADER_SIZE: usize = 16;

const ETHERNET_HEADER_SIZE: usize = 14;
const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const IP_PROTOCOL_UDP: u8 = 17;
const UDP_HEADER_SIZE: usize = 8;

/// One captured frame and when it arrived.
pub struct Record {
    /// Capture timestamp in nanoseconds since the Unix epoch.
    pub recv_ns: u64,
    /// The whole Ethernet frame.
    pub frame: Vec<u8>,
}

/// Anything that hands out captured frames one at a time, a capture file or a live interface.
pub trait PacketSource {
    /// The next frame, None once the input has ended.
    fn next_record(&mut self) -> Result<Option<Record>>;

    /// Packets lost before they reached us, None when the source can't tell, like a file.
    fn drops(&mut self) -> Option<Drops> {
        None
    }
}

/// Packets a live capture lost, from libpcap's counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Drops {
    /// No room left in the kernel buffer, because packets were not read fast enough.
    pub kernel: u32,
    /// Dropped by the network card or its driver.
    pub interface: u32,
}

/// Reads records one at a time, so a file and a live pipe from tcpdump work the same way.
pub struct PcapReader<R> {
    reader: R,
    nanos: bool,
    /// Longest frame the capture may hold, from the file header.
    snaplen: usize,
}

impl<R: Read> PcapReader<R> {
    /// Reads and checks the 24 byte file header.
    pub fn new(mut reader: R) -> Result<Self> {
        let mut header = [0u8; FILE_HEADER_SIZE];
        if read_full(&mut reader, &mut header)? < FILE_HEADER_SIZE {
            return Err(Error::TruncatedPcap);
        }

        let magic = le_u32(&header[0..4]);
        let nanos = match magic {
            MAGIC_NANOS => true,
            MAGIC_MICROS => false,
            // reported as the bytes appear in the file, so pcapng shows up as 0x0a0d0d0a
            _ => {
                return Err(Error::BadPcapMagic(u32::from_be_bytes([
                    header[0], header[1], header[2], header[3],
                ])));
            }
        };

        let snaplen = le_u32(&header[16..20]) as usize;
        let linktype = le_u32(&header[20..24]);
        if linktype != LINKTYPE_ETHERNET {
            return Err(Error::UnsupportedLinkType(linktype));
        }

        Ok(Self {
            reader,
            nanos,
            snaplen,
        })
    }
}

impl<R: Read> PacketSource for PcapReader<R> {
    /// Next record, or None at a clean end of the file.
    fn next_record(&mut self) -> Result<Option<Record>> {
        let mut header = [0u8; RECORD_HEADER_SIZE];
        match read_full(&mut self.reader, &mut header)? {
            0 => return Ok(None),
            RECORD_HEADER_SIZE => {}
            _ => return Err(Error::TruncatedPcap),
        }

        let seconds = u64::from(le_u32(&header[0..4]));
        let fraction = u64::from(le_u32(&header[4..8]));
        let captured_len = le_u32(&header[8..12]) as usize;
        // a corrupt length must become an error, not a huge allocation
        if captured_len > self.snaplen {
            return Err(Error::PcapRecordTooLarge {
                len: captured_len,
                snaplen: self.snaplen,
            });
        }

        let mut frame = vec![0u8; captured_len];
        if read_full(&mut self.reader, &mut frame)? < captured_len {
            return Err(Error::TruncatedPcap);
        }

        let fraction_ns = if self.nanos {
            fraction
        } else {
            fraction * 1_000
        };
        Ok(Some(Record {
            recv_ns: seconds * 1_000_000_000 + fraction_ns,
            frame,
        }))
    }
}

/// The UDP payload of an Ethernet + IPv4 + UDP frame, or None for anything else.
/// Network headers are big endian, unlike shred fields.
pub fn udp_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.get(12..14)? != ETHERTYPE_IPV4 {
        return None;
    }

    let ip = ETHERNET_HEADER_SIZE;
    let version_ihl = *frame.get(ip)?;
    if version_ihl >> 4 != 4 {
        return None;
    }
    // IPv4 header length is in 4 byte words, 5 (20 bytes) without options
    let ip_header_len = usize::from(version_ihl & 0x0F) * 4;
    if *frame.get(ip + 9)? != IP_PROTOCOL_UDP {
        return None;
    }

    let udp = ip + ip_header_len;
    let len = frame.get(udp + 4..udp + 6)?;
    // UDP length includes its own 8 byte header, and it tells us where Ethernet padding starts
    let udp_len = usize::from(u16::from_be_bytes([len[0], len[1]]));
    frame.get(udp + UDP_HEADER_SIZE..udp + udp_len.max(UDP_HEADER_SIZE))
}

/// Fills as much of `buf` as the reader has and returns how many bytes that was.
/// read_exact can't tell a clean end (0 bytes) from a cut record (some bytes), this can.
fn read_full(reader: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(filled)
}

/// pcap headers are little endian on our capture, the callers pass exactly 4 bytes.
fn le_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::Error;

    // pcap file header magic as it appears on disk
    const MAGIC_NANOS: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
    const MAGIC_MICROS: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
    const LINKTYPE_ETHERNET: u32 = 1;

    // builds a pcap file in memory from (seconds, fraction, frame) records
    fn pcap_file(magic: [u8; 4], linktype: u32, records: &[(u32, u32, &[u8])]) -> Vec<u8> {
        let mut f = magic.to_vec();
        f.extend_from_slice(&2u16.to_le_bytes()); // version major
        f.extend_from_slice(&4u16.to_le_bytes()); // version minor
        f.extend_from_slice(&[0u8; 8]); // timezone and accuracy, unused
        f.extend_from_slice(&65535u32.to_le_bytes()); // snaplen
        f.extend_from_slice(&linktype.to_le_bytes());
        for (sec, frac, frame) in records {
            f.extend_from_slice(&sec.to_le_bytes());
            f.extend_from_slice(&frac.to_le_bytes());
            f.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // captured length
            f.extend_from_slice(&(frame.len() as u32).to_le_bytes()); // original length
            f.extend_from_slice(frame);
        }
        f
    }

    // Ethernet + IPv4 + UDP frame around a payload, with `ip_options` extra IPv4 header bytes.
    // Addresses are from the 192.0.2.0/24 documentation range.
    fn udp_frame(payload: &[u8], ip_options: usize) -> Vec<u8> {
        let ihl = 20 + ip_options;
        let mut f = vec![0u8; 12]; // destination and source MAC
        f.extend_from_slice(&0x0800u16.to_be_bytes()); // ethertype IPv4
        f.push(0x40 | (ihl / 4) as u8); // version 4, header length in 4 byte words
        f.push(0); // DSCP
        f.extend_from_slice(&((ihl + 8 + payload.len()) as u16).to_be_bytes()); // total length
        f.extend_from_slice(&[0u8; 4]); // id, flags, fragment offset
        f.push(64); // TTL
        f.push(17); // protocol UDP
        f.extend_from_slice(&[0u8; 2]); // checksum
        f.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2]); // source and destination IP
        f.extend_from_slice(&vec![0u8; ip_options]);
        f.extend_from_slice(&8000u16.to_be_bytes()); // source port
        f.extend_from_slice(&8001u16.to_be_bytes()); // destination port
        f.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes()); // UDP length
        f.extend_from_slice(&[0u8; 2]); // checksum
        f.extend_from_slice(payload);
        f
    }

    // Reading records
    #[test]
    fn test_reads_nanosecond_records() {
        let a = udp_frame(b"first", 0);
        let b = udp_frame(b"second", 0);
        let file = pcap_file(
            MAGIC_NANOS,
            LINKTYPE_ETHERNET,
            &[(10, 123_456_789, &a), (11, 5, &b)],
        );
        let mut r = PcapReader::new(&file[..]).unwrap();

        let rec = r.next_record().unwrap().unwrap();
        assert_eq!(rec.recv_ns, 10_123_456_789);
        assert_eq!(rec.frame, a);

        let rec = r.next_record().unwrap().unwrap();
        assert_eq!(rec.recv_ns, 11_000_000_005);
        assert_eq!(rec.frame, b);

        assert!(r.next_record().unwrap().is_none());
    }

    #[test]
    fn test_reads_microsecond_records() {
        // older captures store microseconds, the reader converts to nanoseconds
        let a = udp_frame(b"x", 0);
        let file = pcap_file(MAGIC_MICROS, LINKTYPE_ETHERNET, &[(10, 250_000, &a)]);
        let mut r = PcapReader::new(&file[..]).unwrap();
        assert_eq!(r.next_record().unwrap().unwrap().recv_ns, 10_250_000_000);
    }

    #[test]
    fn test_empty_capture() {
        let file = pcap_file(MAGIC_NANOS, LINKTYPE_ETHERNET, &[]);
        let mut r = PcapReader::new(&file[..]).unwrap();
        assert!(r.next_record().unwrap().is_none());
    }

    #[test]
    fn test_bad_magic() {
        let mut file = pcap_file(MAGIC_NANOS, LINKTYPE_ETHERNET, &[]);
        file[..4].copy_from_slice(&[0x0a, 0x0d, 0x0d, 0x0a]); // pcapng starts like this
        assert!(matches!(
            PcapReader::new(&file[..]),
            Err(Error::BadPcapMagic(0x0a0d0d0a))
        ));
    }

    #[test]
    fn test_unsupported_link_type() {
        // 113 is Linux cooked capture, what `tcpdump -i any` writes
        let file = pcap_file(MAGIC_NANOS, 113, &[]);
        assert!(matches!(
            PcapReader::new(&file[..]),
            Err(Error::UnsupportedLinkType(113))
        ));
    }

    #[test]
    fn test_header_too_short() {
        let file = pcap_file(MAGIC_NANOS, LINKTYPE_ETHERNET, &[]);
        assert!(matches!(
            PcapReader::new(&file[..10]),
            Err(Error::TruncatedPcap)
        ));
    }

    #[test]
    fn test_truncated_record() {
        // record header says 50 bytes but the file ends after 10
        let a = udp_frame(&[0u8; 8], 0);
        let mut file = pcap_file(MAGIC_NANOS, LINKTYPE_ETHERNET, &[(1, 0, &a)]);
        file.truncate(24 + 16 + 10);
        let mut r = PcapReader::new(&file[..]).unwrap();
        assert!(matches!(r.next_record(), Err(Error::TruncatedPcap)));
    }

    #[test]
    fn test_record_longer_than_snaplen() {
        // a corrupt length field, the reader must refuse it before allocating
        let a = udp_frame(b"x", 0);
        let mut file = pcap_file(MAGIC_NANOS, LINKTYPE_ETHERNET, &[(1, 0, &a)]);
        file[24 + 8..24 + 12].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut r = PcapReader::new(&file[..]).unwrap();
        assert!(matches!(
            r.next_record(),
            Err(Error::PcapRecordTooLarge { snaplen: 65535, .. })
        ));
    }

    #[test]
    fn test_truncated_record_header() {
        // a capture cut in the middle of a record header is truncated, not a clean end
        let a = udp_frame(b"x", 0);
        let mut file = pcap_file(MAGIC_NANOS, LINKTYPE_ETHERNET, &[(1, 0, &a)]);
        file.truncate(24 + 7);
        let mut r = PcapReader::new(&file[..]).unwrap();
        assert!(matches!(r.next_record(), Err(Error::TruncatedPcap)));
    }

    // Stripping Ethernet, IPv4 and UDP headers

    #[test]
    fn test_udp_payload() {
        let f = udp_frame(b"shred bytes", 0);
        assert_eq!(f.len(), 42 + 11);
        assert_eq!(udp_payload(&f), Some(&b"shred bytes"[..]));
    }

    #[test]
    fn test_udp_payload_ip_options() {
        // IPv4 header length comes from the packet, not a fixed 20
        let f = udp_frame(b"shred bytes", 8);
        assert_eq!(udp_payload(&f), Some(&b"shred bytes"[..]));
    }

    #[test]
    fn test_udp_payload_ignores_trailing_padding() {
        // Ethernet can pad short frames, the UDP length field says where the payload ends
        let mut f = udp_frame(b"hi", 0);
        f.extend_from_slice(&[0u8; 16]);
        assert_eq!(udp_payload(&f), Some(&b"hi"[..]));
    }

    #[test]
    fn test_udp_payload_not_ipv4() {
        let mut f = udp_frame(b"x", 0);
        f[12..14].copy_from_slice(&0x86DDu16.to_be_bytes()); // IPv6
        assert_eq!(udp_payload(&f), None);
    }

    #[test]
    fn test_udp_payload_not_udp() {
        let mut f = udp_frame(b"x", 0);
        f[14 + 9] = 6; // TCP
        assert_eq!(udp_payload(&f), None);
    }

    #[test]
    fn test_udp_payload_short_frames() {
        let f = udp_frame(b"shred bytes", 0);
        for len in [0, 13, 20, 33, 41] {
            assert_eq!(udp_payload(&f[..len]), None, "frame cut at {len}");
        }
        // UDP length claims more than the frame holds
        let mut f = udp_frame(b"x", 0);
        f[38..40].copy_from_slice(&500u16.to_be_bytes());
        assert_eq!(udp_payload(&f), None);
    }

    // Real capture, runs only where the raw pcap is present (it is never committed)
    #[test]
    fn test_real_capture() {
        let Ok(file) = std::fs::File::open("tests/fixtures/real-10s.pcap") else {
            return;
        };
        let mut r = PcapReader::new(std::io::BufReader::new(file)).unwrap();
        let (mut records, mut data, mut coding) = (0, 0, 0);
        let mut first_ns = None;
        while let Some(rec) = r.next_record().unwrap() {
            records += 1;
            first_ns.get_or_insert(rec.recv_ns);
            match udp_payload(&rec.frame).map(<[u8]>::len) {
                Some(1203) => data += 1,
                Some(1228) => coding += 1,
                _ => {}
            }
        }
        assert_eq!(records, 15_907);
        assert_eq!(data, 7_948);
        assert_eq!(coding, 7_959);
        assert_eq!(first_ns, Some(1_791_382_349_583_098_409));
    }
}
