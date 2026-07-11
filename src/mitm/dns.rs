//! The stub DNS resolver the stack runs on UDP :53. `A` resolves to the stack's
//! IPv4 address and `AAAA` to its IPv6 address, so all name-based HTTPS lands on
//! the stack over either family (the real upstream is recovered from the TLS SNI).

use anyhow::{Context, Result};
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;

use super::{STACK_IP, STACK_IP6};

/// DNS listen port.
const DNS_PORT: u16 = 53;
/// DNS record/class numbers.
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// The stub resolver: a UDP socket bound to :53 in the [`SocketSet`], serviced
/// each stack tick by [`StubDns::service`].
pub(super) struct StubDns {
    handle: SocketHandle,
}

impl StubDns {
    /// Add the :53 UDP socket to `sockets` and return the handle wrapper.
    pub(super) fn add(sockets: &mut SocketSet) -> Result<StubDns> {
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 8 * 1024]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0u8; 8 * 1024]);
        let mut sock = udp::Socket::new(rx, tx);
        sock.bind(DNS_PORT)
            .with_context(|| format!("binding stub DNS to :{DNS_PORT}"))?;
        Ok(StubDns {
            handle: sockets.add(sock),
        })
    }

    /// Answer every pending DNS query: `A` → `STACK_IP`, `AAAA` → `STACK_IP6`,
    /// everything else NODATA.
    pub(super) fn service(&self, sockets: &mut SocketSet) {
        let sock = sockets.get_mut::<udp::Socket>(self.handle);
        while sock.can_recv() {
            let (query, meta) = match sock.recv() {
                Ok((data, meta)) => (data.to_vec(), meta),
                Err(_) => break,
            };
            if let Some(resp) = build_response(&query) {
                let _ = sock.send_slice(&resp, meta.endpoint);
            }
        }
    }
}

/// Build a minimal DNS response for `query`. Returns `None` for malformed input.
fn build_response(query: &[u8]) -> Option<Vec<u8>> {
    if query.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([query[4], query[5]]);
    if qdcount == 0 {
        return None;
    }
    // Walk the (single) question's QNAME.
    let mut i = 12;
    let name_start = i;
    loop {
        let len = *query.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression pointer in a query: bail
        }
        i += 1 + len;
    }
    let qtype = u16::from_be_bytes([*query.get(i)?, *query.get(i + 1)?]);
    let qclass = u16::from_be_bytes([*query.get(i + 2)?, *query.get(i + 3)?]);
    let question = &query[name_start..i + 4];

    // A → STACK_IP, AAAA → STACK_IP6 (both IN); anything else is NODATA.
    let rdata: Option<Vec<u8>> = match (qclass, qtype) {
        (CLASS_IN, TYPE_A) => Some(STACK_IP.octets().to_vec()),
        (CLASS_IN, TYPE_AAAA) => Some(STACK_IP6.octets().to_vec()),
        _ => None,
    };

    let mut resp = Vec::with_capacity(query.len() + 28);
    resp.extend_from_slice(&query[0..2]); // ID
    let rd = query[2] & 0x01;
    resp.push(0x80 | rd); // QR=1, RD copied
    resp.push(0x80); // RA=1, RCODE=0
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    resp.extend_from_slice(&(rdata.is_some() as u16).to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    resp.extend_from_slice(question);
    if let Some(rdata) = rdata {
        resp.extend_from_slice(&[0xc0, 0x0c]); // name → offset 12
        resp.extend_from_slice(&qtype.to_be_bytes()); // TYPE (echo the queried type)
        resp.extend_from_slice(&CLASS_IN.to_be_bytes()); // CLASS IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
        resp.extend_from_slice(&rdata);
    }
    Some(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_response_answers_a_query_with_stack_ip() {
        // Query for "a.com" A/IN.
        let query = [
            0x12, 0x34, // ID
            0x01, 0x00, // flags: RD
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, //
            0x01, b'a', 0x03, b'c', b'o', b'm', 0x00, // a.com
            0x00, 0x01, // A
            0x00, 0x01, // IN
        ];
        let resp = build_response(&query).unwrap();
        assert_eq!(&resp[0..2], &[0x12, 0x34]); // ID echoed
        assert_eq!(resp[2] & 0x80, 0x80); // QR set
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // one answer
        // Answer rdata is STACK_IP.
        assert!(resp.ends_with(&STACK_IP.octets()));
    }

    #[test]
    fn dns_response_answers_aaaa_query_with_stack_ip6() {
        let query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, b'a',
            0x03, b'c', b'o', b'm', 0x00, 0x00, 0x1c, 0x00, 0x01, // AAAA / IN
        ];
        let resp = build_response(&query).unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // one answer
        assert!(resp.ends_with(&STACK_IP6.octets())); // rdata is STACK_IP6
    }
}
