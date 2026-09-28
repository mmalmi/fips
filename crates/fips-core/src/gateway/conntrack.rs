//! Conntrack sessions read over netlink.
//!
//! A kernel built without `CONFIG_NF_CONNTRACK_PROCFS` has no
//! `/proc/net/nf_conntrack`, while `conntrack -L` still lists the table: it
//! asks the kernel for a dump over `NETLINK_NETFILTER`. This reader does the
//! same, so such a kernel can still pin mappings that carry traffic.

use super::pool::{ConntrackQuerier, ConntrackSnapshot};
use netlink_packet_core::{
    NLM_F_DUMP, NLM_F_DUMP_INTR, NLM_F_REQUEST, NetlinkHeader, NetlinkMessage, NetlinkPayload,
};
use netlink_packet_netfilter::conntrack::{ConntrackAttribute, ConntrackMessage, IPTuple, Tuple};
use netlink_packet_netfilter::{
    NetfilterHeader, NetfilterMessage, NetfilterMessageInner, NetfilterProtoFamily,
};
use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_NETFILTER};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::{IpAddr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// Budget for the complete kernel dump.
///
/// The read runs on a blocking thread once per tick, so a kernel that never
/// answers must not hold that thread for longer than a tick.
const READ_TIMEOUT: Duration = Duration::from_secs(2);

/// Sequence number for the next dump request, so a reply to an earlier
/// request cannot be counted as part of this one.
static NEXT_SEQ: AtomicU32 = AtomicU32::new(1);

/// Whether a dump has more to come after the buffer just counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DumpState {
    /// The kernel has more of the dump to send.
    More,
    /// The kernel sent the end-of-dump message.
    Done,
}

/// Conntrack querier that dumps the table over netlink.
///
/// Needs `CAP_NET_ADMIN` in the gateway's network namespace, which the
/// gateway already needs for its NAT table.
pub struct NetlinkConntrack;

impl ConntrackQuerier for NetlinkConntrack {
    fn snapshot(&self) -> Result<ConntrackSnapshot, io::Error> {
        let mut socket = Socket::new(NETLINK_NETFILTER)?;
        socket.bind_auto()?;
        socket.connect(&SocketAddr::new(0, 0))?;
        let deadline = Instant::now() + READ_TIMEOUT;

        let seq = NEXT_SEQ.fetch_add(1, Ordering::Relaxed);
        socket.send(&dump_request(seq), 0)?;

        let mut counts = HashMap::new();
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .filter(|remaining| !remaining.is_zero())
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::TimedOut, "conntrack dump timed out")
                })?;
            socket2::SockRef::from(&socket).set_read_timeout(Some(remaining))?;
            // Sized by peeking first, so a large batch is not truncated.
            let (buf, _) = socket.recv_from_full()?;
            if count_dump(&buf, seq, &mut counts)? == DumpState::Done {
                break;
            }
        }
        Ok(ConntrackSnapshot::from_counts(counts))
    }
}

/// A request for a dump of the IPv6 conntrack table.
///
/// The family in the netfilter header makes the kernel leave out IPv4
/// entries, which could never name a virtual IP.
fn dump_request(seq: u32) -> Vec<u8> {
    let mut header = NetlinkHeader::default();
    header.flags = NLM_F_REQUEST | NLM_F_DUMP;
    header.sequence_number = seq;
    let mut message = NetlinkMessage::new(
        header,
        NetlinkPayload::from(NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::IPv6, 0, 0),
            ConntrackMessage::Get(vec![]),
        )),
    );
    message.finalize();
    let mut buf = vec![0; message.buffer_len()];
    message.serialize(&mut buf);
    buf
}

/// Count the conntrack entries in one received buffer by destination.
///
/// An entry counts once for each distinct IPv6 destination among its original
/// and reply tuples, the same rule the proc-file parser applies to a line.
/// A message carrying another sequence number is skipped. A dump the kernel
/// flags as interrupted is rejected so a partial table cannot expire live mappings.
fn count_dump(
    buf: &[u8],
    seq: u32,
    counts: &mut HashMap<Ipv6Addr, u32>,
) -> Result<DumpState, io::Error> {
    let mut offset = 0;
    while offset < buf.len() {
        let message = NetlinkMessage::<NetfilterMessage>::deserialize(&buf[offset..])
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        // Validate progress independently of the message decoder.
        let len = message.header.length as usize;
        if len < 16 || len > buf.len() - offset {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid conntrack message length",
            ));
        }
        // Netlink messages are padded to four bytes.
        offset += (len + 3) & !3;
        if message.header.sequence_number != seq {
            continue;
        }
        if message.header.flags & NLM_F_DUMP_INTR != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "conntrack dump interrupted",
            ));
        }
        match message.payload {
            NetlinkPayload::Done(done) if done.code != 0 => {
                return Err(io::Error::from_raw_os_error(done.code.saturating_neg()));
            }
            NetlinkPayload::Done(_) => return Ok(DumpState::Done),
            NetlinkPayload::Error(e) if e.code.is_some() => return Err(e.to_io()),
            NetlinkPayload::InnerMessage(NetfilterMessage {
                inner: NetfilterMessageInner::Conntrack(ConntrackMessage::New(attrs)),
                ..
            }) => count_entry(&attrs, counts),
            _ => {}
        }
    }
    Ok(DumpState::More)
}

/// Add one conntrack entry to the counts, once per distinct IPv6 destination
/// among its original and reply tuples.
fn count_entry(attrs: &[ConntrackAttribute], counts: &mut HashMap<Ipv6Addr, u32>) {
    let mut seen = HashSet::new();
    for attr in attrs {
        let tuples = match attr {
            ConntrackAttribute::CtaTupleOrig(t) | ConntrackAttribute::CtaTupleReply(t) => t,
            _ => continue,
        };
        for tuple in tuples {
            let Tuple::Ip(ip) = tuple else { continue };
            for field in ip {
                if let IPTuple::DestinationAddress(IpAddr::V6(dst)) = field {
                    seen.insert(*dst);
                }
            }
        }
    }
    for dst in seen {
        *counts.entry(dst).or_insert(0) += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use netlink_packet_core::{DoneMessage, ErrorMessage};
    use std::num::NonZeroI32;

    const SEQ: u32 = 7;

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    /// One tuple naming a source and a destination.
    fn tuple(src: Ipv6Addr, dst: Ipv6Addr) -> Vec<Tuple> {
        vec![Tuple::Ip(vec![
            IPTuple::SourceAddress(IpAddr::V6(src)),
            IPTuple::DestinationAddress(IpAddr::V6(dst)),
        ])]
    }

    /// A conntrack entry as a dump reply carries it.
    fn entry(orig: Vec<Tuple>, reply: Vec<Tuple>) -> NetfilterMessage {
        NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::IPv6, 0, 0),
            ConntrackMessage::New(vec![
                ConntrackAttribute::CtaTupleOrig(orig),
                ConntrackAttribute::CtaTupleReply(reply),
            ]),
        )
    }

    /// Serialise one netlink message with the given sequence number.
    fn frame(payload: NetlinkPayload<NetfilterMessage>, seq: u32) -> Vec<u8> {
        let mut header = NetlinkHeader::default();
        header.sequence_number = seq;
        header.flags = netlink_packet_core::NLM_F_MULTIPART;
        let mut message = NetlinkMessage::new(header, payload);
        message.finalize();
        let mut buf = vec![0; message.buffer_len()];
        message.serialize(&mut buf);
        buf
    }

    fn done() -> NetlinkPayload<NetfilterMessage> {
        NetlinkPayload::Done(DoneMessage::default())
    }

    #[test]
    fn interrupted_or_failed_dump_is_not_an_empty_success() {
        let mut counts = HashMap::new();
        let mut interrupted = frame(done(), SEQ);
        interrupted[6..8].copy_from_slice(&NLM_F_DUMP_INTR.to_ne_bytes());
        assert_eq!(
            count_dump(&interrupted, SEQ, &mut counts)
                .unwrap_err()
                .kind(),
            io::ErrorKind::Interrupted
        );

        let mut done = DoneMessage::default();
        done.code = -libc::EIO;
        let failed = frame(NetlinkPayload::Done(done), SEQ);
        assert_eq!(
            count_dump(&failed, SEQ, &mut counts)
                .unwrap_err()
                .raw_os_error(),
            Some(libc::EIO)
        );
    }

    #[test]
    #[ignore = "requires Linux CAP_NET_ADMIN and conntrack in an isolated network namespace"]
    fn kernel_conntrack_dump_counts_virtual_destination() {
        let status = std::process::Command::new("conntrack")
            .args([
                "-I",
                "-p",
                "udp",
                "-s",
                "fd02::1",
                "-d",
                "fd01::1",
                "--sport",
                "40001",
                "--dport",
                "53",
                "--timeout",
                "30",
            ])
            .status()
            .unwrap();
        assert!(status.success());
        let snapshot = NetlinkConntrack.snapshot().unwrap();
        assert!(snapshot.sessions_for(v6("fd01::1")) > 0);
    }

    /// The flow the gateway sees for a LAN client using a virtual IP: the
    /// original tuple is client to virtual IP, and the reply, after DNAT and
    /// masquerade, is the mesh address back to the gateway.
    fn client_flow(virtual_ip: Ipv6Addr) -> NetfilterMessage {
        entry(
            tuple(v6("fd02::20"), virtual_ip),
            tuple(v6("fd9a::1"), v6("fd9a::2")),
        )
    }

    fn count(buf: &[u8]) -> (Result<DumpState, io::Error>, HashMap<Ipv6Addr, u32>) {
        let mut counts = HashMap::new();
        let state = count_dump(buf, SEQ, &mut counts);
        (state, counts)
    }

    #[test]
    fn netlink_dump_counts_an_entry_whose_original_destination_is_the_virtual_ip() {
        let virtual_ip = v6("fd01::1");
        let buf = frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ);

        let (state, counts) = count(&buf);

        assert_eq!(state.unwrap(), DumpState::More);
        assert_eq!(counts.get(&virtual_ip).copied(), Some(1));
        // The reply tuple's destination is counted too, as the proc parser
        // counts every dst= on the line.
        assert_eq!(counts.get(&v6("fd9a::2")).copied(), Some(1));
    }

    #[test]
    fn netlink_dump_counts_an_entry_once_when_both_tuples_name_the_address() {
        let addr = v6("fd01::1");
        let hairpin = entry(tuple(addr, addr), tuple(addr, addr));
        let buf = frame(NetlinkPayload::from(hairpin), SEQ);

        let (_, counts) = count(&buf);

        assert_eq!(counts.get(&addr).copied(), Some(1));
    }

    #[test]
    fn netlink_dump_counts_each_entry_across_several_messages_in_one_buffer() {
        let virtual_ip = v6("fd01::1");
        let other = v6("fd01::2");
        let mut buf = frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ);
        buf.extend(frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ));
        buf.extend(frame(NetlinkPayload::from(client_flow(other)), SEQ));

        let (state, counts) = count(&buf);

        assert_eq!(state.unwrap(), DumpState::More);
        assert_eq!(counts.get(&virtual_ip).copied(), Some(2));
        assert_eq!(counts.get(&other).copied(), Some(1));
    }

    #[test]
    fn netlink_dump_ignores_an_ipv4_entry() {
        let v4 = |s: &str| IpAddr::V4(s.parse().unwrap());
        let ipv4 = NetfilterMessage::new(
            NetfilterHeader::new(NetfilterProtoFamily::IPv4, 0, 0),
            ConntrackMessage::New(vec![ConntrackAttribute::CtaTupleOrig(vec![Tuple::Ip(
                vec![
                    IPTuple::SourceAddress(v4("192.0.2.1")),
                    IPTuple::DestinationAddress(v4("192.0.2.2")),
                ],
            )])]),
        );
        let mut buf = frame(NetlinkPayload::from(ipv4), SEQ);
        buf.extend(frame(NetlinkPayload::from(client_flow(v6("fd01::1"))), SEQ));

        let (state, counts) = count(&buf);

        assert_eq!(state.unwrap(), DumpState::More);
        assert_eq!(counts.len(), 2, "only the IPv6 entry's two destinations");
    }

    #[test]
    fn netlink_dump_reports_done_on_the_done_message() {
        let virtual_ip = v6("fd01::1");
        let mut buf = frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ);
        buf.extend(frame(done(), SEQ));

        let (state, counts) = count(&buf);

        assert_eq!(state.unwrap(), DumpState::Done);
        assert_eq!(counts.get(&virtual_ip).copied(), Some(1));
    }

    #[test]
    fn netlink_dump_turns_an_eperm_error_message_into_permission_denied() {
        let mut error = ErrorMessage::default();
        error.code = NonZeroI32::new(-libc::EPERM);
        let buf = frame(NetlinkPayload::Error(error), SEQ);

        let (state, _) = count(&buf);

        assert_eq!(
            state.expect_err("an error reply must fail the read").kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[test]
    fn netlink_dump_skips_a_message_with_another_sequence_number() {
        let virtual_ip = v6("fd01::1");
        let mut buf = frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ + 1);
        buf.extend(frame(done(), SEQ + 1));
        buf.extend(frame(NetlinkPayload::from(client_flow(virtual_ip)), SEQ));

        let (state, counts) = count(&buf);

        assert_eq!(
            state.unwrap(),
            DumpState::More,
            "another request's end of dump does not end this one"
        );
        assert_eq!(counts.get(&virtual_ip).copied(), Some(1));
    }

    #[test]
    fn netlink_dump_rejects_a_buffer_that_does_not_parse() {
        let mut buf = frame(NetlinkPayload::from(client_flow(v6("fd01::1"))), SEQ);
        buf.truncate(buf.len() - 4);

        let (state, _) = count(&buf);

        assert_eq!(
            state.expect_err("a short buffer must fail the read").kind(),
            io::ErrorKind::InvalidData
        );
    }
}
