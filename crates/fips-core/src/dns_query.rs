//! Shared screening for the daemon and gateway's untrusted DNS datagrams.
use simple_dns::{CLASS, Packet, PacketFlag, QCLASS};

pub(crate) const MAX_DATAGRAM: usize = 4096;
pub(crate) const MAX_TTL: u32 = i32::MAX as u32;

pub(crate) fn accepts_source_port(port: u16) -> bool {
    !matches!(port, 0 | 7 | 13 | 17 | 19 | 37)
}

/// Accept one ordinary query, with at most one additional (e.g. EDNS) record.
/// Check counts before parsing, and reject possibly truncated receive buffers.
pub(crate) fn parse_query(bytes: &[u8]) -> Option<Packet<'_>> {
    if bytes.len() < 12 || bytes.len() >= MAX_DATAGRAM {
        return None;
    }
    let word = |offset| u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    if word(2) & 0xf800 != 0 || word(4) != 1 || word(6) != 0 || word(8) != 0 || word(10) > 1 {
        return None;
    }
    // A sole first question has no earlier name to compress against. Reject
    // pointers rather than expand attacker-selected data into the reply.
    let mut end = 12;
    loop {
        let length = usize::from(*bytes.get(end)?);
        if length > 63 {
            return None;
        }
        end += 1 + length;
        if end - 12 > 255 || end > bytes.len() {
            return None;
        }
        if length == 0 {
            break;
        }
    }
    let query = Packet::parse(bytes).ok()?;
    match query.questions.first()?.qclass {
        QCLASS::CLASS(CLASS::IN) | QCLASS::ANY => Some(query),
        _ => None,
    }
}

/// Copy only the question and client flags; never reflect supplied records.
pub(crate) fn reply<'a>(query: &Packet<'a>) -> Packet<'a> {
    let mut response = Packet::new_reply(query.id());
    for flag in [PacketFlag::RECURSION_DESIRED, PacketFlag::CHECKING_DISABLED] {
        if query.has_flags(flag) {
            response.set_flags(flag);
        }
    }
    response.questions.clone_from(&query.questions);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn never_answer_reflector_service_ports() {
        for port in [0, 7, 13, 17, 19, 37] {
            assert!(!accepts_source_port(port));
        }
        for port in [53, 5353, 12345, 65535] {
            assert!(accepts_source_port(port));
        }
    }

    #[test]
    fn reject_compressed_first_question_without_following_its_pointer() {
        let bytes = [0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 28, 0, 1];
        assert!(parse_query(&bytes).is_none());
    }
}
