use super::*;
use simple_dns::{QCLASS, Question};

fn query() -> Packet<'static> {
    let mut query = Packet::new_query(42);
    query.questions.push(Question::new(
        Name::new_unchecked("missing.fips"),
        QTYPE::TYPE(TYPE::AAAA),
        QCLASS::CLASS(CLASS::IN),
        false,
    ));
    query
}

#[test]
fn dns_does_not_answer_responses_or_echo_injected_records() {
    let hosts = HostMap::new();
    let mut response = query().into_reply();
    response.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
    assert!(
        handle_dns_packet(&response.build_bytes_vec_compressed().unwrap(), 300, &hosts).is_none()
    );

    for section in 0..3 {
        let mut query = query();
        let record = ResourceRecord::new(
            Name::new_unchecked("injected.fips"),
            CLASS::IN,
            300,
            RData::AAAA(AAAA::from(Ipv6Addr::LOCALHOST)),
        );
        match section {
            0 => query.answers.push(record),
            1 => query.name_servers.push(record),
            _ => query.additional_records.push(record),
        }
        let result = handle_dns_packet(&query.build_bytes_vec_compressed().unwrap(), 300, &hosts);
        if section < 2 {
            assert!(result.is_none(), "answer/authority records are not a query");
        } else {
            let (bytes, _) = result.expect("a query with one additional record is accepted");
            let reply = Packet::parse(&bytes).unwrap();
            assert!(reply.answers.is_empty());
            assert!(reply.name_servers.is_empty());
            assert!(
                reply.additional_records.is_empty(),
                "untrusted records must never be echoed"
            );
        }
    }
}

#[test]
fn dns_drops_multiple_questions_and_possibly_truncated_datagrams() {
    let hosts = HostMap::new();
    let mut query = query();
    query.questions.push(query.questions[0].clone());
    assert!(handle_dns_packet(&query.build_bytes_vec_compressed().unwrap(), 300, &hosts).is_none());
    query.questions.pop();
    let mut bytes = query.build_bytes_vec_compressed().unwrap();
    bytes.resize(4096, 0);
    assert!(handle_dns_packet(&bytes, 300, &hosts).is_none());
}

#[test]
fn dns_preserves_query_flags_and_clamps_ttl() {
    let mut hosts = HostMap::new();
    let identity = crate::Identity::generate();
    hosts.insert("missing", &identity.npub()).unwrap();
    let mut query = query();
    query.set_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::CHECKING_DISABLED);
    let (bytes, identity) = handle_dns_packet(
        &query.build_bytes_vec_compressed().unwrap(),
        u32::MAX,
        &hosts,
    )
    .unwrap();
    let reply = Packet::parse(&bytes).unwrap();
    assert!(identity.is_some());
    assert!(reply.has_flags(PacketFlag::RECURSION_DESIRED | PacketFlag::CHECKING_DISABLED));
    assert_eq!(reply.answers[0].ttl, i32::MAX as u32);
}
