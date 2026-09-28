use super::*;

use simple_dns::{Name, Question};
use tokio::sync::mpsc;

const TEST_TTL: u32 = 60;

/// Build a client-facing AAAA query.
fn build_query(id: u16, qname: &str) -> Vec<u8> {
    build_query_of_type(id, qname, QTYPE::TYPE(TYPE::AAAA))
}

/// Build a client-facing query of any type.
fn build_query_of_type(id: u16, qname: &str, qtype: QTYPE) -> Vec<u8> {
    let mut packet = Packet::new_query(id);
    let question = Question::new(Name::new_unchecked(qname), qtype, CLASS::IN.into(), false);
    packet.questions.push(question);
    packet.build_bytes_vec_compressed().unwrap()
}

/// Assert the response is NODATA: NOERROR with no answer records.
fn assert_nodata(response: &[u8]) {
    let packet = Packet::parse(response).unwrap();
    assert_eq!(packet.rcode(), RCODE::NoError);
    assert!(
        packet.answers.is_empty(),
        "expected NODATA, got {} answer(s)",
        packet.answers.len()
    );
}

/// Build an upstream NOERROR AAAA answer.
fn build_answer(id: u16, qname: &str, addr: &str) -> Vec<u8> {
    let mut packet = Packet::new_reply(id);
    packet.set_flags(PacketFlag::RESPONSE | PacketFlag::RECURSION_AVAILABLE);
    let name = Name::new_unchecked(qname);
    packet.questions.push(Question::new(
        name.clone(),
        QTYPE::TYPE(TYPE::AAAA),
        CLASS::IN.into(),
        false,
    ));
    let address: Ipv6Addr = addr.parse().unwrap();
    packet.answers.push(ResourceRecord::new(
        name,
        CLASS::IN,
        TEST_TTL,
        rdata::RData::AAAA(rdata::AAAA {
            address: address.into(),
        }),
    ));
    packet.build_bytes_vec_compressed().unwrap()
}

/// A fake upstream that answers one query with a scripted list of
/// datagrams, in order, from its own socket.
fn spawn_upstream<F>(socket: UdpSocket, replies: F) -> tokio::task::JoinHandle<()>
where
    F: FnOnce(u16) -> Vec<Vec<u8>> + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DNS_SIZE];
        let (len, src) = socket.recv_from(&mut buf).await.unwrap();
        let observed_id = Packet::parse(&buf[..len]).unwrap().id();
        for reply in replies(observed_id) {
            socket.send_to(&reply, src).await.unwrap();
        }
    })
}

fn test_pool() -> std::sync::Arc<tokio::sync::Mutex<VirtualIpPool>> {
    std::sync::Arc::new(tokio::sync::Mutex::new(
        VirtualIpPool::new("fd01::/112", TEST_TTL as u64, 30).unwrap(),
    ))
}

/// Assert the response is an AAAA answer whose address came from the pool.
fn assert_pool_answer(response: &[u8]) -> Ipv6Addr {
    let packet = Packet::parse(response).unwrap();
    assert_eq!(packet.rcode(), RCODE::NoError);
    let addr = extract_aaaa(&packet).expect("expected an AAAA answer");
    assert!(
        addr.octets()[0] == 0xfd && addr.octets()[1] == 0x01,
        "expected a pool virtual IP, got {addr}"
    );
    addr
}

#[test]
fn test_node_addr_from_mesh() {
    // fd00::1 → node_addr bytes should be [0, 0, ..., 0, 1] in positions 0..15
    let mesh: Ipv6Addr = "fd00::1".parse().unwrap();
    let node = node_addr_from_mesh(mesh).unwrap();
    let bytes = node.as_bytes();
    // mesh = [0xfd, 0, 0, ..., 0, 1]
    // node = bytes[1..16] of mesh = [0, 0, ..., 0, 1] in first 15 bytes
    assert_eq!(bytes[14], 1);
    assert_eq!(bytes[0], 0);
}

#[test]
fn test_node_addr_from_mesh_rejects_non_mesh() {
    let addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
    assert!(node_addr_from_mesh(addr).is_none());
}

#[tokio::test]
async fn test_foreign_source_answer_not_accepted() {
    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let foreign = UdpSocket::bind("[::1]:0").await.unwrap();

    // The fake upstream learns the gateway's ephemeral port from the query
    // it receives, has a third socket forge an answer to that port, then
    // sends the genuine answer itself.
    let handle = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_DNS_SIZE];
        let (len, src) = upstream_socket.recv_from(&mut buf).await.unwrap();
        let observed_id = Packet::parse(&buf[..len]).unwrap().id();
        let forged = build_answer(observed_id, "test.fips", "2001:db8::1");
        foreign.send_to(&forged, src).await.unwrap();
        let genuine = build_answer(observed_id, "test.fips", "fd00::1");
        upstream_socket.send_to(&genuine, src).await.unwrap();
    });

    let pool = test_pool();
    let (event_tx, mut event_rx) = mpsc::channel(16);
    let response = handle_query(
        &build_query(0x1234, "test.fips"),
        upstream,
        TEST_TTL,
        &pool,
        &event_tx,
    )
    .await
    .unwrap();
    handle.await.unwrap();

    assert_pool_answer(&response);
    match event_rx.try_recv().unwrap() {
        PoolEvent::MappingCreated { mesh_addr, .. } => {
            assert_eq!(mesh_addr, "fd00::1".parse::<Ipv6Addr>().unwrap());
        }
        other => panic!("unexpected event: {other:?}"),
    }
    assert!(matches!(
        event_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn test_upstream_id_mismatch_discarded() {
    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let handle = spawn_upstream(upstream_socket, |id| {
        vec![
            build_answer(id.wrapping_add(1), "test.fips", "2001:db8::1"),
            build_answer(id, "test.fips", "fd00::1"),
        ]
    });

    let pool = test_pool();
    let (event_tx, mut event_rx) = mpsc::channel(16);
    let response = handle_query(
        &build_query(0x1234, "test.fips"),
        upstream,
        TEST_TTL,
        &pool,
        &event_tx,
    )
    .await
    .unwrap();
    handle.await.unwrap();

    assert_pool_answer(&response);
    match event_rx.try_recv().unwrap() {
        PoolEvent::MappingCreated { mesh_addr, .. } => {
            assert_eq!(mesh_addr, "fd00::1".parse::<Ipv6Addr>().unwrap());
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[tokio::test]
async fn test_upstream_question_mismatch_discarded() {
    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let handle = spawn_upstream(upstream_socket, |id| {
        vec![
            build_answer(id, "other.fips", "2001:db8::1"),
            build_answer(id, "test.fips", "fd00::1"),
        ]
    });

    let pool = test_pool();
    let (event_tx, mut event_rx) = mpsc::channel(16);
    let response = handle_query(
        &build_query(0x1234, "test.fips"),
        upstream,
        TEST_TTL,
        &pool,
        &event_tx,
    )
    .await
    .unwrap();
    handle.await.unwrap();

    assert_pool_answer(&response);
    match event_rx.try_recv().unwrap() {
        PoolEvent::MappingCreated { mesh_addr, .. } => {
            assert_eq!(mesh_addr, "fd00::1".parse::<Ipv6Addr>().unwrap());
        }
        other => panic!("unexpected event: {other:?}"),
    }
}

#[tokio::test]
async fn test_non_mesh_aaaa_rejected() {
    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let handle = spawn_upstream(upstream_socket, |id| {
        vec![build_answer(id, "test.fips", "2001:db8::1")]
    });

    let pool = test_pool();
    let (event_tx, mut event_rx) = mpsc::channel(16);
    let response = handle_query(
        &build_query(0x1234, "test.fips"),
        upstream,
        TEST_TTL,
        &pool,
        &event_tx,
    )
    .await
    .unwrap();
    handle.await.unwrap();

    let packet = Packet::parse(&response).unwrap();
    assert_eq!(packet.rcode(), RCODE::ServerFailure);
    assert!(matches!(
        event_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[tokio::test]
async fn an_a_query_returns_nodata_and_mints_no_mapping() {
    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let handle = spawn_upstream(upstream_socket, |id| {
        vec![build_answer(id, "test.fips", "fd00::1")]
    });

    let pool = test_pool();
    let (event_tx, mut event_rx) = mpsc::channel(16);
    let response = handle_query(
        &build_query_of_type(0x1234, "test.fips", QTYPE::TYPE(TYPE::A)),
        upstream,
        TEST_TTL,
        &pool,
        &event_tx,
    )
    .await
    .unwrap();
    handle.await.unwrap();

    assert_nodata(&response);
    assert!(
        matches!(event_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "an A query minted a mapping, so any LAN host can take a pool \
         address per name with a query type it is never given one for"
    );
    assert!(
        pool.lock()
            .await
            .mapping_info(std::time::Instant::now())
            .is_empty(),
        "an A query left a mapping in the pool"
    );
}

#[tokio::test]
async fn an_a_query_refreshes_an_existing_mapping_without_creating_one() {
    let pool = test_pool();
    let (event_tx, mut event_rx) = mpsc::channel(16);

    // An AAAA query mints the mapping.
    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let handle = spawn_upstream(upstream_socket, |id| {
        vec![build_answer(id, "test.fips", "fd00::1")]
    });
    let response = handle_query(
        &build_query(0x1234, "test.fips"),
        upstream,
        TEST_TTL,
        &pool,
        &event_tx,
    )
    .await
    .unwrap();
    handle.await.unwrap();
    let virtual_ip = assert_pool_answer(&response);
    assert!(matches!(
        event_rx.try_recv().unwrap(),
        PoolEvent::MappingCreated { .. }
    ));

    let before = {
        let guard = pool.lock().await;
        guard
            .lookup_virtual_ip(&virtual_ip)
            .unwrap()
            .last_referenced
    };

    // An A query for the same name refreshes it and creates nothing. A
    // client that re-queries a mapped name with both types must not lose
    // half of its refresh: with no conntrack sessions, the DNS reference
    // is the only thing keeping the mapping alive.
    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let handle = spawn_upstream(upstream_socket, |id| {
        vec![build_answer(id, "test.fips", "fd00::1")]
    });
    let response = handle_query(
        &build_query_of_type(0x1235, "test.fips", QTYPE::TYPE(TYPE::A)),
        upstream,
        TEST_TTL,
        &pool,
        &event_tx,
    )
    .await
    .unwrap();
    handle.await.unwrap();

    assert_nodata(&response);

    let guard = pool.lock().await;
    let mapping = guard
        .lookup_virtual_ip(&virtual_ip)
        .expect("the A query removed or replaced the mapping");
    assert!(
        mapping.last_referenced > before,
        "the A query did not refresh the mapping's TTL clock"
    );
    drop(guard);

    assert!(
        matches!(event_rx.try_recv(), Err(mpsc::error::TryRecvError::Empty)),
        "the A query sent a second MappingCreated"
    );
}

#[tokio::test]
async fn test_healthy_path_resolves() {
    let upstream_socket = UdpSocket::bind("[::1]:0").await.unwrap();
    let upstream = upstream_socket.local_addr().unwrap();
    let handle = spawn_upstream(upstream_socket, |id| {
        vec![build_answer(id, "test.fips", "fd00::1")]
    });

    let pool = test_pool();
    let (event_tx, mut event_rx) = mpsc::channel(16);
    let response = handle_query(
        &build_query(0x1234, "test.fips"),
        upstream,
        TEST_TTL,
        &pool,
        &event_tx,
    )
    .await
    .unwrap();
    handle.await.unwrap();

    assert_pool_answer(&response);
    match event_rx.try_recv().unwrap() {
        PoolEvent::MappingCreated { mesh_addr, .. } => {
            assert_eq!(mesh_addr, "fd00::1".parse::<Ipv6Addr>().unwrap());
        }
        other => panic!("unexpected event: {other:?}"),
    }
    assert!(matches!(
        event_rx.try_recv(),
        Err(mpsc::error::TryRecvError::Empty)
    ));
}

#[test]
fn an_in_use_hint_names_the_mdns_responders_for_5353() {
    let hint = holder_hint(5353);
    assert!(hint.contains("mDNS"), "{hint}");
    assert!(hint.contains("node.discovery.lan"), "{hint}");
    assert!(hint.contains("avahi-daemon"), "{hint}");
}

#[test]
fn an_in_use_hint_names_llmnr_for_5355() {
    let hint = holder_hint(5355);
    assert!(hint.contains("LLMNR"), "{hint}");
    assert!(!hint.contains("mDNS"), "{hint}");
}

#[test]
fn an_in_use_hint_names_the_daemon_for_5354() {
    let hint = holder_hint(5354);
    assert!(hint.contains("fips daemon's own DNS responder"), "{hint}");
}

#[test]
fn an_in_use_hint_names_a_dns_server_for_53() {
    let hint = holder_hint(53);
    assert!(hint.contains("another DNS server"), "{hint}");
    assert!(hint.contains("dnsmasq"), "{hint}");
}

#[test]
fn an_in_use_hint_names_another_gateway_for_the_default_port() {
    let hint = holder_hint(5365);
    assert!(hint.contains("another fips-gateway"), "{hint}");
}

#[test]
fn an_in_use_hint_names_another_process_for_an_unknown_port() {
    assert_eq!(holder_hint(40000), "another process holds it");
}

#[tokio::test]
async fn binding_a_held_port_fails_with_addr_in_use_and_names_the_port_ss_and_netstat() {
    let holder = UdpSocket::bind("[::1]:0").await.unwrap();
    let port = holder.local_addr().unwrap().port();
    let listen = format!("[::1]:{port}");

    let err = bind_listener(&listen)
        .await
        .expect_err("binding a held port must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::AddrInUse);
    let message = err.to_string();
    assert!(message.contains(&listen), "{message}");
    assert!(message.contains(&format!("sport = :{port}")), "{message}");
    assert!(message.contains("ss -ulpn"), "{message}");
    assert!(message.contains("netstat -ulnp"), "{message}");
    assert!(message.contains(holder_hint(port)), "{message}");
}

#[tokio::test]
async fn binding_a_free_port_returns_a_bound_socket() {
    let socket = bind_listener("[::1]:0").await.expect("bind a free port");
    assert_ne!(socket.local_addr().unwrap().port(), 0);
}

#[test]
fn test_extract_fips_name() {
    // Build a simple AAAA query for test.fips
    let mut packet = Packet::new_query(1);
    use simple_dns::{Name, Question};
    let name = Name::new_unchecked("test.fips");
    let question = Question::new(name, QTYPE::TYPE(TYPE::AAAA), CLASS::IN.into(), false);
    packet.questions.push(question);

    let result = extract_fips_name(&packet);
    assert_eq!(result, Some("test.fips".to_string()));
}

#[test]
fn test_extract_non_fips_name() {
    let mut packet = Packet::new_query(1);
    use simple_dns::{Name, Question};
    let name = Name::new_unchecked("example.com");
    let question = Question::new(name, QTYPE::TYPE(TYPE::AAAA), CLASS::IN.into(), false);
    packet.questions.push(question);

    assert!(extract_fips_name(&packet).is_none());
}

#[test]
fn test_build_aaaa_response() {
    let mut query = Packet::new_query(42);
    use simple_dns::{Name, Question};
    let name = Name::new_unchecked("test.fips");
    let question = Question::new(name, QTYPE::TYPE(TYPE::AAAA), CLASS::IN.into(), false);
    query.questions.push(question);

    let vip: Ipv6Addr = "fd01::1".parse().unwrap();
    let response_bytes = build_aaaa_response(&query, vip, 60).unwrap();
    let response = Packet::parse(&response_bytes).unwrap();

    assert_eq!(response.id(), 42);
    assert_eq!(response.answers.len(), 1);
    if let rdata::RData::AAAA(aaaa) = &response.answers[0].rdata {
        assert_eq!(Ipv6Addr::from(aaaa.address), vip);
    } else {
        panic!("Expected AAAA record");
    }
}
