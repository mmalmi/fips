use super::*;
use std::net::SocketAddrV6;

fn vip(last: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfd01, 0, 0, 0, 0, 0, 0, last)
}

fn mesh(last: u16) -> Ipv6Addr {
    Ipv6Addr::new(0xfd02, 0, 0, 0, 0, 0, 0, last)
}

/// A manager holding `count` mappings and no netlink socket.
fn manager_with_mappings(count: u16) -> NatManager {
    let mut mgr = NatManager::with_state("br-lan".to_string());
    for i in 1..=count {
        mgr.mappings.insert(
            vip(i),
            NatMapping {
                virtual_ip: vip(i),
                mesh_addr: mesh(i),
            },
        );
    }
    mgr
}

#[test]
#[ignore = "requires CAP_NET_ADMIN and nft in an isolated network namespace"]
fn kernel_nat_large_rebuild_is_atomic_on_rejection() {
    let mut manager = manager_with_mappings(1000);
    manager.rebuild().unwrap();
    let listing = || {
        let output = std::process::Command::new("nft")
            .args(["-j", "list", "table", "inet", TABLE_NAME])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
    };
    let before = listing();
    assert_eq!(
        before["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v.get("rule").is_some())
            .count(),
        2001
    );
    manager.mappings.remove(&vip(1));
    let mut invalid = manager.encode_batch(&manager.rebuild_batches()[0]).unwrap();
    let headers = nl_headers(&invalid).unwrap();
    let last = batch_objects(&headers).unwrap().last().unwrap().offset;
    // Invalid nf_tables operation at the end of a delete/recreate transaction.
    invalid[last + 4..last + 6].copy_from_slice(&0x0a7fu16.to_ne_bytes());
    assert!(send_batch(&invalid).is_err());
    assert_eq!(
        listing(),
        before,
        "a rejected replacement must retain the complete old table"
    );
    manager.rebuild().unwrap();
    assert_eq!(
        listing()["nftables"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v.get("rule").is_some())
            .count(),
        1999
    );
    manager.cleanup().unwrap();
}

#[test]
fn rebuild_deletes_and_recreates_the_table_inside_one_batch() {
    let batches = manager_with_mappings(3).rebuild_batches();

    assert_eq!(
        batches.len(),
        1,
        "a rebuild that sends the delete in a batch of its own leaves the \
         fips_gateway table absent between the two sends, so the gateway \
         has no NAT at all in that window: {batches:?}"
    );
    assert_eq!(
        batches[0][..3],
        [
            NatOp::Table(MsgType::Add),
            NatOp::Table(MsgType::Del),
            NatOp::Table(MsgType::Add),
        ],
        "the delete needs a preceding add so it always has a target, and a \
         following add to recreate the table inside the same transaction"
    );
}

#[test]
fn rebuild_deletes_the_table_exactly_once_and_before_every_rule() {
    let batches = manager_with_mappings(2).rebuild_batches();
    let ops = &batches[0];

    let deletes: Vec<usize> = ops
        .iter()
        .enumerate()
        .filter(|(_, op)| matches!(op, NatOp::Table(MsgType::Del)))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(deletes, vec![1], "the table is deleted once, at index 1");

    // Everything that lives in the table has to be added after the delete
    // and the recreate, or the delete would take it back out again.
    for (index, op) in ops.iter().enumerate() {
        if matches!(op, NatOp::Table(_)) {
            continue;
        }
        assert!(
            index > 2,
            "{op:?} at index {index} would be removed by the table delete"
        );
    }
}

#[test]
fn rebuild_emits_a_dnat_and_an_snat_for_every_mapping() {
    let ops = manager_with_mappings(3).rebuild_batches().remove(0);

    for i in 1..=3u16 {
        assert!(ops.contains(&NatOp::Dnat(vip(i))), "no DNAT for {}", vip(i));
        assert!(ops.contains(&NatOp::Snat(vip(i))), "no SNAT for {}", vip(i));
    }
    assert!(ops.contains(&NatOp::FipsMasquerade));
    assert!(!ops.contains(&NatOp::LanMasquerade), "no port forwards");
}

#[test]
fn rebuild_emits_the_lan_masquerade_once_when_port_forwards_exist() {
    let mut mgr = manager_with_mappings(1);
    mgr.port_forwards = vec![
        PortForward {
            proto: Proto::Tcp,
            listen_port: 8080,
            target: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0),
        },
        PortForward {
            proto: Proto::Udp,
            listen_port: 5353,
            target: SocketAddrV6::new(Ipv6Addr::LOCALHOST, 53, 0, 0),
        },
    ];

    let ops = mgr.rebuild_batches().remove(0);

    assert!(ops.contains(&NatOp::PortForward(0)));
    assert!(ops.contains(&NatOp::PortForward(1)));
    assert_eq!(
        ops.iter()
            .filter(|op| matches!(op, NatOp::LanMasquerade))
            .count(),
        1
    );
}

/// The encoded rebuild of a manager holding `count` mappings.
fn encoded_rebuild(count: u16) -> Vec<u8> {
    let mgr = manager_with_mappings(count);
    let ops = mgr.rebuild_batches().remove(0);
    mgr.encode_batch(&ops).expect("the rebuild encodes")
}

/// One netlink message, padded to 4 bytes.
fn nlmsg(kind: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    let len = (NLMSG_HDRLEN + payload.len()) as u32;
    let mut msg = Vec::new();
    msg.extend_from_slice(&len.to_ne_bytes());
    msg.extend_from_slice(&kind.to_ne_bytes());
    msg.extend_from_slice(&0u16.to_ne_bytes());
    msg.extend_from_slice(&seq.to_ne_bytes());
    msg.extend_from_slice(&0u32.to_ne_bytes());
    msg.extend_from_slice(payload);
    msg.resize(msg.len().div_ceil(4) * 4, 0);
    msg
}

/// The kernel's `NLMSG_ERROR` reply to message `seq`, as it sends it on a
/// socket with `NETLINK_CAP_ACK`: the error, then the request's header.
fn ack(seq: u32, error: i32) -> Vec<u8> {
    let mut payload = error.to_ne_bytes().to_vec();
    payload.extend_from_slice(&nlmsg(0x0a00, seq, &[])[..NLMSG_HDRLEN]);
    nlmsg(libc::NLMSG_ERROR as u16, seq, &payload)
}

/// The largest batch the kernel admits: twice its send-buffer clamp,
/// less the 32 bytes netlink reserves.
const KERNEL_BATCH_LIMIT: usize = 2_147_483_614;

#[test]
fn rebuild_for_2000_mappings_requests_exactly_one_ack_on_the_last_message() {
    let encoded = encoded_rebuild(2000);
    assert!(
        encoded.len() > 212_960,
        "the 2000-mapping batch ({} bytes) must be past the default \
         netlink send limit for this test to cover the large case",
        encoded.len()
    );

    let headers = nl_headers(&encoded).expect("the batch parses");
    assert_eq!(
        headers.first().map(|h| h.kind),
        Some(libc::NFNL_MSG_BATCH_BEGIN as u16)
    );
    assert_eq!(
        headers.last().map(|h| h.kind),
        Some(libc::NFNL_MSG_BATCH_END as u16)
    );
    let acked: Vec<usize> = headers
        .iter()
        .enumerate()
        .filter(|(_, h)| h.flags & libc::NLM_F_ACK as u16 != 0)
        .map(|(i, _)| i)
        .collect();
    assert_eq!(
        acked,
        vec![headers.len() - 2],
        "only the last object before the batch end may request an ack; \
         one ack per message overflows the receive buffer after the \
         kernel has committed the batch"
    );
}

#[test]
fn sndbuf_for_admits_the_2000_mapping_batch_and_small_batches_after_kernel_doubling() {
    let large = encoded_rebuild(2000).len();
    for len in [large, 0, 1, 212_961] {
        let sndbuf = sndbuf_for(len);
        assert!(
            2 * sndbuf as u64 - 32 >= len as u64,
            "a send buffer of {sndbuf}, doubled by the kernel, refuses a \
             {len}-byte batch"
        );
    }
}

#[test]
fn sndbuf_for_saturates_at_the_kernel_clamp_for_huge_batches() {
    for len in [2 * MAX_SNDBUF as usize, usize::MAX] {
        assert_eq!(sndbuf_for(len), i32::MAX / 2, "sndbuf_for({len})");
    }
}

#[test]
fn check_admissible_refuses_a_batch_larger_than_the_kernel_can_accept() {
    assert!(check_admissible(KERNEL_BATCH_LIMIT).is_ok());
    for len in [KERNEL_BATCH_LIMIT + 1, usize::MAX] {
        match check_admissible(len) {
            Err(e @ NatError::BatchTooLarge { bytes }) => {
                assert_eq!(bytes, len);
                assert!(
                    e.to_string().contains(&len.to_string()),
                    "the error names the batch size: {e}"
                );
            }
            other => panic!("a {len}-byte batch was admitted: {other:?}"),
        }
    }
}

#[test]
fn ack_reader_fails_on_an_error_that_precedes_the_last_ack() {
    // The kernel aborts the batch on a failing rule mid-batch, reports
    // that rule's error, and still acknowledges the last message.
    let reader = AckReader { last_seq: 4000 };
    let error = ack(1234, -libc::ENOENT);
    let last = ack(4000, 0);

    let expect_error = |result: Result<AckState, NatError>| match result {
        Err(NatError::Kernel { errno, seq }) => {
            assert_eq!(errno, Errno(libc::ENOENT));
            assert_eq!(seq, 1234);
        }
        other => panic!("the aborted batch was not reported: {other:?}"),
    };

    expect_error(reader.feed(&error));
    expect_error(reader.feed(&[error.clone(), last.clone()].concat()));
}

#[test]
fn ack_reader_is_done_only_on_the_last_sequence_ack() {
    let reader = AckReader { last_seq: 10 };

    assert_eq!(reader.feed(&ack(10, 0)).expect("parses"), AckState::Done);
    assert_eq!(reader.feed(&ack(5, 0)).expect("parses"), AckState::Pending);
    assert_eq!(
        reader
            .feed(&nlmsg(libc::NLMSG_NOOP as u16, 10, &[]))
            .expect("parses"),
        AckState::Pending
    );
    assert_eq!(
        reader
            .feed(&[ack(5, 0), ack(10, 0)].concat())
            .expect("parses"),
        AckState::Done
    );

    let whole = ack(10, 0);
    assert!(
        reader.feed(&whole[..8]).is_err(),
        "a header shorter than 16 bytes"
    );
    let mut overlong = whole.clone();
    overlong[..4].copy_from_slice(&((whole.len() + 4) as u32).to_ne_bytes());
    assert!(
        reader.feed(&overlong).is_err(),
        "a length past the end of the datagram"
    );
    let short = nlmsg(libc::NLMSG_ERROR as u16, 10, &[0, 0]);
    assert!(
        reader.feed(&short[..NLMSG_HDRLEN + 2]).is_err(),
        "an NLMSG_ERROR payload shorter than its error field"
    );
}

#[test]
fn kernel_error_display_names_the_errno() {
    let text = NatError::Kernel {
        errno: Errno(libc::EMSGSIZE),
        seq: 7,
    }
    .to_string();
    assert!(text.contains("EMSGSIZE"), "{text}");
    assert!(text.contains(&format!("({})", libc::EMSGSIZE)), "{text}");
}
