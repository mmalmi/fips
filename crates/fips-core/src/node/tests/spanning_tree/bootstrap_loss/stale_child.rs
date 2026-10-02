//! One lost child update must not leave its parent on an obsolete root.
use super::*;

#[path = "stale_child_completion.rs"]
mod completion;

// Observe a copy of the real encrypted frame to select the one loss. The live
// Noise session, replay window, and counters are not advanced by this observer.
fn announced_tree(
    receiver: &TestNode,
    peer: &NodeAddr,
    packet: &ReceivedPacket,
) -> Option<TreeAnnounce> {
    let wire = packet.data.as_slice();
    if CommonPrefix::parse(wire).unwrap().phase != PHASE_ESTABLISHED {
        return None;
    }
    let header = crate::dataplane::FmpWireHeader::parse_encrypted(wire).unwrap();
    let offset = usize::from(header.ciphertext_offset());
    let cipher = receiver
        .node
        .get_peer(peer)
        .unwrap()
        .noise_session()
        .unwrap()
        .recv_cipher_clone()
        .unwrap();
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&header.counter().to_le_bytes());
    let mut ciphertext = wire[offset..].to_vec();
    let plaintext = cipher
        .open_in_place(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::from(&wire[..offset]),
            &mut ciphertext,
        )
        .unwrap();
    // Established FMP plaintext starts with its four-byte relative timestamp.
    (plaintext.get(4) == Some(&crate::protocol::LinkMessageType::TreeAnnounce.to_byte()))
        .then(|| TreeAnnounce::decode(&plaintext[5..]).unwrap())
}

async fn drop_child_root_update(nodes: &mut [TestNode]) -> u64 {
    let root = *nodes[0].node.node_addr();
    let child = *nodes[1].node.node_addr();
    let mut held_root_announcements = Vec::new();
    let started = Instant::now();
    loop {
        // First let the parent learn the child's genuine self-root declaration.
        // Hold only parent TreeAnnounce frames until that premise is established.
        for index in 0..2 {
            while let Ok(packet) = nodes[index].packet_rx.try_recv() {
                let phase = CommonPrefix::parse(packet.data.as_slice()).unwrap().phase;
                if phase == PHASE_MSG2 {
                    // complete_direct_handshake already handled this queued copy.
                    continue;
                }
                assert_eq!(phase, PHASE_ESTABLISHED);
                let remote = if index == 0 { child } else { root };
                let announce = announced_tree(&nodes[index], &remote, &packet);
                if index == 1
                    && announce.is_some()
                    && nodes[0]
                        .node
                        .tree_state()
                        .peer_declaration(&child)
                        .is_none()
                {
                    held_root_announcements.push(packet);
                    continue;
                }
                if index == 0
                    && let Some(announce) = announce
                    && *announce.ancestry.root_id() == root
                {
                    let previous = nodes[0].node.tree_state().peer_declaration(&child).unwrap();
                    assert!(
                        previous.is_root(),
                        "parent must retain the actual old self-root declaration"
                    );
                    assert!(*announce.declaration.parent_id() == root);
                    assert!(announce.declaration.sequence() > previous.sequence());
                    announce
                        .declaration
                        .verify(&nodes[0].node.get_peer(&child).unwrap().pubkey())
                        .unwrap();
                    announce.validate_semantics().unwrap();
                    assert_eq!(*nodes[1].node.tree_state().root(), root);
                    assert_eq!(
                        *nodes[0]
                            .node
                            .tree_state()
                            .peer_coords(&child)
                            .unwrap()
                            .root_id(),
                        child
                    );
                    assert!(
                        !nodes[1]
                            .node
                            .get_peer(&root)
                            .unwrap()
                            .has_pending_tree_announce(),
                        "the dropped successful send must not itself leave a pending retry"
                    );
                    assert!(held_root_announcements.is_empty());
                    // Exactly this real, newly signed child-root-change frame is
                    // lost. Every other frame will continue through the dataplane.
                    return announce.declaration.sequence();
                }
                process_dataplane_packet(&mut nodes[index], packet).await;
            }
        }
        if nodes[0]
            .node
            .tree_state()
            .peer_declaration(&child)
            .is_some()
        {
            for packet in held_root_announcements.drain(..) {
                process_dataplane_packet(&mut nodes[1], packet).await;
            }
        }
        for node in nodes.iter_mut() {
            process_dataplane_completions(&mut node.node).await;
            node.node.check_mmp_reports().await;
            node.node.send_pending_tree_announces().await;
        }
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "real child-root-change frame was not produced"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

#[tokio::test]
async fn lost_child_root_change_repairs_before_periodic_refresh_without_echo() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    nodes.sort_by_key(|node| *node.node.node_addr());
    let result = AssertUnwindSafe(async {
        for node in &nodes {
            assert_eq!(node.node.config.node.tree.announce_min_interval_ms, 500);
            assert_eq!(node.node.config.node.tree.announce_refresh_interval_secs, 5);
            assert_eq!(node.node.config.node.tree.reeval_interval_secs, 60);
        }
        Box::pin(complete_direct_handshake(&mut nodes, 0, 1)).await;
        let authenticated = edges(&nodes);
        let indices: Vec<_> = nodes.iter().map(|node| {
            node.node.peers.values().next().unwrap().our_index()
        }).collect();
        let initial_sent: Vec<_> = nodes.iter().map(|node| {
            node.node.peers.values().next().unwrap().last_tree_announce_sent_ms()
        }).collect();
        let lost_sequence = drop_child_root_update(&mut nodes).await;
        assert!(!synchronized(&nodes));
        let stale_before = nodes[1].node.stats().tree.stale;
        let started = Instant::now();
        let mut next_tick = started + Duration::from_secs(1);
        let mut observed = sent_counts(&nodes);
        let mut timestamps: Vec<_> = nodes.iter().map(|node| {
            node.node.peers.values().next().unwrap().last_tree_announce_sent_ms()
        }).collect();
        while started.elapsed() < Duration::from_secs(2) {
            process_available_packets(&mut nodes).await;
            for node in &mut nodes {
                node.node.check_mmp_reports().await;
                node.node.send_pending_tree_announces().await;
            }
            if Instant::now() >= next_tick {
                production_tick(&mut nodes).await;
                next_tick += Duration::from_secs(1);
            }
            process_available_packets(&mut nodes).await;
            assert_eq!(edges(&nodes), authenticated);
            for (index, node) in nodes.iter().enumerate() {
                let peer = node.node.peers.values().next().unwrap();
                assert_eq!(peer.our_index(), indices[index]);
                let sent = node.node.stats().tree.sent;
                if sent != observed[index] {
                    let timestamp = peer.last_tree_announce_sent_ms();
                    assert_eq!(sent, observed[index] + 1, "repair must not burst announcements");
                    assert!(timestamp.saturating_sub(timestamps[index]) >= 500);
                    assert!(timestamp.saturating_sub(initial_sent[index]) < 5_000,
                        "periodic refresh must not satisfy prompt repair");
                    observed[index] = sent;
                    timestamps[index] = timestamp;
                }
            }
            if synchronized(&nodes) && measured(&nodes) { break; }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let child = *nodes[1].node.node_addr();
        eprintln!("lost child root update: repair_ms={}, lost_sequence={lost_sequence}, synchronized={}, sent={observed:?}",
            started.elapsed().as_millis(), synchronized(&nodes));
        assert!(measured(&nodes), "real link feedback is required for the repair premise");
        assert!(synchronized(&nodes),
            "parent must replace the obsolete child root before the five-second periodic refresh");
        assert_eq!(nodes[0].node.tree_state().peer_declaration(&child).unwrap().sequence(), lost_sequence,
            "repair must repeat the current signed declaration without fabricating a new sequence");
        assert!(nodes[1].node.stats().tree.stale > stale_before,
            "the child must receive a fresh encrypted copy of its parent's unchanged declaration");
        verify_tree_convergence(&nodes);

        let quiet = Instant::now();
        let sent = sent_counts(&nodes);
        while quiet.elapsed() < Duration::from_secs(3) {
            process_available_packets(&mut nodes).await;
            for node in &mut nodes {
                node.node.check_mmp_reports().await;
                node.node.send_pending_tree_announces().await;
            }
            if Instant::now() >= next_tick {
                production_tick(&mut nodes).await;
                next_tick += Duration::from_secs(1);
            }
            assert_eq!(edges(&nodes), authenticated);
            assert!(synchronized(&nodes), "repair must settle without a same-root echo");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        for (after, before) in sent_counts(&nodes).into_iter().zip(sent) {
            assert!(after - before <= 1,
                "synchronized neighbors must retain the existing quiet-tree traffic bound");
        }
    }).catch_unwind().await;
    cleanup_nodes(&mut nodes).await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn first_rtt_preserves_pending_and_later_reports_repair_without_periodic_refresh() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    nodes.sort_by_key(|node| *node.node.node_addr());
    let result = AssertUnwindSafe(async {
        for node in &mut nodes {
            node.node.config.node.tree.announce_refresh_interval_secs = 0;
            assert_eq!(node.node.config.node.tree.announce_min_interval_ms, 500);
        }
        Box::pin(complete_direct_handshake(&mut nodes, 0, 1)).await;
        let root = *nodes[0].node.node_addr();
        let child = *nodes[1].node.node_addr();
        let authenticated = edges(&nodes);
        let indices: Vec<_> = nodes.iter().map(|node| {
            node.node.peers.values().next().unwrap().our_index()
        }).collect();
        let mut sent = sent_counts(&nodes);
        let mut timestamps: Vec<_> = nodes.iter().map(|node| {
            node.node.peers.values().next().unwrap().last_tree_announce_sent_ms()
        }).collect();
        let mut lost_root_announcements = 0;
        let mut pending_at_first_rtt = None;
        let mut subsequent_report_rearmed = false;
        let mut repeated_child_declaration = false;
        let started = Instant::now();
        let deadline = started + Duration::from_secs(3);
        let mut next_tick = started + Duration::from_secs(1);

        // The root retains the child's real original self-root declaration.
        // Drop root declarations until a report AFTER the first RTT has re-armed
        // a cleared pending flag and caused another real child announcement.
        // The first RTT must preserve any work already pending. Heartbeats and
        // ReceiverReports remain genuine and flow
        // throughout; no tree state, RTT, send time, or pending flag is injected.
        while started.elapsed() < Duration::from_secs(3) {
            for index in 0..2 {
                while let Ok(packet) = nodes[index].packet_rx.try_recv() {
                    let phase = CommonPrefix::parse(packet.data.as_slice()).unwrap().phase;
                    if phase == PHASE_MSG2 {
                        // The handshake helper already processed this queued copy.
                        continue;
                    }
                    assert_eq!(phase, PHASE_ESTABLISHED);
                    let remote = if index == 0 { child } else { root };
                    let announce = announced_tree(&nodes[index], &remote, &packet);
                    if index == 1 && announce.is_some() && !repeated_child_declaration {
                        lost_root_announcements += 1;
                        continue;
                    }
                    let repeated_old_child = index == 0 && announce.as_ref().is_some_and(|announce| {
                        nodes[0].node.tree_state().peer_declaration(&child).is_some_and(|old| {
                            old.is_root()
                                && old.sequence() == announce.declaration.sequence()
                                && *announce.ancestry.root_id() == child
                        })
                    });
                    let was_measured = nodes[1].node.dataplane_fmp_has_srtt(&root);
                    let was_pending = nodes[1].node.get_peer(&root).unwrap().has_pending_tree_announce();
                    let child_sent_before = nodes[1].node.stats().tree.sent;
                    let stale_before = nodes[0].node.stats().tree.stale;
                    assert!(completion::process_frame(
                        &mut nodes[index].node, remote, packet, deadline,
                    ).await, "selected encrypted frame must finish its ordinary handler before the repair deadline");
                    if index == 1 && !was_measured && nodes[1].node.dataplane_fmp_has_srtt(&root) {
                        assert!(nodes[1].node.tree_state().peer_declaration(&root).is_none());
                        assert_eq!(*nodes[1].node.tree_state().root(), child);
                        assert_eq!(nodes[1].node.stats().tree.sent, child_sent_before);
                        assert_eq!(nodes[1].node.get_peer(&root).unwrap().has_pending_tree_announce(), was_pending,
                            "first-RTT deferral must neither create nor discard already-owned work");
                        pending_at_first_rtt = Some(was_pending);
                    } else if index == 1 && was_measured && !was_pending
                        && nodes[1].node.tree_state().peer_declaration(&root).is_none()
                        && nodes[1].node.get_peer(&root).unwrap().has_pending_tree_announce()
                    {
                        // All parent TreeAnnounces are still held. The incoming
                        // report must create a new repair after an earlier send
                        // cleared pending state; one old pending send is not enough.
                        subsequent_report_rearmed = true;
                    }
                    if repeated_old_child {
                        assert!(nodes[0].node.stats().tree.stale > stale_before,
                            "fresh encrypted repair must reach the ordinary stale-declaration handler");
                        repeated_child_declaration = subsequent_report_rearmed;
                    }
                }
            }
            for node in &mut nodes {
                process_dataplane_completions(&mut node.node).await;
                node.node.check_mmp_reports().await;
                node.node.send_pending_tree_announces().await;
            }
            if Instant::now() >= next_tick {
                production_tick(&mut nodes).await;
                next_tick += Duration::from_secs(1);
            }
            assert_eq!(edges(&nodes), authenticated);
            for (index, node) in nodes.iter().enumerate() {
                let peer = node.node.peers.values().next().unwrap();
                assert_eq!(peer.our_index(), indices[index]);
                let current_sent = node.node.stats().tree.sent;
                if current_sent != sent[index] {
                    assert_eq!(current_sent, sent[index] + 1, "repair must not burst");
                    assert!(peer.last_tree_announce_sent_ms().saturating_sub(timestamps[index]) >= 500);
                    sent[index] = current_sent;
                    timestamps[index] = peer.last_tree_announce_sent_ms();
                }
            }
            if repeated_child_declaration && synchronized(&nodes) && measured(&nodes) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        eprintln!("first-RTT loss repair: elapsed_ms={}, lost_root_announcements={lost_root_announcements}, pending_at_first_rtt={pending_at_first_rtt:?}, subsequent_report_rearmed={subsequent_report_rearmed}, repeated_child={repeated_child_declaration}, synchronized={}, sent={sent:?}",
            started.elapsed().as_millis(), synchronized(&nodes));
        assert!(lost_root_announcements > 0);
        assert!(pending_at_first_rtt.is_some() && subsequent_report_rearmed && repeated_child_declaration,
            "later reports must re-arm repair after old pending work has cleared");
        assert!(synchronized(&nodes) && measured(&nodes),
            "lost declarations must recover with periodic refresh disabled");
        verify_tree_convergence(&nodes);
    }).catch_unwind().await;
    cleanup_nodes(&mut nodes).await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}

#[tokio::test]
async fn invalid_parent_and_same_root_nonparent_announcements_do_not_repush() {
    let mut nodes = vec![make_test_node().await, make_test_node().await];
    nodes.sort_by_key(|node| *node.node.node_addr());
    let result = AssertUnwindSafe(async {
        Box::pin(complete_direct_handshake(&mut nodes, 0, 1)).await;
        let authenticated = edges(&nodes);
        let setup = Instant::now();
        let mut settled_since = None;
        loop {
            process_available_packets(&mut nodes).await;
            for node in &mut nodes {
                node.node.check_mmp_reports().await;
                node.node.send_pending_tree_announces().await;
            }
            process_available_packets(&mut nodes).await;
            if synchronized(&nodes) && measured(&nodes) {
                let since = settled_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= Duration::from_millis(100) {
                    break;
                }
            } else {
                settled_since = None;
            }
            assert!(
                setup.elapsed() < Duration::from_secs(3),
                "native tree did not settle"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let root = *nodes[0].node.node_addr();
        let child = *nodes[1].node.node_addr();
        assert_eq!(
            *nodes[1].node.tree_state().my_declaration().parent_id(),
            root
        );
        assert_ne!(
            *nodes[0].node.tree_state().my_declaration().parent_id(),
            child
        );
        let original_declarations: Vec<_> = nodes
            .iter()
            .map(|node| node.node.tree_state().my_declaration().clone())
            .collect();
        let before_sent = sent_counts(&nodes);
        let before_accepted: Vec<_> = nodes
            .iter()
            .map(|node| node.node.stats().tree.accepted)
            .collect();
        let before_sig_failed = nodes[1].node.stats().tree.sig_failed;
        let before_decode_error = nodes[1].node.stats().tree.decode_error;
        let before_stale = nodes[0].node.stats().tree.stale;

        let mut invalid_parent = nodes[0]
            .node
            .build_tree_announce()
            .unwrap()
            .encode()
            .unwrap();
        *invalid_parent.last_mut().unwrap() ^= 1;
        let decoded = TreeAnnounce::decode(&invalid_parent[1..])
            .expect("bad signature, not malformed encoding");
        decoded.validate_semantics().unwrap();
        assert!(
            decoded
                .declaration
                .verify(&nodes[1].node.get_peer(&root).unwrap().pubkey())
                .is_err()
        );
        let valid_nonparent = nodes[1]
            .node
            .build_tree_announce()
            .unwrap()
            .encode()
            .unwrap();
        // Both are new authenticated FMP frames. One carries a bad declaration
        // signature; the other carries the child's valid unchanged declaration.
        nodes[0]
            .node
            .send_dataplane_fmp_link_plaintext(&child, &invalid_parent, false)
            .await
            .unwrap();
        nodes[1]
            .node
            .send_dataplane_fmp_link_plaintext(&root, &valid_nonparent, false)
            .await
            .unwrap();
        let dispatched = Instant::now();
        loop {
            process_available_packets(&mut nodes).await;
            for node in &mut nodes {
                node.node.send_pending_tree_announces().await;
            }
            assert_eq!(
                sent_counts(&nodes),
                before_sent,
                "neither input may send a repair declaration"
            );
            assert_eq!(edges(&nodes), authenticated);
            assert!(
                synchronized(&nodes),
                "rejected or nonparent input must not change tree state or arm a pending reply"
            );
            for (index, node) in nodes.iter().enumerate() {
                assert_eq!(
                    node.node.tree_state().my_declaration(),
                    &original_declarations[index]
                );
                assert_eq!(node.node.stats().tree.accepted, before_accepted[index]);
                assert!(
                    !node
                        .node
                        .peers
                        .values()
                        .next()
                        .unwrap()
                        .has_pending_tree_announce()
                );
            }
            if nodes[1].node.stats().tree.sig_failed == before_sig_failed + 1
                && nodes[0].node.stats().tree.stale == before_stale + 1
            {
                break;
            }
            assert!(
                dispatched.elapsed() < Duration::from_secs(1),
                "both actual encrypted guard frames must reach the handler"
            );
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert_eq!(
            nodes[1].node.stats().tree.decode_error,
            before_decode_error,
            "the current-parent input must reach signature validation"
        );
    })
    .catch_unwind()
    .await;
    cleanup_nodes(&mut nodes).await;
    if let Err(error) = result {
        std::panic::resume_unwind(error);
    }
}
