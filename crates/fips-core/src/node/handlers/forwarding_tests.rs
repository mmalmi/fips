include!("forwarding_helpers.rs");

#[cfg(test)]
mod forwarding_fast_path_tests {
    use super::*;
    include!("forwarding_deferred_tests.rs");

    #[test]
    fn session_ack_route_pin_requires_matching_carried_identities() {
        let src = NodeAddr::from_bytes(1_u128.to_be_bytes());
        let dest = NodeAddr::from_bytes(2_u128.to_be_bytes());
        let root = NodeAddr::from_bytes(3_u128.to_be_bytes());
        let src_coords = crate::tree::TreeCoordinate::from_addrs(vec![src, root]).unwrap();
        let dest_coords = crate::tree::TreeCoordinate::from_addrs(vec![dest, root]).unwrap();
        let encoded = SessionDatagram::new(
            src,
            dest,
            SessionAck::new(src_coords.clone(), dest_coords).encode(),
        )
        .encode();
        let datagram = SessionDatagramRef::decode(&encoded[1..]).unwrap();
        assert_eq!(session_ack_source(&datagram), Some(src));

        let mismatched = SessionDatagram::new(
            src,
            dest,
            SessionAck::new(
                crate::tree::TreeCoordinate::from_addrs(vec![dest, root]).unwrap(),
                src_coords,
            )
            .encode(),
        )
        .encode();
        let datagram = SessionDatagramRef::decode(&mismatched[1..]).unwrap();
        assert_eq!(session_ack_source(&datagram), None);
    }

    #[test]
    fn borrowed_forward_encoder_matches_owned_session_datagram_encode() {
        let src = NodeAddr::from_bytes([0x11; 16]);
        let dest = NodeAddr::from_bytes([0x22; 16]);
        let datagram = SessionDatagram::new(src, dest, vec![1, 2, 3, 4, 5])
            .with_ttl(12)
            .with_path_mtu(1400);
        let encoded = datagram.encode();
        let decoded = SessionDatagramRef::decode(&encoded[1..]).expect("decode datagram");

        let forwarded_ttl = 11;
        let forwarded_mtu = 1280;
        let borrowed = copy_forwarded_session_datagram(&encoded[1..], forwarded_ttl, forwarded_mtu);
        let owned = SessionDatagram {
            src_addr: decoded.src_addr,
            dest_addr: decoded.dest_addr,
            ttl: forwarded_ttl,
            path_mtu: forwarded_mtu,
            payload: decoded.payload.to_vec(),
        }
        .encode();

        assert_eq!(borrowed, owned);
    }

    #[test]
    fn owned_forward_rewrite_preserves_packet_allocation_and_payload() {
        let datagram = SessionDatagram::new(
            NodeAddr::from_bytes([0x33; 16]),
            NodeAddr::from_bytes([0x44; 16]),
            vec![9, 8, 7, 6, 5],
        )
        .with_ttl(20)
        .with_path_mtu(1450);
        let mut plaintext = PacketBuffer::new(datagram.encode());
        let allocation = plaintext.as_slice().as_ptr();

        assert!(rewrite_forwarded_session_datagram(&mut plaintext, 19, 1280));
        assert_eq!(plaintext.as_slice().as_ptr(), allocation);

        let decoded = SessionDatagramRef::decode(&plaintext.as_slice()[1..]).expect("decode");
        assert_eq!(decoded.ttl, 19);
        assert_eq!(decoded.path_mtu, 1280);
        assert_eq!(decoded.src_addr, datagram.src_addr);
        assert_eq!(decoded.dest_addr, datagram.dest_addr);
        assert_eq!(decoded.payload, datagram.payload);
    }

    #[test]
    fn route_failure_is_claimed_once_per_pair_and_flush() {
        let dest = NodeAddr::from_bytes([0x11; 16]);
        let next_hop = NodeAddr::from_bytes([0x22; 16]);
        let other_hop = NodeAddr::from_bytes([0x33; 16]);
        let mut failed_routes = std::collections::HashSet::new();

        assert!(claim_route_failure_once(
            &mut failed_routes,
            dest,
            next_hop,
            true
        ));
        assert!(!claim_route_failure_once(
            &mut failed_routes,
            dest,
            next_hop,
            true
        ));
        assert!(!claim_route_failure_once(
            &mut failed_routes,
            dest,
            next_hop,
            false
        ));
        assert!(claim_route_failure_once(
            &mut failed_routes,
            dest,
            other_hop,
            true
        ));

        let mut next_flush = std::collections::HashSet::new();
        assert!(claim_route_failure_once(
            &mut next_flush,
            dest,
            next_hop,
            true
        ));
    }

    #[test]
    fn forwarding_submission_window_pipelines_four_transport_batches() {
        let limit = forwarding_submission_limit(64);
        assert_eq!(limit, 256);
        assert!(!forward_run_reached_limit(255, limit));
        assert!(forward_run_reached_limit(256, limit));

        let minimum = forwarding_submission_limit(0);
        assert_eq!(minimum, 4);
        assert!(forward_run_reached_limit(4, minimum));
        assert_eq!(forwarding_submission_limit(usize::MAX), 256);
    }

    #[test]
    fn only_valid_nonlocal_datagrams_are_transit_candidates() {
        let node = Node::new(crate::Config::new()).expect("test node");
        let peer_identity_full = fips_identity::Identity::generate();
        let previous_hop = crate::PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());
        let source = *previous_hop.node_addr();

        let local = SessionDatagram::new(source, *node.node_addr(), vec![1, 2, 3]).encode();
        let local = AuthenticatedSessionDatagram::new(previous_hop, &local[1..], false);
        assert!(!node.session_datagram_is_transit_candidate(&local));

        let unknown_dest = NodeAddr::from_bytes([0x55; 16]);
        let no_route = SessionDatagram::new(source, unknown_dest, vec![4, 5, 6]).encode();
        let no_route = AuthenticatedSessionDatagram::new(previous_hop, &no_route[1..], false);
        assert!(node.session_datagram_is_transit_candidate(&no_route));

        let ttl_zero = SessionDatagram::new(source, unknown_dest, vec![7, 8, 9])
            .with_ttl(0)
            .encode();
        let ttl_zero = AuthenticatedSessionDatagram::new(previous_hop, &ttl_zero[1..], false);
        assert!(!node.session_datagram_is_transit_candidate(&ttl_zero));
    }

    #[tokio::test]
    async fn no_route_drop_action_is_deferred_until_after_planning() {
        let mut node = Node::new(crate::Config::new()).expect("test node");
        let peer_identity_full = fips_identity::Identity::generate();
        let previous_hop = crate::PeerIdentity::from_pubkey_full(peer_identity_full.pubkey_full());
        let source = *previous_hop.node_addr();
        let unknown_dest = NodeAddr::from_bytes([0x66; 16]);
        let encoded = SessionDatagram::new(source, unknown_dest, vec![1, 2, 3]).encode();
        let datagram = AuthenticatedSessionDatagram::new(previous_hop, &encoded[1..], false);

        let PreparedSessionDatagram::NoRoute {
            datagram,
            received_len,
            loop_failure,
        } = node.prepare_session_datagram(datagram).await
        else {
            panic!("unknown destination should produce deferred no-route action");
        };
        assert_eq!(node.stats().forwarding.received_packets, 1);
        assert_eq!(node.stats().forwarding.drop_no_route_packets, 0);

        node.finish_session_datagram_no_route(datagram, received_len, loop_failure)
            .await;
        assert_eq!(node.stats().forwarding.drop_no_route_packets, 1);
    }
}
