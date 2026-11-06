use super::*;
use crate::discovery::nostr::signal::validate_traversal_answer_for_offer;

fn valid_offer() -> TraversalOffer {
    TraversalOffer {
        message_type: "offer".into(),
        session_id: "session".into(),
        issued_at: 1_000_000,
        expires_at: 1_120_000,
        nonce: "offer-nonce".into(),
        sender_npub: crate::Identity::generate().npub(),
        recipient_npub: crate::Identity::generate().npub(),
        reflexive_address: None,
        local_addresses: Vec::new(),
        stun_server: None,
    }
}

fn answer(offer: &TraversalOffer) -> Option<TraversalAnswer> {
    unsupported_mesh_traversal_answer(
        &serde_json::to_vec(offer).unwrap(),
        1_000_001,
        120_000,
        &offer.sender_npub,
        &offer.recipient_npub,
    )
}

#[test]
fn rejection_satisfies_existing_initiator_validation_and_size_bound() {
    let mut offer = valid_offer();
    // Even maximally escaped allowed identifiers remain bounded on the wire.
    offer.session_id = "\"".repeat(128);
    offer.nonce = "\\".repeat(128);
    let answer = answer(&offer).unwrap();
    assert!(!answer.accepted);
    assert_eq!(answer.reason.as_deref(), Some("traversal-unsupported"));
    assert!(serde_json::to_vec(&answer).unwrap().len() <= 1024);
    validate_traversal_answer_for_offer(
        &offer,
        &answer,
        1_000_002,
        120_000,
        &offer.recipient_npub,
        &offer.sender_npub,
    )
    .unwrap();
}

#[test]
fn malformed_oversized_and_invalid_identifier_offers_are_silent() {
    let offer = valid_offer();
    for body in [b"{".to_vec(), vec![b' '; 4097]] {
        assert!(
            unsupported_mesh_traversal_answer(
                &body,
                1_000_001,
                120_000,
                &offer.sender_npub,
                &offer.recipient_npub
            )
            .is_none()
        );
    }
    for id in [
        String::new(),
        "a".repeat(129),
        "line\nbreak".into(),
        "é".into(),
    ] {
        let mut bad = offer.clone();
        bad.session_id = id.clone();
        assert!(answer(&bad).is_none());
        bad = offer.clone();
        bad.nonce = id;
        assert!(answer(&bad).is_none());
    }
    let mut padded = serde_json::to_vec(&offer).unwrap();
    padded.resize(4097, b' ');
    assert!(serde_json::from_slice::<TraversalOffer>(&padded).is_ok());
    assert!(
        unsupported_mesh_traversal_answer(
            &padded,
            1_000_001,
            120_000,
            &offer.sender_npub,
            &offer.recipient_npub
        )
        .is_none()
    );
}

#[test]
fn identity_type_and_freshness_checks_precede_rejection() {
    let offer = valid_offer();
    for change in 0..5 {
        let mut bad = offer.clone();
        match change {
            0 => bad.message_type = "answer".into(),
            1 => {
                bad.issued_at -= 300_000;
                bad.expires_at -= 300_000;
            }
            2 => {
                bad.issued_at += 120_000;
                bad.expires_at += 120_000;
            }
            3 => bad.expires_at = bad.issued_at,
            4 => bad.expires_at = bad.issued_at - 1,
            _ => unreachable!(),
        }
        assert!(answer(&bad).is_none());
    }
    let body = serde_json::to_vec(&offer).unwrap();
    for (sender, recipient) in [
        (&offer.recipient_npub, &offer.recipient_npub),
        (&offer.sender_npub, &offer.sender_npub),
    ] {
        assert!(
            unsupported_mesh_traversal_answer(&body, 1_000_001, 120_000, sender, recipient)
                .is_none()
        );
    }
    assert!(
        unsupported_mesh_traversal_answer(
            &body,
            u64::MAX,
            120_000,
            &offer.sender_npub,
            &offer.recipient_npub
        )
        .is_none()
    );
}
