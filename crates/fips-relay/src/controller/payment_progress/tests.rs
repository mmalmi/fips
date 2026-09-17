use super::*;
use crate::ledger::{BytePrice, Limits};
use cashu_service::CashuSpilmanPaymentSigner;
use fips_core::node::{ForwardingOutcome, OriginatedSessionObserver, OriginatedSessionRequest};

struct FailedSigner;
impl CashuSpilmanPaymentSigner for FailedSigner {
    fn sign_cashu_spilman_payment(
        &self,
        _: &str,
        _: u64,
        _: bool,
    ) -> Result<CashuSpilmanPayment, String> {
        Err("signature reply lost".into())
    }
}

#[test]
fn progress_reads_fresh_evidence_and_durable_unsigned_reply_liability() {
    let root = tempfile::tempdir().unwrap();
    let local = NodeAddr::from_bytes([1; 16]);
    let provider = NodeAddr::from_bytes([2; 16]);
    let destination = NodeAddr::from_bytes([3; 16]);
    let buyer =
        BuyerAuthorizer::create(&root.path().join("buyer"), local, 10, Limits::default()).unwrap();
    let terms = ChannelTerms {
        id: "channel".into(),
        buyer: local,
        mint_url: "http://test.invalid".into(),
        capacity_sat: 10,
        grace_msat: 1_000,
        expires_unix: now().unwrap() + 600,
    };
    buyer.accept_channel(provider, terms.clone(), 0).unwrap();
    buyer
        .accept_quote(Contract {
            billing: Default::default(),
            id: "quote".into(),
            channel_id: terms.id.clone(),
            destination,
            next_hop: destination,
            expires_unix: terms.expires_unix,
            price: BytePrice {
                msat: 1,
                per_bytes: 1,
            },
            max_units: 100,
        })
        .unwrap();
    let registry = ProgressRegistry::default();
    assert_eq!(
        registry
            .sample(&buyer, &terms.id)
            .unwrap()
            .acknowledged_msat,
        None
    );
    let observer = registry.track(&terms.id).unwrap();
    observer.lock().unwrap().finished(Some(0));
    let token = buyer
        .observe(&OriginatedSessionRequest {
            source: local,
            destination,
            next_hop: provider,
            session_payload: b"packet",
        })
        .unwrap();
    buyer.complete(token, ForwardingOutcome::Submitted);
    assert!(
        buyer
            .sign_claim(&FailedSigner, provider, &terms.id, 6, now().unwrap())
            .is_err()
    );
    // No scheduler tick ran after the new evidence or durable authorization.
    assert_eq!(
        registry.sample(&buyer, &terms.id).unwrap(),
        PaymentProgress {
            evidence_msat: 6,
            authorized_sat: 1,
            acknowledged_msat: Some(0),
            in_flight: false,
        }
    );
    assert!(registry.sample(&buyer, "missing").is_err());
    drop(observer);
    assert_eq!(
        registry
            .sample(&buyer, &terms.id)
            .unwrap()
            .acknowledged_msat,
        None
    );
    let restarted = registry.track(&terms.id).unwrap();
    assert_eq!(
        registry
            .sample(&buyer, &terms.id)
            .unwrap()
            .acknowledged_msat,
        None
    );
    drop(restarted);
}

#[test]
fn progress_registry_is_bounded_and_reclaims_only_dropped_workers() {
    let registry = ProgressRegistry::default();
    let mut workers: Vec<_> = (0..MAX_CHANNELS)
        .map(|id| registry.track(&id.to_string()).unwrap())
        .collect();
    assert!(registry.track("excess").is_none());
    assert!(registry.track("0").is_none());
    workers.pop();
    let replacement = registry.track("replacement").unwrap();
    assert_eq!(registry.channels.lock().unwrap().len(), MAX_CHANNELS);
    drop((workers, replacement));
    let fresh = registry.track("fresh").unwrap();
    assert_eq!(registry.channels.lock().unwrap().len(), 1);
    assert_eq!(fresh.lock().unwrap().acknowledged_msat, None);
}
