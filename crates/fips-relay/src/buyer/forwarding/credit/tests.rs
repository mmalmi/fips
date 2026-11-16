use super::*;
use crate::ledger::BytePrice;
use fips_core::{Identity, PeerIdentity};
use fips_credit::{CreditForwarder, Route};
use peer_payments::{
    Account, AccountStore, Agreement, Book, Buyer, Controller, Keypair, PurchaseIntent,
    SpendingLimits,
};

fn peer(n: u8) -> PeerIdentity {
    PeerIdentity::from_pubkey(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey())
}
fn key(n: u8) -> Keypair {
    format!("{n:02x}").repeat(32).parse().unwrap()
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Fixture {
    root: tempfile::TempDir,
    seller: Arc<DurableRelay>,
    buyer: Arc<BuyerAuthorizer>,
    credit: Arc<CreditForwarder>,
    provider: AccountStore,
    payer: AccountStore,
}
impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let seller = Arc::new(
            DurableRelay::create(&root.path().join("cashu-seller"), Limits::default(), 1000)
                .unwrap(),
        );
        let buyer = Arc::new(
            BuyerAuthorizer::create(
                &root.path().join("cashu-buyer"),
                *peer(2).node_addr(),
                100,
                Limits::default(),
            )
            .unwrap(),
        );
        let credit = Arc::new(CreditForwarder::new(&peer(2)));
        let create = |name, own: u8, other: u8| {
            let identity = peer(own).pubkey().to_string();
            AccountStore::create(
                root.path().join(name),
                Account::new(
                    Book::new(
                        &identity,
                        peer_payments::Limits::default(),
                        [peer(other).pubkey().to_string()],
                    )
                    .unwrap(),
                    Buyer::new(&identity, SpendingLimits::default()).unwrap(),
                )
                .unwrap(),
            )
            .unwrap()
        };
        let provider = create("credit-provider", 2, 1);
        let payer = create("credit-payer", 1, 2);
        Self {
            root,
            seller,
            buyer,
            credit,
            provider,
            payer,
        }
    }

    fn forwarding(&self) -> PeerCreditForwarder {
        PaidForwarder::for_billing(
            self.seller.clone(),
            self.buyer.clone(),
            BillingBasis::ForwardingAttempt,
        )
        .with_peer_credit(self.credit.clone())
    }

    fn install_credit(&mut self, destination: u8, next_hop: u8, units: u64) {
        let route = Route {
            ingress_pubkey: peer(1).pubkey().serialize(),
            next_hop: *peer(next_hop).node_addr(),
            destination: *peer(destination).node_addr(),
        };
        let a = Agreement {
            id: format!("credit-{destination}"),
            payer: peer(1).pubkey().to_string(),
            provider: peer(2).pubkey().to_string(),
            service: "fips.forwarding.attempt_bytes".into(),
            resource: route.resource(),
            max_units: units,
            price_sat: 1,
            price_per_units: units,
            max_amount_sat: 1,
            created_at: now(),
            expires_at: now() + 60,
        };
        let offer = Controller::new(&mut self.provider, &key(2))
            .unwrap()
            .offer(a.clone(), now())
            .unwrap();
        let accepted = Controller::new(&mut self.payer, &key(1))
            .unwrap()
            .accept_offer(
                &offer,
                &PurchaseIntent {
                    provider: &a.provider,
                    service: &a.service,
                    resource: &a.resource,
                    units,
                    max_price_sat: 1,
                    price_per_units: units,
                    max_amount_sat: 1,
                    max_duration_secs: 60,
                },
                now(),
            )
            .unwrap();
        let window = Controller::new(&mut self.provider, &key(2))
            .unwrap()
            .open(&offer, &accepted, now())
            .unwrap()
            .allowance
            .unwrap();
        self.credit.install(route, window).unwrap();
    }

    fn channel(&self, id: &str, buyer: u8) -> ChannelTerms {
        ChannelTerms {
            id: id.into(),
            buyer: *peer(buyer).node_addr(),
            mint_url: "http://test.invalid".into(),
            expires_unix: now() + 60,
            capacity_sat: 1,
            grace_msat: 0,
            refund_after_unix: None,
        }
    }

    fn contract(&self, id: &str, channel: &str, destination: u8, next_hop: u8) -> Contract {
        Contract {
            bid_msat_per_kib: 0,
            id: id.into(),
            channel_id: channel.into(),
            destination: *peer(destination).node_addr(),
            next_hop: *peer(next_hop).node_addr(),
            expires_unix: now() + 50,
            price: BytePrice {
                msat: 1,
                per_bytes: 1,
            },
            max_units: 1000,
            billing: BillingBasis::ForwardingAttempt,
        }
    }
}

fn request(destination: u8, next_hop: u8, bytes: &[u8]) -> ForwardingRequest<'_> {
    ForwardingRequest {
        ingress: peer(1),
        source: *peer(9).node_addr(),
        destination: *peer(destination).node_addr(),
        next_hop: *peer(next_hop).node_addr(),
        session_payload: bytes,
    }
}

#[test]
fn credit_cannot_bypass_onward_authorization_or_double_complete_cashu() {
    let mut f = Fixture::new();
    f.install_credit(4, 3, 100);
    let forwarding = f.forwarding();
    let bytes = [7; 50];
    let r = request(4, 3, &bytes);
    assert_eq!(forwarding.decide(&r), ForwardingDecision::Reject);
    assert!(f.credit.can_admit(&request(4, 3, &[8; 100]))); // nothing consumed
    f.buyer
        .accept_channel(*peer(3).node_addr(), f.channel("outgoing", 2), 0)
        .unwrap();
    f.buyer
        .accept_quote(f.contract("onward", "outgoing", 4, 4))
        .unwrap();
    let first = forwarding.admit(&r).unwrap();
    assert_ne!(first, 0);
    assert_eq!(f.buyer.observed_units("onward"), Some(50));
    forwarding.complete(first, ForwardingOutcome::Submitted);
    forwarding.complete(first, ForwardingOutcome::Submitted);
    assert_eq!(
        f.buyer.state.lock().unwrap().quotes["onward"].submitted_units,
        50
    );
    let second = forwarding.admit(&r).unwrap();
    assert_ne!(first, second);
    forwarding.complete(second, ForwardingOutcome::Unconfirmed);
    forwarding.complete(second, ForwardingOutcome::Submitted);
    assert_eq!(
        f.buyer.state.lock().unwrap().quotes["onward"].submitted_units,
        50
    );
    assert_eq!(f.buyer.observed_units("onward"), Some(100));
    assert_eq!(forwarding.decide(&r), ForwardingDecision::Reject);
    assert!(f.root.path().exists());
}

#[test]
fn cashu_routes_keep_priority_and_inner_completion_tokens_do_not_collide() {
    let mut f = Fixture::new();
    f.install_credit(4, 4, 100);
    f.install_credit(5, 3, 100);
    f.seller
        .open_channel_verified(f.channel("incoming", 1), 50)
        .unwrap();
    f.seller
        .add_contract(f.contract("cashu", "incoming", 4, 4))
        .unwrap();
    f.buyer
        .accept_channel(*peer(3).node_addr(), f.channel("outgoing", 2), 0)
        .unwrap();
    f.buyer
        .accept_quote(f.contract("onward", "outgoing", 5, 5))
        .unwrap();
    let forwarding = f.forwarding();
    let cashu = forwarding.admit(&request(4, 4, &[7; 50])).unwrap();
    let credit = forwarding.admit(&request(5, 3, &[8; 50])).unwrap();
    assert_ne!(cashu, credit);
    assert!(f.credit.can_admit(&request(4, 4, &[9; 100])));
    forwarding.complete(credit, ForwardingOutcome::Submitted);
    forwarding.complete(cashu, ForwardingOutcome::Submitted);
    forwarding.complete(credit, ForwardingOutcome::Unconfirmed);
    assert_eq!(f.seller.usage("cashu").unwrap().submitted_units, 50);
    assert_eq!(
        f.buyer.state.lock().unwrap().quotes["onward"].submitted_units,
        50
    );
    // Exhausted paid balance does not fall through and consume a second method.
    assert_eq!(
        forwarding.decide(&request(4, 4, &[7; 1])),
        ForwardingDecision::Retry
    );
    assert!(f.credit.can_admit(&request(4, 4, &[9; 100])));
}

#[test]
fn disabling_credit_stops_service_while_existing_cashu_routes_continue() {
    let mut f = Fixture::new();
    f.install_credit(4, 4, 100);
    f.seller
        .open_channel_verified(f.channel("incoming", 1), 100)
        .unwrap();
    f.seller
        .add_contract(f.contract("cashu", "incoming", 5, 5))
        .unwrap();
    let forwarding = f.forwarding();
    assert_eq!(forwarding.admit(&request(4, 4, &[7; 50])), Some(0));
    Controller::new(&mut f.provider, &key(2))
        .unwrap()
        .set_enabled(false)
        .unwrap();
    assert_eq!(
        forwarding.decide(&request(4, 4, &[8; 50])),
        ForwardingDecision::Reject
    );
    let token = forwarding.admit(&request(5, 5, &[9; 50])).unwrap();
    forwarding.complete(token, ForwardingOutcome::Submitted);
    assert_eq!(f.seller.usage("cashu").unwrap().submitted_units, 50);
}

#[test]
fn saturated_data_slots_preserve_only_the_existing_bounded_bootstrap_tier() {
    let f = Fixture::new();
    let forwarding = PaidForwarder::for_billing(
        f.seller.clone(),
        f.buyer.clone(),
        BillingBasis::ForwardingData,
    )
    .with_peer_credit(f.credit.clone());
    {
        let mut pending = forwarding.pending.lock().unwrap();
        for token in 1..=MAX_PENDING as u64 {
            pending.tokens.insert(token, Completion::Onward(token));
        }
        pending.next = MAX_PENDING as u64;
    }
    let mut handshake =
        fips_core::protocol::SessionMsg3::new(vec![0; fips_core::noise::XK_HANDSHAKE_MSG3_SIZE])
            .encode();
    assert_eq!(
        forwarding.admit_classified(&request(4, 3, &handshake)),
        Some(ForwardingAdmission {
            token: 0,
            class: ForwardingClass::Control,
        })
    );
    handshake.push(0);
    assert_eq!(
        forwarding.decide(&request(4, 3, &handshake)),
        ForwardingDecision::Reject
    );
    assert_eq!(forwarding.pending.lock().unwrap().tokens.len(), MAX_PENDING);
}
