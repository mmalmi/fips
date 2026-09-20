//! An applied acceptance can outlive the neighbor and must not pin source selection.
use super::*;

#[path = "pending/gate.rs"]
mod gate;
pub(crate) use gate::{ResponseGate, interpose, interpose_promotion};
#[path = "pending/promotion.rs"]
mod promotion;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lost_acceptance_does_not_pin_a_mobile_source_or_release_its_funding() {
    tokio::time::timeout(
        Duration::from_secs(300),
        run(0, Scenario::InterruptedMobility, 114),
    )
    .await
    .expect("interrupted paid mobility scenario deadline");
}

fn journal(root: &Path, node: usize) -> serde_json::Value {
    serde_json::from_slice(
        &std::fs::read(root.join(format!("controller-{node}/controller.json"))).unwrap(),
    )
    .unwrap()
}

fn phase_summary(root: &Path, offer_id: &str) -> serde_json::Value {
    let saved = journal(root, 0);
    let outgoing = saved["outgoing"].as_object().unwrap();
    let interrupted = outgoing
        .values()
        .find(|record| record["offer"]["id"] == offer_id);
    // Explicit scalar selection prevents funding tokens or signed payment
    // bodies from entering a failing test's diagnostics.
    serde_json::json!({
        "requested": saved["requested"].as_object().unwrap().len(),
        "route_changes": saved["route_changes"].as_object().unwrap().len(),
        "funding_intents": saved["funding"].as_object().unwrap().len(),
        "active_accepted": outgoing.values().filter(|record| {
            record["accepted"] == true && record["retired"] == false
        }).count(),
        "interrupted_local_accepted": interrupted.map(|record| record["accepted"].clone()),
        "interrupted_local_retired": interrupted.map(|record| record["retired"].clone()),
        "watch_pinned_to_interrupted": saved["watched_routes"].as_object().unwrap().values()
            .any(|watch| watch["pending"]["id"] == offer_id),
    })
}

fn assert_captured_boundary(root: &Path, accepted: &gate::Accepted, first: &Purchase) {
    let buyer = journal(root, 0);
    let outgoing = buyer["outgoing"]
        .as_object()
        .unwrap()
        .values()
        .find(|record| record["offer"]["id"] == accepted.offer_id)
        .expect("source must journal the outgoing purchase before sending Accept");
    assert_eq!(outgoing["accepted"], false);
    assert_eq!(outgoing["retired"], false);
    let purchase: Purchase = serde_json::from_value(outgoing["purchase"].clone()).unwrap();
    assert_eq!(purchase, accepted.purchase);
    assert_ne!(purchase.channel.id, first.channel.id);
    assert!(
        buyer["watched_routes"]
            .as_object()
            .unwrap()
            .values()
            .any(|watch| { watch["pending"]["id"] == accepted.offer_id })
    );
    let provider = journal(root, 2);
    let incoming = provider["incoming"]
        .as_object()
        .unwrap()
        .values()
        .find(|record| record["offer"]["id"] == accepted.offer_id)
        .expect("real provider handler must persist its incoming purchase");
    assert_eq!(incoming["phase"], "Active");
    assert_eq!(incoming["channel"]["id"], accepted.purchase.channel.id);
    assert_eq!(incoming["contract"]["id"], accepted.purchase.contract.id);
}

fn interrupted_refunded(root: &Path, accepted: &gate::Accepted) -> bool {
    let saved = journal(root, 0);
    let settlement = &saved["buyer_settlements"][&accepted.purchase.channel.id];
    if settlement["refunded"] != true {
        return false;
    }
    assert!(
        settlement["channel"] == serde_json::to_value(&accepted.purchase.channel).unwrap(),
        "automatic recovery changed the interrupted channel terms"
    );
    assert_eq!(
        settlement["report"]["channel_id"],
        accepted.purchase.channel.id
    );
    true
}

async fn recovery_finances(
    driver: &Driver<'_>,
    accepted: &gate::Accepted,
    exact_funding: &serde_json::Value,
    remaining: u64,
) {
    let capital = driver.controllers[0].funding_budget().await.unwrap();
    let saved = journal(driver.root, 0);
    assert!(
        saved["funding"] == *exact_funding,
        "recovery changed funding identities or terms"
    );
    assert_eq!(
        capital.wallet_debited_sat, 128,
        "recovery cannot open another channel"
    );
    assert!(capital.wallet_refunded_sat <= 64);
    if capital.locked_sat == 64 {
        // Capital releases the entire closed channel, not just its unused
        // refund. Read the durable marker after sampling released capital.
        let closed = &saved["buyer_settlements"][&accepted.purchase.channel.id];
        assert_eq!(closed["refunded"], true);
        assert_eq!(
            closed["wallet_refund_sat"].as_u64(),
            Some(capital.wallet_refunded_sat)
        );
    } else {
        assert_eq!(capital.locked_sat, 128);
        assert_eq!(capital.wallet_refunded_sat, 0);
    }
    assert!(driver.services[0].buyer.remaining_budget_sat().unwrap() <= remaining);
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn exercise(
    network: &SimNetwork,
    nodes: &[Arc<FipsEndpoint>],
    peers: &[PeerIdentity],
    controllers: &[Arc<Controller>],
    services: &[ControllerServices],
    receiver: &mut FipsEndpointServiceReceiver,
    first: &Purchase,
    root: &Path,
    gate: &mut ResponseGate,
) {
    let evidence = Evidence::read(root, &controllers[0]).await;
    assert_eq!(evidence.funding.len(), 1);
    assert_eq!(evidence.budget.wallet_debited_sat, 64);
    let original = evidence.funding.clone();
    let mut driver = Driver {
        nodes,
        peers,
        controllers,
        services,
        receiver,
        root,
        evidence,
    };
    network.set_link_up("0", "2", true);
    driver
        .membership(2, true, "interrupted alternative joins")
        .await;
    network.set_link_up("0", "1", false);
    driver
        .membership(1, false, "original departs before held acceptance")
        .await;
    let accepted = gate.accepted().await;
    assert_eq!(accepted.purchase.provider, *peers[2].node_addr());
    assert_eq!(
        accepted.purchase.contract.destination,
        *peers[3].node_addr()
    );
    assert_captured_boundary(root, &accepted, first);
    driver.sample().await;
    assert_eq!(driver.evidence.funding.len(), 2);
    assert_eq!(driver.evidence.budget.wallet_debited_sat, 128);
    assert_eq!(driver.evidence.budget.locked_sat, 128);
    assert_eq!(driver.evidence.budget.pending_reserved_sat, 0);
    for (id, identity) in &original {
        assert_eq!(driver.evidence.funding.get(id), Some(identity));
    }
    let retained = driver.evidence.funding.clone();
    let exact_funding = journal(root, 0)["funding"].clone();
    eprintln!(
        "interrupted mobility: real provider-2 Accepted held; source unacknowledged, debit=128 locked=128"
    );

    network.set_link_up("0", "2", false);
    network.set_link_up("0", "1", true);
    driver
        .membership(1, true, "original returns with independent funded account")
        .await;
    driver
        .membership(2, false, "accepted provider disappears before reply")
        .await;
    let returned = tokio::time::timeout(Duration::from_secs(40), driver.selected(1, 140)).await;
    let returned = returned.unwrap_or_else(|_| {
        panic!(
            "post-reservation mobility stalled: provider 1 is authenticated, provider 2 is absent; the original source account must resume while the interrupted account remains recoverable. phases={} capital={:?} errors={:?}",
            phase_summary(root, &accepted.offer_id),
            driver.evidence.budget,
            errors(controllers),
        )
    });
    assert_eq!(returned.channel, first.channel);
    driver.paid_delivery(&returned, 1, 141).await;
    assert!(!driver.connected(0, 2).await);
    driver.sample().await;
    assert_eq!(driver.evidence.funding, retained);
    assert_eq!(driver.evidence.budget.locked_sat, 128);
    assert_eq!(driver.evidence.budget.wallet_debited_sat, 128);
    assert_eq!(driver.evidence.budget.wallet_refunded_sat, 0);
    assert!(
        journal(root, 0)["funding"] == exact_funding,
        "returning to the original provider changed retained financial terms"
    );
    let remaining_before_return = services[0].buyer.remaining_budget_sat().unwrap();

    network.set_link_up("0", "2", true);
    tokio::time::timeout(Duration::from_secs(50), async {
        loop {
            recovery_finances(&driver, &accepted, &exact_funding, remaining_before_return).await;
            if driver.connected(0, 2).await && driver.connected(2, 0).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("interrupted provider returns for financial recovery");
    let rejoined = Instant::now();
    let mut automatic_refund_observed = None;
    let released = gate.release().await;
    assert!(
        released.attempted > 0,
        "the successful response must really have been held"
    );
    assert_eq!(released.attempted, released.delivered + released.canceled);
    // Link eviction can already have canceled the old TCP/FIPS responder. Do
    // not claim its reply reached the caller merely because we attempted it.
    eprintln!("interrupted mobility: late response release {released:?}");
    let started = Instant::now();
    let mut delivered = false;
    while started.elapsed() < Duration::from_secs(12) {
        let active = controllers[0].purchases().await.unwrap();
        assert!(
            active
                .iter()
                .any(|purchase| purchase.channel == first.channel)
        );
        assert!(
            active
                .iter()
                .all(|purchase| purchase.provider != accepted.purchase.provider),
            "late acceptance restored the abandoned source choice"
        );
        nodes[0]
            .send_datagram(peers[3], 44_740, 44_740, vec![142; 200])
            .await
            .unwrap();
        let mut batch = Vec::new();
        if let Ok(Some(_)) = tokio::time::timeout(
            Duration::from_millis(200),
            driver.receiver.recv_batch_into(&mut batch, 32),
        )
        .await
        {
            delivered |= batch.iter().any(|message| {
                message.source_peer.node_addr() == peers[0].node_addr()
                    && message.data.as_slice() == [142; 200]
            });
        }
        let quality = nodes[0]
            .source_route_quality(peers[3], Duration::from_secs(2))
            .await
            .unwrap();
        if quality.next_hop.is_some() {
            assert_eq!(
                quality.next_hop,
                Some(first.provider),
                "late response rebound the native source route"
            );
        }
        recovery_finances(&driver, &accepted, &exact_funding, remaining_before_return).await;
        if interrupted_refunded(root, &accepted) {
            automatic_refund_observed.get_or_insert_with(|| rejoined.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(800)).await;
    }
    assert!(
        delivered,
        "fresh original-path data must still arrive after late-response release"
    );
    tokio::time::timeout_at(rejoined + Duration::from_secs(30), async {
        while automatic_refund_observed.is_none() {
            recovery_finances(&driver, &accepted, &exact_funding, remaining_before_return).await;
            if interrupted_refunded(root, &accepted) {
                automatic_refund_observed = Some(rejoined.elapsed());
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("automatic interrupted-channel refund must complete without a manual settle call");
    eprintln!(
        "interrupted mobility: automatic refund observed {:.2}s after authenticated rejoin",
        automatic_refund_observed.unwrap().as_secs_f64()
    );
    // Only after automatic completion, verify that an explicit replay returns
    // the same final report without another debit or refund.
    let report = tokio::time::timeout(
        Duration::from_secs(30),
        controllers[0].settle_channel(&accepted.purchase.channel.id),
    )
    .await
    .expect("recovered interrupted account settlement deadline")
    .expect(
        "provider-known funded account must eventually settle despite the lost first Accept reply",
    );
    assert_eq!(report.channel_id, accepted.purchase.channel.id);
    assert_eq!(
        report.paid_sat,
        services[0]
            .buyer
            .authorized_sat(&report.channel_id)
            .unwrap()
    );
    assert_eq!(report.fee_sat, 0);
    assert_eq!(report.paid_sat + report.refunded_sat, 64);
    let capital = controllers[0].funding_budget().await.unwrap();
    assert_eq!(capital.wallet_debited_sat, 128);
    assert_eq!(capital.wallet_refunded_sat, report.refunded_sat);
    assert_eq!(capital.locked_sat, 64);
    // The enclosing fixture reloads the source, delivers again, then settles
    // the original account and requires all 259 test sats to be conserved.
}
