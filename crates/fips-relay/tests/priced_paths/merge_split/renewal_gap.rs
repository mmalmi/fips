//! Original source datagrams offered during a short automatic renewal gap.
use super::*;
use cashu_service::spilman_client_store_path;
use pending_funding::{journal, read};

const COHORT: usize = 8;
const TAG: u8 = 211;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sealed_renewal_preserves_each_original_source_datagram_once() {
    tokio::time::timeout(Duration::from_secs(480), exercise())
        .await
        .expect("original renewal cohort and settlement deadline");
}

async fn exercise() {
    let (mut bench, proxy, previous, unaffected) = slow_renewal::start().await;
    let original = journal(&bench, 2);
    let saved = read(&spilman_client_store_path(&bench.wallets[2]));
    let funding: Vec<cashu::nuts::Proof> = serde_json::from_str(
        saved["funding"][&previous]["funding_proofs_json"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let originals: std::collections::BTreeSet<_> = funding
        .iter()
        .map(|proof| proof.y().unwrap().to_string())
        .collect();
    assert!(!originals.is_empty());
    let (mut committed, release) = proxy.state.pause_matching_swap_reply(move |swap| {
        swap.inputs().len() == originals.len()
            && swap
                .inputs()
                .iter()
                .all(|proof| proof.y().is_ok_and(|y| originals.contains(&y.to_string())))
    });
    tokio::time::timeout(Duration::from_secs(120), async {
        for tag in 30..50 {
            tokio::select! {
                signal = &mut committed => {
                    signal.expect("predecessor settlement reached the held mint reply");
                    return;
                }
                _ = traffic(&mut bench, 2, 0, tag) => {}
            }
        }
        committed.await.unwrap();
    })
    .await
    .expect("real traffic automatically renews the original paid path");

    let held = journal(&bench, 2);
    assert_eq!(held["renewals"][&previous]["completed"], false);
    assert!(held["buyer_settlements"][&previous]["usage"].is_object());
    assert!(held["buyer_settlements"][&previous]["payment"].is_object());
    assert!(held["buyer_settlements"][&previous]["report"].is_null());
    assert!(held["funding"] == original["funding"]);
    let sealed = bench.sellers[1].channel_usage(&previous).unwrap();
    let evidence = bench.buyers[2].evidence_msat(&previous).unwrap();
    let signed = bench.buyers[2].authorized_sat(&previous).unwrap();
    let remaining = bench.buyers[2].remaining_budget_sat().unwrap();
    let before = bench.controllers[2].funding_budget().await.unwrap();
    assert_eq!(before.pending_reserved_sat, 0);
    assert_eq!(before.locked_sat, 128);
    assert_eq!(before.wallet_debited_sat, 128);
    assert_eq!(before.wallet_refunded_sat, 0);
    assert!(before.exposure_sat <= bench.controller_policy.max_wallet_spend_sat);

    // These payloads have never been submitted to a carrier or charged to the
    // sealed channel. Each is offered once; setup traffic uses different tags.
    let started = Instant::now();
    for sequence in 0..COHORT {
        let mut payload = vec![TAG; 900];
        payload[0] = sequence as u8;
        bench.nodes[2]
            .send_datagram(bench.peers[0], 44_740, 44_740, payload)
            .await
            .unwrap();
    }
    let mut received = [0usize; COHORT];
    let mut premature = false;
    let mut batch = Vec::new();
    let hold_until = started + Duration::from_millis(100);
    while Instant::now() < hold_until {
        if let Ok(Some(_)) = tokio::time::timeout_at(
            hold_until,
            bench.receivers[0].recv_batch_into(&mut batch, 64),
        )
        .await
        {
            for message in batch.drain(..) {
                if let Some(sequence) =
                    sequence(message.data.as_slice(), message.source_peer, bench.peers[2])
                {
                    received[sequence] += 1;
                    premature = true;
                }
            }
        }
    }
    assert!(!release.is_closed(), "release precedes the mint timeout");
    assert!(started.elapsed() < Duration::from_secs(1), "short held gap");
    release.send(()).unwrap();

    // Drain the original cohort even when delivery fails, and keep duplicate
    // counts through the full interval instead of stopping at the first copy.
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if let Ok(Some(_)) =
            tokio::time::timeout_at(deadline, bench.receivers[0].recv_batch_into(&mut batch, 64))
                .await
        {
            for message in batch.drain(..) {
                if let Some(sequence) =
                    sequence(message.data.as_slice(), message.source_peer, bench.peers[2])
                {
                    received[sequence] += 1;
                    premature |= !bench.controllers[2]
                        .purchases()
                        .await
                        .unwrap()
                        .iter()
                        .any(|p| {
                            p.contract.destination == *bench.peers[0].node_addr()
                                && p.channel.id != previous
                        });
                }
            }
        }
    }
    eprintln!(
        "renewal original cohort: offered={COHORT}, copies={received:?}, before_acceptance={premature}, elapsed={:.3}s",
        started.elapsed().as_secs_f64()
    );

    tokio::time::timeout(Duration::from_secs(30), async {
        while journal(&bench, 2)["renewals"][&previous]["completed"] != true {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("released renewal completes before financial collection");
    let active = hop_usage(&bench).await;
    assert_ne!(active[&(2, 1)].channel, previous);
    assert_eq!(active[&(2, 3)].channel, unaffected);
    assert_eq!(bench.sellers[1].channel_usage(&previous).unwrap(), sealed);
    assert_eq!(bench.buyers[2].evidence_msat(&previous), Some(evidence));
    assert_eq!(bench.buyers[2].authorized_sat(&previous), Some(signed));
    let restored = journal(&bench, 2);
    assert!(restored["policy"] == original["policy"]);
    assert_eq!(restored["funding"].as_object().unwrap().len(), 3);
    for (id, intent) in original["funding"].as_object().unwrap() {
        assert!(restored["funding"][id] == *intent);
    }
    assert_eq!(
        restored["next_funding"].as_u64().unwrap(),
        original["next_funding"].as_u64().unwrap() + 1
    );
    let after = bench.controllers[2].funding_budget().await.unwrap();
    assert_eq!(after.pending_reserved_sat, 0);
    assert_eq!(after.wallet_debited_sat, before.wallet_debited_sat + 64);
    assert!(after.locked_sat <= bench.controller_policy.max_locked_sat);
    assert!(after.exposure_sat <= bench.controller_policy.max_wallet_spend_sat);
    let buyer = read(&bench.root.path().join("buyer-2/buyer.json"));
    assert_eq!(buyer["total_budget_sat"], 128);
    assert!(bench.buyers[2].remaining_budget_sat().unwrap() <= remaining);

    // The fresh tag proves successor payments and permits exact collection on
    // a red run too. It never replaces a missing original cohort packet.
    traffic(&mut bench, 2, 0, 220).await;
    payments(&bench).await;
    slow_renewal::collect(bench).await;
    assert!(!premature, "originals arrived before successor acceptance");
    assert_eq!(
        received, [1; COHORT],
        "each original must arrive exactly once"
    );
}

fn sequence(payload: &[u8], source: PeerIdentity, expected: PeerIdentity) -> Option<usize> {
    (source == expected
        && payload.len() == 900
        && payload[1..].iter().all(|&byte| byte == TAG)
        && usize::from(payload[0]) < COHORT)
        .then(|| usize::from(payload[0]))
}
