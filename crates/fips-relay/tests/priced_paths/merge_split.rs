//! Two independently discovered, paying components meet, separate and meet again.
use super::*;
use bench::Bench;
use cashu_service::{receive_payment_token, send_payment_token};
use fips_relay::controller::FundingBudget;
use serde_json::Value;
use std::collections::BTreeMap;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    time::Instant,
};

#[path = "merge_split/brief.rs"]
mod brief;
#[path = "merge_split/observation.rs"]
mod observation;
use observation::Observer;

#[path = "merge_split/timing.rs"]
mod timing;

#[path = "merge_split/crowded.rs"]
mod crowded;
#[path = "merge_split/pending_funding.rs"]
mod pending_funding;
#[path = "merge_split/reliable.rs"]
mod reliable;
#[path = "merge_split/settlement_cleanup.rs"]
mod settlement_cleanup;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn independently_discovered_meshes_merge_split_and_reuse_paid_channels() {
    for (root, seed) in [(0, 116), (3, 117)] {
        tokio::time::timeout(Duration::from_secs(480), exercise(root, seed))
            .await
            .expect("paid mesh merge/split deadline");
    }
}

async fn tree(bench: &Bench, node: usize) -> Value {
    native_query(bench.root.path(), node, "show_tree").await
}

async fn native_query(root: &std::path::Path, node: usize, command: &str) -> Value {
    tokio::time::timeout(Duration::from_secs(3), async {
        let mut socket = tokio::net::UnixStream::connect(root.join(format!("native-{node}.sock")))
            .await
            .unwrap();
        socket
            .write_all(format!("{{\"command\":\"{command}\"}}\n").as_bytes())
            .await
            .unwrap();
        let mut reply = String::new();
        BufReader::new(socket).read_line(&mut reply).await.unwrap();
        let reply: Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["status"], "ok");
        reply["data"].clone()
    })
    .await
    .expect("native control observation deadline")
}

fn adjacent(a: usize, b: usize, merged: bool) -> bool {
    a.abs_diff(b) == 1 && (merged || !matches!((a, b), (2, 3) | (3, 2)))
}

async fn topology(bench: &Bench, merged: bool) -> bool {
    let mut trees = Vec::new();
    for (i, node) in bench.nodes.iter().enumerate() {
        let peers = node.peers().await.unwrap();
        assert!(
            peers.len() <= 2,
            "native peer admission exceeds the configured cap"
        );
        let wanted: Vec<_> = (0..6).filter(|&j| adjacent(i, j, merged)).collect();
        if peers.len() != wanted.len()
            || peers.iter().any(|p| {
                !p.connected
                    || p.transport_type.as_deref() != Some("sim")
                    || !wanted
                        .iter()
                        .any(|&j| p.node_addr == *bench.peers[j].node_addr())
            })
        {
            return false;
        }
        trees.push(tree(bench, i).await);
    }
    for (i, state) in trees.iter().enumerate() {
        let component = if merged {
            0..6
        } else if i < 3 {
            0..3
        } else {
            3..6
        };
        let root = component
            .clone()
            .map(|j| trees[j]["my_node_addr"].as_str().unwrap())
            .min()
            .unwrap();
        if state["root"] != root {
            return false;
        }
        let depth = state["depth"].as_u64().unwrap();
        if state["my_node_addr"] == root {
            if state["is_root"] != true || depth != 0 {
                return false;
            }
        } else {
            let parent = component
                .clone()
                .find(|&j| trees[j]["my_node_addr"] == state["parent"]);
            if state["is_root"] != false
                || !parent.is_some_and(|j| {
                    adjacent(i, j, merged) && trees[j]["depth"].as_u64().unwrap() + 1 == depth
                })
            {
                return false;
            }
        }
    }
    true
}

async fn converge(bench: &Bench, merged: bool, phase: &str) {
    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(100), async {
        while !topology(bench, merged).await {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "{phase}: membership/tree deadline; {:?}",
            errors(&bench.controllers)
        )
    });
    eprintln!(
        "mesh {phase}: exact peers and component roots after {:.2}s",
        started.elapsed().as_secs_f64()
    );
}

#[derive(Clone)]
struct Account {
    // Keep bearer proofs out of diagnostics and compare only durable identities.
    funding: BTreeMap<String, (String, String)>,
    budget: FundingBudget,
    remaining: u64,
}

async fn accounts(bench: &Bench) -> Vec<Account> {
    let mut result = Vec::new();
    for (i, controller) in bench.controllers.iter().enumerate() {
        let saved: Value = serde_json::from_slice(
            &std::fs::read(
                bench
                    .root
                    .path()
                    .join(format!("controller-{i}/controller.json")),
            )
            .unwrap(),
        )
        .unwrap();
        let intents = saved["funding"].as_object().unwrap();
        assert!(
            intents.len() <= 2,
            "only two paying neighbors fit each operator's capital cap"
        );
        assert!(
            intents.values().all(|record| record["funded"].is_object()),
            "stable checkpoint contains pending funding"
        );
        let funding = intents
            .iter()
            .filter_map(|(id, record)| {
                let funded = record["funded"].as_object()?;
                Some((
                    id.clone(),
                    (
                        funded["terms"]["id"].as_str().unwrap().to_owned(),
                        funded["wallet_operation_id"].as_str().unwrap().to_owned(),
                    ),
                ))
            })
            .collect();
        let budget = controller.funding_budget().await.unwrap();
        assert!(budget.wallet_debited_sat <= 128 && budget.locked_sat <= 128);
        assert!(budget.exposure_sat <= 128);
        assert_eq!(budget.pending_reserved_sat, 0);
        assert_eq!(
            budget.wallet_refunded_sat, 0,
            "separation cannot refund a channel"
        );
        result.push(Account {
            funding,
            budget,
            remaining: bench.buyers[i].remaining_budget_sat().unwrap(),
        });
    }
    result
}

fn retain(prior: &[Account], current: &[Account], exact: bool) {
    for (old, new) in prior.iter().zip(current) {
        for (id, identity) in &old.funding {
            assert!(
                new.funding.get(id) == Some(identity),
                "changed channel/funding identity"
            );
        }
        assert!(
            new.remaining <= old.remaining,
            "encounters cannot reset spending"
        );
        assert!(new.budget.wallet_debited_sat >= old.budget.wallet_debited_sat);
        if exact {
            assert!(
                new.funding == old.funding,
                "returning neighbors cannot fund again"
            );
            assert_eq!(
                new.budget, old.budget,
                "returning peers retain every capital bound"
            );
        }
    }
}

async fn watch(bench: &Bench, source: usize, destination: usize) {
    let RouteAccess::Paid(purchase) = bench.controllers[source]
        .watch_route(bench.peers[destination], 512)
        .await
        .unwrap_or_else(|e| panic!("source watch {source}->{destination}: {e}"))
    else {
        panic!("mesh forwarding needs the paid agreement");
    };
    assert_eq!(
        purchase.contract.price.msat,
        128 * (source.abs_diff(destination) as u64 - 1)
    );
}

async fn traffic(bench: &mut Bench, source: usize, destination: usize, tag: u8) {
    let started = Instant::now();
    let mut received = [false; 12];
    let mut attempts = [0; 12];
    let mut submissions = Vec::with_capacity(36);
    let mut next_attempt = started;
    let mut rounds = 0;
    let mut first_delivery_ms = None;
    let mut last_delivery_ms = None;
    let result = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            let retry_due = Instant::now() >= next_attempt;
            for (i, (found, attempt)) in received.iter().zip(&mut attempts).enumerate() {
                if retry_due && !found && *attempt < 3 {
                    let mut payload = vec![tag; 900];
                    payload[0] = i as u8;
                    let submitted_us = started.elapsed().as_micros();
                    bench.nodes[source]
                        .send_datagram(bench.peers[destination], 44_740, 44_740, payload)
                        .await
                        .unwrap();
                    *attempt += 1;
                    submissions.push([
                        i as u128,
                        *attempt as u128,
                        submitted_us,
                        started.elapsed().as_micros(),
                    ]);
                    tokio::time::sleep(Duration::from_millis(30)).await;
                }
            }
            if retry_due {
                // Preserve the finite retry cap, but sample after normal route
                // refresh has had time to run instead of spending every retry
                // in the first second after tree convergence.
                rounds += 1;
                next_attempt = started + Duration::from_secs(rounds * 7);
            }
            let mut batch = Vec::new();
            let received_batch = tokio::time::timeout(
                Duration::from_millis(100),
                bench.receivers[destination].recv_batch_into(&mut batch, 64),
            )
            .await;
            assert!(!matches!(received_batch, Ok(None)), "live receiver closed");
            if matches!(received_batch, Ok(Some(_))) {
                for message in batch {
                    let bytes = message.data.as_slice();
                    if message.source_peer.node_addr() == bench.peers[source].node_addr()
                        && bytes.len() == 900
                        && bytes[1..].iter().all(|&b| b == tag)
                        && let Some(found) = received.get_mut(bytes[0] as usize)
                        && !*found
                    {
                        let now = started.elapsed().as_millis();
                        first_delivery_ms.get_or_insert(now);
                        last_delivery_ms = Some(now);
                        *found = true;
                    }
                }
            }
            if received.iter().all(|&v| v) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    eprintln!(
        "mesh traffic submissions: {}",
        serde_json::json!({
            "source": source, "destination": destination, "tag": tag,
            "columns": ["packet", "attempt", "started_us", "completed_us"],
            "submissions": submissions,
        })
    );
    if result.is_err() {
        for (pair, usage) in hop_usage(bench).await {
            eprintln!(
                "mesh stalled hop {pair:?}: evidence={} submitted={}",
                usage.evidence, usage.submitted
            );
        }
        eprintln!(
            "mesh stalled source quality: {:?}",
            bench.nodes[source]
                .source_route_quality(bench.peers[destination], Duration::from_secs(15))
                .await
                .unwrap()
        );
        panic!(
            "fresh mesh traffic {source}->{destination} tag={tag}: delivered={received:?}; {:?}",
            errors(&bench.controllers)
        );
    }
    eprintln!(
        "mesh traffic {source}->{destination} tag={tag}: 12 fresh payloads, {} attempts, {rounds} rounds, first_ms={first_delivery_ms:?} last_ms={last_delivery_ms:?}, {:.2}s",
        attempts.iter().sum::<u32>(),
        started.elapsed().as_secs_f64()
    );
}

#[derive(Clone)]
struct HopUsage {
    channel: String,
    evidence: u64,
    submitted: u64,
}

async fn hop_usage(bench: &Bench) -> BTreeMap<(usize, usize), HopUsage> {
    let mut hops = BTreeMap::new();
    for (buyer, controller) in bench.controllers.iter().enumerate() {
        for purchase in controller.purchases().await.unwrap() {
            let seller = bench
                .peers
                .iter()
                .position(|p| *p.node_addr() == purchase.provider)
                .unwrap();
            let usage = HopUsage {
                evidence: bench.buyers[buyer]
                    .evidence_msat(&purchase.channel.id)
                    .unwrap(),
                submitted: bench.sellers[seller]
                    .channel_usage(&purchase.channel.id)
                    .unwrap()
                    .submitted_msat,
                channel: purchase.channel.id,
            };
            if let Some(previous) = hops.insert((buyer, seller), usage.clone()) {
                assert_eq!(
                    previous.channel, usage.channel,
                    "destinations share the same neighbor channel"
                );
            }
        }
    }
    hops
}

fn fresh_hops(
    before: &BTreeMap<(usize, usize), HopUsage>,
    after: &BTreeMap<(usize, usize), HopUsage>,
) {
    let expected = vec![
        (0, 1),
        (1, 2),
        (2, 1),
        (2, 3),
        (3, 2),
        (3, 4),
        (4, 3),
        (5, 4),
    ];
    assert_eq!(before.keys().copied().collect::<Vec<_>>(), expected);
    assert_eq!(after.keys().copied().collect::<Vec<_>>(), expected);
    for (pair, current) in after {
        let prior = &before[pair];
        assert_eq!(current.channel, prior.channel);
        assert!(
            current.evidence > prior.evidence && current.submitted > prior.submitted,
            "fresh traffic lacks buyer/provider evidence at hop {pair:?}"
        );
    }
}

async fn payments(bench: &Bench) -> BTreeMap<String, u64> {
    let targets: Vec<_> = hop_usage(bench)
        .await
        .into_iter()
        .map(|((_, seller), usage)| {
            let supported = usage.evidence.min(usage.submitted);
            assert!(supported > 0, "payment target needs real supported usage");
            (seller, usage.channel, supported.div_ceil(1000) * 1000)
        })
        .collect();
    tokio::time::timeout(Duration::from_secs(20), async {
        while !targets.iter().all(|(seller, channel, target)| {
            bench.sellers[*seller]
                .channel_usage(channel)
                .unwrap()
                .paid_msat
                >= *target
        }) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("automatic cumulative payments catch up on every paying hop");
    targets
        .into_iter()
        .map(|(seller, channel, _)| {
            let paid = bench.sellers[seller]
                .channel_usage(&channel)
                .unwrap()
                .paid_msat;
            (channel, paid)
        })
        .collect()
}

async fn no_cross_delivery(bench: &mut Bench, tag: u8) {
    for (source, destination) in [(0, 5), (5, 0)] {
        bench.nodes[source]
            .send_datagram(bench.peers[destination], 44_740, 44_740, vec![tag; 900])
            .await
            .unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        for destination in [0, 5] {
            let mut batch = Vec::new();
            if let Ok(Some(_)) = tokio::time::timeout(
                Duration::from_millis(100),
                bench.receivers[destination].recv_batch_into(&mut batch, 64),
            )
            .await
            {
                assert!(
                    batch
                        .iter()
                        .all(|message| message.data.as_slice() != [tag; 900]),
                    "partition leaked a fresh cross-component packet"
                );
            }
        }
    }
}

async fn assert_watches(bench: &Bench) {
    for (node, controller) in bench.controllers.iter().enumerate() {
        let expected: Vec<_> = match node {
            0 => vec![bench.peers[2].npub(), bench.peers[5].npub()],
            5 => vec![bench.peers[3].npub(), bench.peers[0].npub()],
            _ => Vec::new(),
        };
        let watches = controller.watched_routes().await.unwrap();
        assert_eq!(watches.len(), expected.len());
        assert!(watches.iter().all(|watch| {
            expected.contains(&watch.destination)
                && watch.billing == BillingBasis::ForwardingData
                && watch.max_rate_msat_per_kib == 512
                && !watch.paused
        }));
    }
}

async fn exercise(root: usize, seed: u64) {
    let mut bench = bench::start(root, Scenario::MergeSplit, seed).await;
    converge(&bench, false, "independent components").await;
    let initial = accounts(&bench).await;
    assert!(
        initial
            .iter()
            .all(|a| a.funding.is_empty() && a.budget.locked_sat == 0 && a.remaining == 128),
        "discovery cannot grant spending authority"
    );
    for (source, destination, tag) in [(0, 2, 10), (5, 3, 11)] {
        watch(&bench, source, destination).await;
        traffic(&mut bench, source, destination, tag).await;
    }
    let local = accounts(&bench).await;
    assert_eq!(local.iter().map(|a| a.funding.len()).sum::<usize>(), 2);
    let _ = payments(&bench).await;
    let mut anchor: Option<Vec<Account>> = None;
    let mut credited = BTreeMap::new();
    for cycle in 0..2u8 {
        bench.network.set_link(
            "2",
            "3",
            SimLink {
                latency_ms: 2,
                ..Default::default()
            },
        );
        converge(&bench, true, "merged components").await;
        if cycle == 0 {
            let joined = accounts(&bench).await;
            retain(&local, &joined, true);
            for (source, destination) in [(0, 5), (5, 0)] {
                watch(&bench, source, destination).await;
            }
        }
        let before_hops = hop_usage(&bench).await;
        for (source, destination, tag) in [(0, 5, 20 + cycle * 10), (5, 0, 21 + cycle * 10)] {
            traffic(&mut bench, source, destination, tag).await;
        }
        fresh_hops(&before_hops, &hop_usage(&bench).await);
        let paid = payments(&bench).await;
        assert_eq!(
            paid.len(),
            8,
            "every forwarding neighbor direction has its own channel"
        );
        assert!(paid.values().all(|&value| value > 0));
        for (channel, previous) in &credited {
            assert!(
                paid[channel] > *previous,
                "fresh traffic must pay every retained hop"
            );
        }
        credited = paid;
        let funded = accounts(&bench).await;
        if let Some(prior) = &anchor {
            retain(prior, &funded, true);
        } else {
            retain(&local, &funded, false);
        }
        assert_eq!(funded.iter().map(|a| a.funding.len()).sum::<usize>(), 8);
        anchor = Some(funded);
        if cycle == 0 {
            bench.network.set_link_up("2", "3", false);
            converge(&bench, false, "separated components").await;
            no_cross_delivery(&mut bench, 90).await;
            for (source, destination, tag) in [(0, 2, 40), (5, 3, 41)] {
                traffic(&mut bench, source, destination, tag).await;
            }
            retain(anchor.as_ref().unwrap(), &accounts(&bench).await, true);
        }
    }
    collect(bench, &anchor.unwrap(), &credited).await;
    eprintln!("mesh root={root} seed={seed}: eight original channels settled");
}

async fn collect(bench: Bench, final_accounts: &[Account], credited: &BTreeMap<String, u64>) {
    for controller in &bench.controllers {
        controller.pause_route_refresh().await.unwrap();
        controller.pause_renewals().await.unwrap();
    }
    let mut unsettled: BTreeMap<_, _> = hop_usage(&bench)
        .await
        .into_iter()
        .map(|(pair, usage)| (usage.channel, pair))
        .collect();
    assert_eq!(
        unsettled.keys().collect::<Vec<_>>(),
        credited.keys().collect::<Vec<_>>()
    );
    let mut expected_balances = vec![256u64; bench.wallets.len()];
    let settlement_deadline = Instant::now() + Duration::from_secs(120);
    for (i, controller) in bench.controllers.iter().enumerate() {
        let before: Vec<_> = bench
            .services
            .iter()
            .map(|service| service.acceptance.statistics().snapshot())
            .collect();
        let reports = match settlement_cleanup::resume(
            &bench,
            i,
            &final_accounts[i],
            settlement_deadline,
        )
        .await
        {
            Ok(reports) => reports,
            Err(error) => {
                let after: Vec<_> = bench
                    .services
                    .iter()
                    .map(|service| service.acceptance.statistics().snapshot())
                    .collect();
                eprintln!(
                    "mesh settlement node={i}: {error}; control_before={before:?} control_after={after:?}"
                );
                let saved: Value = serde_json::from_slice(
                    &std::fs::read(
                        bench
                            .root
                            .path()
                            .join(format!("controller-{i}/controller.json")),
                    )
                    .unwrap(),
                )
                .unwrap();
                for (id, settlement) in saved["buyer_settlements"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .take(2)
                {
                    eprintln!(
                        "mesh settlement node={i} channel={id} usage={} payment={} report={} released={} refunded={}",
                        !settlement["usage"].is_null(),
                        !settlement["payment"].is_null(),
                        !settlement["report"].is_null(),
                        settlement["released"],
                        settlement["refunded"]
                    );
                }
                for node in
                    (0..bench.nodes.len()).filter(|&node| node == i || adjacent(i, node, true))
                {
                    for command in ["show_peers", "show_sessions", "show_connections"] {
                        eprintln!(
                            "mesh settlement source={i} node={node} command={command}: {}",
                            native_query(bench.root.path(), node, command).await
                        );
                    }
                }
                panic!("mesh settlement node={i}: {error}");
            }
        };
        let expected: std::collections::BTreeSet<_> = final_accounts[i]
            .funding
            .values()
            .map(|(channel, _)| channel.as_str())
            .collect();
        assert_eq!(
            reports
                .iter()
                .map(|r| r.channel_id.as_str())
                .collect::<std::collections::BTreeSet<_>>(),
            expected
        );
        assert_eq!(reports.len(), expected.len());
        for report in reports {
            let (buyer, seller) = unsettled.remove(&report.channel_id).unwrap();
            assert_eq!(buyer, i);
            assert_eq!(report.value_after_stage1_sat, 64);
            assert_eq!(report.paid_sat + report.refunded_sat, 64);
            assert_eq!(report.fee_sat + report.receiver_fee_reserve_sat, 0);
            assert!(
                report.paid_sat * 1000 >= credited[&report.channel_id],
                "settlement must redeem at least the acknowledged payment"
            );
            expected_balances[buyer] -= report.paid_sat;
            expected_balances[seller] += report.paid_sat;
        }
        let budget = controller.funding_budget().await.unwrap();
        assert_eq!(budget.locked_sat, 0);
        assert_eq!(budget.pending_reserved_sat, 0);
        assert_eq!(
            budget.wallet_debited_sat,
            final_accounts[i].budget.wallet_debited_sat
        );
        assert_eq!(
            budget.exposure_sat + budget.wallet_refunded_sat,
            budget.wallet_debited_sat
        );
        assert!(bench.buyers[i].remaining_budget_sat().unwrap() <= final_accounts[i].remaining);
    }
    assert!(unsettled.is_empty());
    // Drain controller wallet owners before the collection helpers reopen them.
    for task in bench.tasks {
        task.stop().await;
    }
    let mut total = 0;
    for (i, wallet) in bench.wallets.iter().enumerate() {
        let balance = load_mint_balance(wallet, &bench.controller_policy.mint_url)
            .await
            .unwrap()
            .balance_sat;
        assert_eq!(
            balance, expected_balances[i],
            "wallet {i} must contain its initial funds minus purchases plus relay earnings"
        );
        total += balance;
        if balance > 0 {
            let token =
                send_payment_token(wallet, &bench.controller_policy.mint_url, balance as u64)
                    .await
                    .unwrap();
            receive_payment_token(&bench.root.path().join("collector"), &token.token)
                .await
                .unwrap();
        }
        assert_eq!(
            load_mint_balance(wallet, &bench.controller_policy.mint_url)
                .await
                .unwrap()
                .balance_sat,
            0
        );
    }
    assert_eq!(total, 1536, "all original test money is conserved");
    assert_eq!(
        load_mint_balance(
            &bench.root.path().join("collector"),
            &bench.controller_policy.mint_url,
        )
        .await
        .unwrap()
        .balance_sat,
        total
    );
    eprintln!("mesh: all {total} test sats collected");
    for server in bench.quote_servers {
        server.stop().await;
    }
    for server in bench.payment_servers {
        server.stop().await;
    }
    for node in bench.nodes {
        node.shutdown().await.unwrap();
    }
    fips_core::unregister_sim_network(&bench.network_name);
}
