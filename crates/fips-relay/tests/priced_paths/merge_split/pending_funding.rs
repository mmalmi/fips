//! A newly encountered neighbor's mint wait cannot stop an existing paid link.
use super::*;
use cashu_service::{simulation::MintProxy, spilman_client_store_path};
use std::path::Path;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pending_encounter_funding_preserves_healthy_payments_and_original_capital() {
    tokio::time::timeout(Duration::from_secs(480), exercise())
        .await
        .expect("pending encounter funding and collection deadline");
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn journal(bench: &Bench, node: usize) -> Value {
    read(
        &bench
            .root
            .path()
            .join(format!("controller-{node}/controller.json")),
    )
}

struct Pending {
    id: String,
    intent: Value,
    opening: Value,
    sequence: Value,
    swaps: usize,
    before: Vec<Value>,
}

impl Pending {
    fn capture(bench: &Bench, proxy: &MintProxy, before: Vec<Value>) -> Self {
        let saved = journal(bench, 2);
        let intents = saved["funding"].as_object().unwrap();
        assert_eq!(intents.len(), 2);
        let pending: Vec<_> = intents
            .iter()
            .filter(|(_, intent)| intent["funded"].is_null())
            .collect();
        assert_eq!(pending.len(), 1);
        let (id, intent) = pending[0];
        assert!(intent["provider"] == serde_json::to_value(bench.peers[3].node_addr()).unwrap());
        assert_eq!(intent["capacity_sat"], 64);
        assert_eq!(intent["max_wallet_debit_sat"], 64);
        assert_eq!(
            saved["next_funding"].as_u64().unwrap(),
            before[2]["next_funding"].as_u64().unwrap() + 1
        );
        let wallet = read(&spilman_client_store_path(&bench.wallets[2]));
        let opening = wallet["openings"][format!("r:{id}")].clone();
        assert!(opening["wallet_request"].is_object());
        assert!(
            opening["wallet_send"]["operation_id"]
                .as_str()
                .is_some_and(|id| !id.is_empty())
        );
        assert!(opening["swap_request_json"].is_string());
        Self {
            id: id.clone(),
            intent: intent.clone(),
            opening,
            sequence: saved["next_funding"].clone(),
            swaps: proxy.state.swaps.load(Ordering::SeqCst),
            before,
        }
    }

    async fn retained(&self, bench: &Bench, proxy: &MintProxy, buying_finished: bool) {
        assert!(
            !buying_finished,
            "the original funding caller must still be waiting"
        );
        let saved = journal(bench, 2);
        assert!(saved["funding"][&self.id] == self.intent);
        assert!(saved["next_funding"] == self.sequence);
        assert_eq!(saved["funding"].as_object().unwrap().len(), 2);
        assert!(
            saved["outgoing"] == self.before[2]["outgoing"],
            "pending mint funding must not install another route"
        );
        for (i, prior) in self.before.iter().enumerate() {
            let current = journal(bench, i);
            for (id, original) in prior["funding"].as_object().unwrap() {
                assert!(
                    current["funding"][id] == *original,
                    "changed existing funding"
                );
            }
            if i != 2 {
                assert!(current["funding"] == prior["funding"]);
                assert!(current["next_funding"] == prior["next_funding"]);
            }
        }
        let wallet = read(&spilman_client_store_path(&bench.wallets[2]));
        assert!(wallet["openings"][format!("r:{}", self.id)] == self.opening);
        assert_eq!(proxy.state.swaps.load(Ordering::SeqCst), self.swaps);
        assert_eq!(
            bench.controllers[2].funding_budget().await.unwrap(),
            FundingBudget {
                pending_reserved_sat: 64,
                wallet_debited_sat: 64,
                wallet_refunded_sat: 0,
                locked_sat: 128,
                exposure_sat: 128,
            }
        );
        assert_watches(bench).await;
    }

    fn resolved(&self, bench: &Bench) -> String {
        let saved = journal(bench, 2);
        assert_eq!(saved["funding"].as_object().unwrap().len(), 2);
        assert!(saved["next_funding"] == self.sequence);
        let mut restored = saved["funding"][&self.id].clone();
        let funded = restored["funded"].take();
        assert!(
            restored == self.intent,
            "funding authority changed on rejoin"
        );
        assert!(
            funded["wallet_operation_id"] == self.opening["wallet_send"]["operation_id"],
            "recovery must finish the original wallet operation"
        );
        assert_eq!(funded["opening"]["balance"], 0);
        funded["terms"]["id"].as_str().unwrap().to_owned()
    }
}

async fn assert_watches(bench: &Bench) {
    for (i, controller) in bench.controllers.iter().enumerate() {
        let watches = controller.watched_routes().await.unwrap();
        let expected: Vec<_> = match i {
            2 => vec![bench.peers[0].npub(), bench.peers[5].npub()],
            5 => vec![bench.peers[3].npub()],
            _ => Vec::new(),
        };
        assert_eq!(watches.len(), expected.len());
        assert!(watches.iter().all(|watch| {
            !watch.paused
                && watch.max_rate_msat_per_kib == 512
                && expected.contains(&watch.destination)
        }));
    }
}

async fn healthy_progress(bench: &mut Bench, channel: &str) -> bool {
    let before = hop_usage(bench).await.remove(&(2, 1)).unwrap();
    assert_eq!(before.channel, channel);
    let paid_before = bench.sellers[1].channel_usage(channel).unwrap().paid_msat;
    // Three finite batches fit the ordinary grace window even if signing stalls.
    // Actual credited payment, not delivery within that grace, is the acceptance.
    for tag in 40..43 {
        traffic(bench, 2, 0, tag).await;
    }
    let after = hop_usage(bench).await.remove(&(2, 1)).unwrap();
    assert_eq!(after.channel, before.channel);
    assert!(after.evidence > before.evidence && after.submitted > before.submitted);
    let target = after.evidence.min(after.submitted).div_ceil(1_000) * 1_000;
    assert!(
        target > paid_before,
        "fresh traffic must require a new signed payment"
    );
    let started = Instant::now();
    let progressed = tokio::time::timeout(Duration::from_secs(5), async {
        while bench.sellers[1].channel_usage(channel).unwrap().paid_msat < target {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .is_ok();
    eprintln!(
        "pending encounter: 36 fresh payloads; healthy credit {paid_before} -> {}, target {target}, observed {:.3}s, progressed={progressed}",
        bench.sellers[1].channel_usage(channel).unwrap().paid_msat,
        started.elapsed().as_secs_f64()
    );
    progressed
}

async fn exercise() {
    let (mut bench, proxy) = bench::start_with_mint_proxy(0, 121).await;
    converge(
        &bench,
        false,
        "independent components before pending funding",
    )
    .await;
    for (source, destination, tag) in [(2, 0, 20), (5, 3, 21)] {
        watch(&bench, source, destination).await;
        traffic(&mut bench, source, destination, tag).await;
    }
    payments(&bench).await;
    let baseline = accounts(&bench).await;
    let healthy_channel = hop_usage(&bench).await[&(2, 1)].channel.clone();
    let before: Vec<_> = (0..6).map(|node| journal(&bench, node)).collect();
    bench.network.set_link(
        "2",
        "3",
        SimLink {
            latency_ms: 2,
            ..Default::default()
        },
    );
    converge(&bench, true, "encounter before pending funding").await;

    let source_store = spilman_client_store_path(&bench.wallets[2]);
    let (committed, release) = proxy.state.pause_matching_swap_reply(move |request| {
        let saved = read(&source_store);
        saved["openings"]
            .as_object()
            .into_iter()
            .flat_map(|o| o.values())
            .any(|opening| {
                let original: cashu::nuts::SwapRequest =
                    serde_json::from_str(opening["swap_request_json"].as_str().unwrap()).unwrap();
                original.outputs() == request.outputs()
            })
    });
    let controller = bench.controllers[2].clone();
    let destination = bench.peers[5];
    let buying = tokio::spawn(async move { controller.watch_route(destination, 512).await });
    tokio::time::timeout(Duration::from_secs(30), committed)
        .await
        .expect("the original persisted opening must commit at the real mint")
        .unwrap();
    let pending = Pending::capture(&bench, &proxy, before);
    pending.retained(&bench, &proxy, buying.is_finished()).await;
    eprintln!("pending encounter: mint committed; one pending operation, reserved=64, locked=128");

    bench.network.set_link_up("2", "3", false);
    converge(
        &bench,
        false,
        "separation with one committed funding reply held",
    )
    .await;
    pending.retained(&bench, &proxy, buying.is_finished()).await;
    let progressed = healthy_progress(&mut bench, &healthy_channel).await;
    pending.retained(&bench, &proxy, buying.is_finished()).await;
    bench.network.set_link_up("2", "3", true);
    converge(
        &bench,
        true,
        "discovery rejoin with the same pending operation",
    )
    .await;
    pending.retained(&bench, &proxy, buying.is_finished()).await;

    // Release before awaiting either the original caller or task shutdown. The
    // proxy also releases on sender drop, so a failing assertion cannot keep
    // a blocking wallet operation behind an indefinitely held response.
    release
        .send(())
        .expect("original mint response waiter remains live");
    let result = tokio::time::timeout(Duration::from_secs(45), buying)
        .await
        .expect("original funding caller must finish after release")
        .unwrap();
    eprintln!(
        "pending encounter: original Watch returned success={}",
        result.is_ok()
    );
    // A withdrawn offer may return an error; the one retained Watch must drive
    // recovery without another application purchase or new funding identity.
    tokio::time::timeout(Duration::from_secs(60), async {
        while !bench.controllers[2]
            .purchases()
            .await
            .unwrap()
            .iter()
            .any(|p| {
                p.provider == *bench.peers[3].node_addr()
                    && p.contract.destination == *bench.peers[5].node_addr()
            })
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("the original Watch must recover through discovered neighbors");
    let restored_channel = pending.resolved(&bench);
    assert_eq!(hop_usage(&bench).await[&(2, 3)].channel, restored_channel);
    assert_eq!(hop_usage(&bench).await[&(2, 1)].channel, healthy_channel);
    assert_watches(&bench).await;
    for (source, destination, tag) in [(2, 0, 50), (2, 5, 51), (5, 3, 52)] {
        traffic(&mut bench, source, destination, tag).await;
    }
    let credited = payments(&bench).await;
    let final_accounts = accounts(&bench).await;
    retain(&baseline, &final_accounts, false);
    assert_eq!(
        final_accounts
            .iter()
            .map(|a| a.funding.len())
            .collect::<Vec<_>>(),
        vec![0, 0, 2, 1, 0, 1],
        "only the original healthy and explicitly authorized onward channels exist"
    );
    assert_eq!(final_accounts[2].budget.wallet_debited_sat, 128);
    assert_eq!(final_accounts[2].budget.locked_sat, 128);
    assert_eq!(final_accounts[2].funding[&pending.id].0, restored_channel);
    tokio::time::timeout(
        Duration::from_secs(90),
        collect(bench, &final_accounts, &credited),
    )
    .await
    .expect("four original channels settle and all 1536 test sats collect");
    assert!(
        progressed,
        "pending funding blocked fresh automatic payments on the same router's healthy channel"
    );
}
