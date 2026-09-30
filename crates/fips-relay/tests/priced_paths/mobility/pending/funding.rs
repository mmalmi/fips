//! Source selection must progress while another neighbor's committed funding waits.
use super::*;
use cashu_service::{simulation::MintProxy, spilman_client_store_path};
use serde_json::Value;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn committed_funding_does_not_pin_selection_or_increase_spending() {
    tokio::time::timeout(
        Duration::from_secs(300),
        run(0, Scenario::PendingFundingMobility, 123),
    )
    .await
    .expect("pending funding mobility and collection deadline");
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

struct Pending {
    id: String,
    intent: Value,
    opening: Value,
    sequence: Value,
    original: Value,
}

impl Pending {
    fn capture(root: &Path, provider: PeerIdentity, before: &Value) -> Self {
        let saved = journal(root, 0);
        let intents = saved["funding"].as_object().unwrap();
        assert_eq!(intents.len(), 2);
        let pending: Vec<_> = intents
            .iter()
            .filter(|(_, intent)| intent["funded"].is_null())
            .collect();
        assert_eq!(pending.len(), 1);
        let (id, intent) = pending[0];
        assert!(
            intent["provider"] == serde_json::to_value(provider.node_addr().as_bytes()).unwrap()
        );
        assert_eq!(intent["capacity_sat"], 64);
        assert_eq!(intent["max_wallet_debit_sat"], 64);
        assert_eq!(
            saved["next_funding"].as_u64().unwrap(),
            before["next_funding"].as_u64().unwrap() + 1
        );
        let wallet = read(&spilman_client_store_path(&root.join("wallet-0")));
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
            original: before["funding"].clone(),
        }
    }

    fn retained(&self, root: &Path) -> Option<String> {
        let saved = journal(root, 0);
        assert_eq!(saved["funding"].as_object().unwrap().len(), 2);
        assert!(
            saved["next_funding"] == self.sequence,
            "mobility allocated another funding identity"
        );
        for (id, original) in self.original.as_object().unwrap() {
            assert!(
                saved["funding"][id] == *original,
                "original funding changed"
            );
        }
        let mut intent = saved["funding"][&self.id].clone();
        let funded = intent["funded"].take();
        // Boolean comparisons keep tokens and signed payment bodies out of diagnostics.
        assert!(intent == self.intent, "original funding authority changed");
        if funded.is_null() {
            return None;
        }
        assert!(
            funded["wallet_operation_id"] == self.opening["wallet_send"]["operation_id"],
            "recovery changed the wallet operation"
        );
        assert_eq!(funded["opening"]["balance"], 0);
        Some(funded["terms"]["id"].as_str().unwrap().to_owned())
    }

    async fn unresolved(&self, driver: &mut Driver<'_>) -> bool {
        driver.sample().await;
        let budget = &driver.evidence.budget;
        assert_eq!(budget.wallet_debited_sat + budget.pending_reserved_sat, 128);
        assert_eq!(budget.locked_sat, 128);
        assert_eq!(budget.exposure_sat, 128);
        assert_eq!(budget.wallet_refunded_sat, 0);
        let wallet = read(&spilman_client_store_path(&driver.root.join("wallet-0")));
        self.retained(driver.root).is_none()
            && wallet["openings"][format!("r:{}", self.id)] == self.opening
            && budget.pending_reserved_sat == 64
    }
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
    proxy: &MintProxy,
) {
    let evidence = Evidence::read(root, &controllers[0]).await;
    assert_eq!(evidence.funding.len(), 1);
    assert_eq!(evidence.budget.wallet_debited_sat, 64);
    let before = journal(root, 0);
    let source_store = spilman_client_store_path(&root.join("wallet-0"));
    let old_openings = read(&source_store)["openings"].as_object().unwrap().clone();
    let (committed, release) = proxy.state.pause_matching_swap_reply(move |request| {
        read(&source_store)["openings"]
            .as_object()
            .into_iter()
            .flat_map(|openings| openings.iter())
            .filter(|(id, _)| !old_openings.contains_key(*id))
            .any(|(_, opening)| {
                opening["swap_request_json"].as_str().is_some_and(|saved| {
                    let original: cashu::nuts::SwapRequest = serde_json::from_str(saved).unwrap();
                    original.outputs() == request.outputs()
                })
            })
    });
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
        .membership(2, true, "alternative joins before funding")
        .await;
    network.set_link_up("0", "1", false);
    driver
        .membership(1, false, "original departs before funding")
        .await;
    tokio::time::timeout(Duration::from_secs(30), committed)
        .await
        .expect("replacement funding must commit at the real mint")
        .unwrap();
    let held = Instant::now();
    let pending = Pending::capture(root, peers[2], &before);
    assert!(pending.unresolved(&mut driver).await && !release.is_closed());
    eprintln!("pending route funding: mint committed; debit=64 pending=64 locked=128");

    network.set_link_up("0", "1", true);
    network.set_link_up("0", "2", false);
    driver
        .membership(1, true, "original returns during funding")
        .await;
    driver
        .membership(2, false, "funding provider departs")
        .await;
    let returned = driver.selected(1, 160).await;
    assert_eq!(returned.channel, first.channel);
    let held_before_payment = pending.unresolved(&mut driver).await && !release.is_closed();
    driver.paid_delivery(&returned, 1, 161).await;
    let held_after_payment = pending.unresolved(&mut driver).await && !release.is_closed();
    eprintln!(
        "pending route funding: fallback paid after {:.2}s; unresolved before={held_before_payment} after={held_after_payment}",
        held.elapsed().as_secs_f64()
    );
    assert!(
        held_before_payment && held_after_payment,
        "fallback and automatic payment must precede funding completion or timeout"
    );

    // Release before stopping workers; dropping this sender also releases the
    // mint handler if an earlier assertion fails.
    assert!(
        release.send(()).is_ok(),
        "original mint reply waiter disappeared"
    );
    let channel = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            driver.sample().await;
            if let Some(channel) = pending.retained(root) {
                break channel;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .expect("committed funding must finish with its original identity");
    assert!(!driver.connected(0, 2).await);
    assert!(
        controllers[0]
            .purchases()
            .await
            .unwrap()
            .iter()
            .all(|p| p.provider != *peers[2].node_addr()),
        "late funding must not activate the absent provider"
    );
    driver.paid_delivery(&returned, 1, 162).await;

    network.set_link_up("0", "2", true);
    driver
        .membership(2, true, "funded alternative returns")
        .await;
    network.set_link_up("0", "1", false);
    driver
        .membership(1, false, "original departs after funding recovery")
        .await;
    let alternative = driver.selected(2, 163).await;
    assert_eq!(alternative.channel.id, channel);
    driver.paid_delivery(&alternative, 2, 164).await;
    assert_eq!(pending.retained(root).as_deref(), Some(channel.as_str()));
    driver.sample().await;
    assert_eq!(driver.evidence.budget.wallet_debited_sat, 128);
    assert_eq!(driver.evidence.budget.locked_sat, 128);
    assert_eq!(driver.evidence.budget.pending_reserved_sat, 0);

    network.set_link_up("0", "1", true);
    driver.membership(1, true, "cheaper original returns").await;
    let cheaper = driver.selected(1, 165).await;
    assert_eq!(cheaper.channel, first.channel);
    driver.paid_delivery(&cheaper, 1, 166).await;
    assert_eq!(pending.retained(root).as_deref(), Some(channel.as_str()));
}
