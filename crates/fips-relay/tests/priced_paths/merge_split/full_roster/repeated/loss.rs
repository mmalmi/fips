//! The same paid encounter with independent loss on its only inter-group link.
use super::*;

async fn lossy(seed: u64) {
    run(EncounterProfile {
        seed,
        bridge_link: SimLink {
            latency_ms: 10,
            throughput_mbps: 1.0,
            loss_probability: 0.05,
            ..Default::default()
        },
        ..EncounterProfile::baseline(false)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lossy_crowded_paid_encounters_seed_137() {
    lossy(137).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lossy_crowded_paid_encounters_seed_138() {
    lossy(138).await;
}
