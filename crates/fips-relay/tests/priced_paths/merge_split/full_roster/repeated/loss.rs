//! The same paid encounter with independent loss on its only inter-group link.
use super::*;

fn lossy_profile(seed: u64) -> EncounterProfile {
    EncounterProfile {
        seed,
        bridge_link: SimLink {
            latency_ms: 10,
            throughput_mbps: 1.0,
            loss_probability: 0.05,
            ..Default::default()
        },
        ..EncounterProfile::baseline(false)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lossy_crowded_paid_encounters_seed_137() {
    run(lossy_profile(137)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lossy_crowded_paid_encounters_seed_138() {
    run(lossy_profile(138)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lossy_brief_contacts_and_long_absence_reuse_original_paid_routes() {
    assert_eq!(Config::new().node.rate_limit.handshake_timeout_secs, 30);
    run(EncounterProfile {
        finite_contacts: true,
        post_split_absence: Duration::from_secs(31),
        ..lossy_profile(139)
    })
    .await;
}
