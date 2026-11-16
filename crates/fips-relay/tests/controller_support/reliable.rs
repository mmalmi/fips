//! One application byte prefix per endpoint crosses actual paid channel renewals.
use super::{traffic::Traffic, *};
use fips_relay::probe::stream::{self, StreamProbe, StreamReport};
use sha2::{Digest, Sha256};
use std::sync::Mutex;
use tokio::{sync::watch, task::JoinSet, time::MissedTickBehavior};

const BYTES: u64 = 18_000;
const DURATION: u64 = 60;
const ID: &str = "102030405060708090a0b0c0d0e0f000";

pub(super) async fn exercise(traffic: &mut Traffic<'_>) {
    let (stop, receive_stop) = watch::channel(false);
    let progress: Vec<_> = (0..2)
        .map(|_| Arc::new(Mutex::new(None::<StreamReport>)))
        .collect();
    let mut jobs = JoinSet::new();
    for (index, node, remote) in [(0, 0, 4), (1, 4, 0)] {
        let shape = StreamProbe {
            peer: traffic.peers[remote].npub(),
            stream_id: ID.into(),
            bytes: BYTES,
            bytes_per_second: 32 * 1024,
            duration_secs: DURATION,
            connect: node == 0,
        };
        let endpoint = traffic.nodes[node].clone();
        let observed = progress[index].clone();
        let stopping = receive_stop.clone();
        jobs.spawn(async move {
            (
                node,
                stream::run(endpoint, shape, &observed, stopping).await,
            )
        });
    }
    let mut observation = tokio::time::interval(Duration::from_secs(1));
    observation.set_missed_tick_behavior(MissedTickBehavior::Skip);
    let mut results = Vec::new();
    while !jobs.is_empty() {
        tokio::select! {
            finished = jobs.join_next() => results.push(finished.unwrap().unwrap()),
            _ = observation.tick() => {
                for controller in traffic.controllers {
                    assert!(controller.locked_capital_sat().await.unwrap() <= traffic.capacity * 2);
                }
                #[cfg(unix)]
                if let Some(rekey) = traffic.rekey.as_mut() {
                    rekey.observe(traffic.root, traffic.peers).await;
                }
            }
        }
    }
    drop(stop);
    // Retain both original outcomes. A failed endpoint never starts a new probe.
    let reports: Vec<_> = progress.iter().map(|p| p.lock().unwrap().clone()).collect();
    eprintln!(
        "controller reliable stream {}",
        serde_json::json!({
            "bytes_per_direction": BYTES, "deadline_secs": DURATION,
            "reports": reports, "errors": results.iter().filter_map(|(node, result)|
                result.as_ref().err().map(|e| (*node, e))).collect::<Vec<_>>()
        })
    );
    if results.iter().any(|(_, result)| result.is_err()) {
        super::delivery_evidence(
            traffic.root,
            traffic.peers,
            traffic.forwarding,
            traffic.ledgers,
            traffic.buyers,
        )
        .await;
        eprintln!(
            "controller reliable recovery {}",
            serde_json::json!({
                "errors": super::errors(traffic.controllers),
                "stages": super::recovery_stages(traffic.root),
            })
        );
    }
    let successful: Vec<_> = results
        .into_iter()
        .map(|(node, result)| result.unwrap_or_else(|e| panic!("reliable endpoint {node}: {e}")))
        .collect();
    assert_eq!(successful.len(), 2);
    let id = u128::from_str_radix(ID, 16).unwrap().to_be_bytes();
    let expected: Vec<_> = (0..BYTES)
        .map(|position| (position % 251) as u8 ^ id[(position % 16) as usize])
        .collect();
    let digest = format!("{:x}", Sha256::digest(expected));
    for report in successful {
        assert!(report.ready && report.connected && report.finished);
        assert!(report.completed_us.is_some() && report.stopped_reason.is_none());
        assert_eq!(report.accepted_bytes, BYTES);
        assert_eq!(report.received_bytes, BYTES);
        assert_eq!(report.acknowledged_bytes, BYTES);
        assert_eq!(report.received_sha256, digest);
    }
}
