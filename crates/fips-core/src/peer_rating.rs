use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRatingHealth {
    pub score: i64,
    pub sample_count: u64,
    pub reason: String,
}

pub fn compute_peer_rating(peer: &Value) -> Option<PeerRatingHealth> {
    let mut score = 50_i64;
    let mut signals = 0_usize;
    let mut misbehavior_signals = 0_usize;
    let mut reasons = Vec::new();

    if let Some(mmp) = peer.get("mmp").and_then(Value::as_object) {
        if let Some(loss) = json_f64_prefer(mmp, &["smoothed_loss", "loss_rate"]) {
            let loss = loss.clamp(0.0, 1.0);
            signals += 1;
            if loss <= 0.005 {
                score += 10;
            } else if loss <= 0.02 {
                score += 4;
            } else {
                score -= ((loss * 100.0).round() as i64).clamp(4, 45);
            }
            reasons.push(format!("loss={loss:.3}"));
        }

        if let Some(delivery) = average_delivery_ratio(mmp) {
            let delivery = delivery.clamp(0.0, 1.0);
            signals += 1;
            if delivery >= 0.995 {
                score += 15;
            } else if delivery >= 0.98 {
                score += 8;
            } else if delivery < 0.80 {
                score -= 35;
            } else if delivery < 0.90 {
                score -= 25;
            } else if delivery < 0.97 {
                score -= 12;
            }
            reasons.push(format!("delivery={delivery:.3}"));
        }

        if let Some(etx) = json_f64_prefer(mmp, &["smoothed_etx", "etx"]) {
            let etx = etx.max(1.0);
            signals += 1;
            if etx <= 1.05 {
                score += 12;
            } else if etx <= 1.20 {
                score += 6;
            } else if etx >= 3.0 {
                score -= 35;
            } else if etx >= 2.0 {
                score -= 25;
            } else if etx >= 1.5 {
                score -= 15;
            }
            reasons.push(format!("etx={etx:.2}"));
        }

        if let Some(srtt_ms) = json_f64_prefer(mmp, &["srtt_ms"]) {
            signals += 1;
            if srtt_ms <= 50.0 {
                score += 8;
            } else if srtt_ms <= 150.0 {
                score += 3;
            } else if srtt_ms >= 1_000.0 {
                score -= 25;
            } else if srtt_ms >= 300.0 {
                score -= 15;
            }
            reasons.push(format!("srtt_ms={srtt_ms:.0}"));
        }

        if let Some(goodput_bps) = json_f64_prefer(mmp, &["goodput_bps"]) {
            signals += 1;
            if goodput_bps >= 5_000_000.0 {
                score += 8;
            } else if goodput_bps >= 1_000_000.0 {
                score += 4;
            }
            reasons.push(format!("goodput_bps={goodput_bps:.0}"));
        }
    }

    let decrypt_failures = json_u64_field(peer, "consecutive_decrypt_failures").unwrap_or(0);
    if decrypt_failures > 0 {
        signals += 1;
        misbehavior_signals += 1;
        score -= i64::try_from(decrypt_failures.saturating_mul(20).min(70)).unwrap_or(70);
        reasons.push(format!("decrypt_failures={decrypt_failures}"));
    }

    let replay_suppressed = json_u64_field(peer, "replay_suppressed").unwrap_or(0);
    if replay_suppressed > 0 {
        signals += 1;
        misbehavior_signals += 1;
        score -= i64::try_from(replay_suppressed.saturating_mul(5).min(30)).unwrap_or(30);
        reasons.push(format!("replay_suppressed={replay_suppressed}"));
    }

    if signals == 0 {
        return None;
    }

    let score = if misbehavior_signals == 0 {
        score.clamp(50, 100)
    } else {
        score.clamp(0, 100)
    };
    let sample_count = peer_sample_count(peer).max(signals as u64);
    Some(PeerRatingHealth {
        score,
        sample_count,
        reason: reasons.join(" "),
    })
}

fn average_delivery_ratio(map: &serde_json::Map<String, Value>) -> Option<f64> {
    let forward = json_f64_prefer(map, &["delivery_ratio_forward"]);
    let reverse = json_f64_prefer(map, &["delivery_ratio_reverse"]);
    match (forward, reverse) {
        (Some(forward), Some(reverse)) => Some((forward + reverse) / 2.0),
        (Some(forward), None) => Some(forward),
        (None, Some(reverse)) => Some(reverse),
        (None, None) => None,
    }
}

fn peer_sample_count(peer: &Value) -> u64 {
    ["packets_sent", "packets_recv"]
        .into_iter()
        .filter_map(|key| nested_u64_field(peer, "stats", key))
        .fold(0_u64, u64::saturating_add)
}

fn json_u64_field(value: &Value, key: &str) -> Option<u64> {
    value.get(key).and_then(Value::as_u64)
}

fn nested_u64_field(value: &Value, object_key: &str, key: &str) -> Option<u64> {
    value
        .get(object_key)
        .and_then(|object| object.get(key))
        .and_then(Value::as_u64)
}

fn json_f64_prefer(object: &serde_json::Map<String, Value>, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .filter_map(|key| object.get(*key).and_then(Value::as_f64))
        .find(|value| value.is_finite())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn healthy_peer_rating_promotes() {
        let peer = json!({
            "npub": "npub1good",
            "stats": {"packets_sent": 100, "packets_recv": 120},
            "mmp": {
                "smoothed_loss": 0.001,
                "smoothed_etx": 1.01,
                "delivery_ratio_forward": 0.999,
                "delivery_ratio_reverse": 0.998,
                "srtt_ms": 20.0,
                "goodput_bps": 8_000_000.0
            },
            "replay_suppressed": 0,
            "consecutive_decrypt_failures": 0
        });

        let health = compute_peer_rating(&peer).expect("health rating");

        assert!(health.score > 50, "{health:?}");
        assert_eq!(health.sample_count, 220);
    }

    #[test]
    fn performance_only_weakness_does_not_downvote_peer() {
        let peer = json!({
            "npub": "npub1mobile",
            "stats": {"packets_sent": 100, "packets_recv": 120},
            "mmp": {
                "smoothed_loss": 0.20,
                "smoothed_etx": 3.2,
                "delivery_ratio_forward": 0.73,
                "delivery_ratio_reverse": 0.81,
                "srtt_ms": 1200.0,
                "goodput_bps": 50_000.0
            },
            "replay_suppressed": 0,
            "consecutive_decrypt_failures": 0
        });

        let health = compute_peer_rating(&peer).expect("health rating");

        assert_eq!(health.score, 50, "{health:?}");
    }

    #[test]
    fn detected_misbehavior_downranks_peer() {
        let peer = json!({
            "npub": "npub1bad",
            "stats": {"packets_sent": 100, "packets_recv": 120},
            "mmp": {
                "smoothed_loss": 0.25,
                "smoothed_etx": 3.2,
                "delivery_ratio_forward": 0.73,
                "delivery_ratio_reverse": 0.81,
                "srtt_ms": 1200.0,
                "goodput_bps": 50_000.0
            },
            "replay_suppressed": 2,
            "consecutive_decrypt_failures": 2
        });

        let health = compute_peer_rating(&peer).expect("health rating");

        assert!(health.score < 50, "{health:?}");
    }

    #[test]
    fn peer_without_health_signal_is_skipped() {
        let peer = json!({
            "npub": "npub1unknown",
            "stats": {"packets_sent": 0, "packets_recv": 0},
            "replay_suppressed": 0,
            "consecutive_decrypt_failures": 0
        });

        assert!(compute_peer_rating(&peer).is_none());
    }
}
