//! Establish the new keys using the normal bounded return allowance.
use fips_relay::{
    probe::{ReceiveProbe, SendProbe},
    service::{AdminRequest, ServiceConfig, native_request, request},
};
use serde_json::{Value, json};
use std::time::Duration;

async fn session(config: &ServiceConfig, remote: &str) -> Result<Value, String> {
    let reply = native_request(config, &json!({"command": "show_sessions"})).await?;
    reply["data"]["sessions"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["npub"] == remote))
        .map(|row| {
            json!({
                "state": row["state"],
                "session_start_ms": row["session_start_ms"],
                "current_k_bit": row["current_k_bit"],
                "is_draining": row["is_draining"],
            })
        })
        .ok_or_else(|| "expected endpoint session is absent".into())
}

pub async fn after_drain(configs: &[ServiceConfig], npubs: &[String]) -> Value {
    let mut evidence = json!({"passed": false, "return_allowance": true});
    if let Err(error) = exercise(configs, npubs, &mut evidence).await {
        evidence["error"] = error.into();
    }
    evidence
}

async fn exercise(
    configs: &[ServiceConfig],
    npubs: &[String],
    evidence: &mut Value,
) -> Result<(), String> {
    let last = configs.len() - 1;
    let source = &configs[0];
    let destination = &configs[last];
    if configs.iter().any(|config| !config.return_allowance) {
        return Err("all transit relays must enable bounded replies".into());
    }
    let endpoints = [(source, &npubs[last]), (destination, &npubs[0])];
    let before = [
        session(source, &npubs[last]).await?,
        session(destination, &npubs[0]).await?,
    ];
    evidence["before"] = json!({"source": before[0], "destination": before[1]});
    // Keep the paid route active across the normal rotation timer and drain.
    // Each accepted forward packet earns bounded credit for ordinary replies.
    tokio::time::timeout(Duration::from_secs(200), async {
        loop {
            request(
                source,
                &AdminRequest::Send {
                    destination: npubs[last].clone(),
                    payload: "rotation check".to_owned(),
                },
            )
            .await?;
            let mut after = Vec::new();
            for (config, remote) in endpoints {
                after.push(session(config, remote).await?);
            }
            let retired = after.iter().zip(&before).all(|(current, old)| {
                current["state"] == "established"
                    && current["session_start_ms"]
                        .as_u64()
                        .zip(old["session_start_ms"].as_u64())
                        .is_some_and(|(new, old)| new > old)
                    && current["current_k_bit"]
                        .as_bool()
                        .zip(old["current_k_bit"].as_bool())
                        .is_some_and(|(new, old)| new != old)
                    && current["is_draining"] == false
            });
            if retired && after[0]["current_k_bit"] == after[1]["current_k_bit"] {
                evidence["after_drain"] = json!({"source": after[0], "destination": after[1]});
                return Ok::<(), String>(());
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    })
    .await
    .map_err(|_| "endpoints did not retire their old session keys".to_owned())??;

    #[cfg(feature = "measurements")]
    {
        let mut idle = json!({"passed": false, "quiet_ms": 1_500, "window_ms": 7_000});
        if let Err(error) = observe_idle_cost(configs, npubs, &mut idle).await {
            idle["error"] = error.into();
        }
        evidence["idle"] = idle;
    }

    const COUNT: u32 = 16;
    const BYTES: usize = 128;
    let stream_id = format!("{:032x}", 603);
    request(
        destination,
        &AdminRequest::ReceiveProbe {
            probe: ReceiveProbe {
                source: npubs[0].clone(),
                stream_id: stream_id.clone(),
                packet_count: COUNT,
                payload_bytes: BYTES,
                lifetime_secs: Some(30),
                measure_one_way_latency: false,
                reflect: false,
            },
        },
    )
    .await?;
    let sent = request(
        source,
        &AdminRequest::SendProbe {
            probe: SendProbe {
                destination: npubs[last].clone(),
                stream_id,
                packet_count: COUNT,
                payload_bytes: BYTES,
                packets_per_second: 16,
                max_duration_secs: Some(5),
                measure_round_trip: false,
            },
        },
    )
    .await?["probe"]
        .clone();
    evidence["sender"] = sent.clone();
    let delivery = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let receiver = request(destination, &AdminRequest::Status).await?["probe"].clone();
            let complete =
                receiver["stream_id"] == sent["stream_id"] && receiver["unique_packets"] == COUNT;
            evidence["receiver"] = receiver;
            if complete {
                return Ok::<(), String>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    let idle_passed = evidence
        .get("idle")
        .is_none_or(|idle| idle["passed"] == true);
    evidence["passed"] = (idle_passed
        && delivery.is_ok_and(|result| result.is_ok())
        && sent["submitted_packets"] == COUNT
        && sent["stopped_reason"].is_null())
    .into();
    // The caller settles the original channels before asserting this verdict.
    // It must not replay the stream, reset accounts or issue replacement funds.
    Ok(())
}

#[cfg(feature = "measurements")]
async fn idle_cost_snapshot(
    configs: &[ServiceConfig],
    npubs: &[String],
) -> Result<(Value, bool), String> {
    let mut ready = true;
    let mut costs = Vec::new();
    let mut channels = 0;
    for config in configs {
        // This fixture charges exactly one msat per byte, so an unchanged
        // evidence counter cannot hide a newly priced small control frame.
        if config.terms.fee_msat_per_kib != 1_024 {
            return Err("idle cost observation requires one msat per byte".into());
        }
        let status = request(config, &AdminRequest::Status).await?;
        let payment = status["control_traffic"]
            .as_array()
            .and_then(|rows| rows.iter().find(|row| row["service_port"] == 44_743))
            .ok_or("payment control counters are absent")?;
        let started = payment["counters"]["requests_started"]
            .as_u64()
            .ok_or("payment request count is absent")?;
        let received = payment["counters"]["requests_received"]
            .as_u64()
            .ok_or("payment receive count is absent")?;
        let progress = status["payment_progress"]
            .as_object()
            .ok_or("payment progress is absent")?;
        channels += progress.len();
        for row in progress.values() {
            let authorized = row["authorized_sat"]
                .as_u64()
                .ok_or("authorized payment is absent")?;
            row["evidence_msat"]
                .as_u64()
                .ok_or("usage evidence is absent")?;
            ready &= row["in_flight"] == false
                && row["pending"].is_null()
                && (authorized == 0
                    || row["acknowledged_msat"]
                        .as_u64()
                        .is_some_and(|paid| paid >= authorized.saturating_mul(1_000)));
        }
        costs.push(json!({"started": started, "received": received, "channels": progress}));
    }
    if channels != 3 {
        return Err("idle observation must cover all three original channels".into());
    }
    let last = configs.len() - 1;
    let source = session(&configs[0], &npubs[last]).await?;
    let destination = session(&configs[last], &npubs[0]).await?;
    for endpoint in [&source, &destination] {
        ready &= endpoint["state"] == "established" && endpoint["is_draining"] == false;
    }
    Ok((
        json!({"source": source, "destination": destination, "costs": costs}),
        ready,
    ))
}

#[cfg(feature = "measurements")]
async fn observe_idle_cost(
    configs: &[ServiceConfig],
    npubs: &[String],
    evidence: &mut Value,
) -> Result<(), String> {
    let before = tokio::time::timeout(Duration::from_secs(10), async {
        let (mut previous, _) = idle_cost_snapshot(configs, npubs).await?;
        let mut unchanged_since = tokio::time::Instant::now();
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let (current, ready) = idle_cost_snapshot(configs, npubs).await?;
            if !ready || current != previous {
                previous = current;
                unchanged_since = tokio::time::Instant::now();
            } else if unchanged_since.elapsed() >= Duration::from_millis(1_500) {
                return Ok::<_, String>(current);
            }
        }
    })
    .await
    .map_err(|_| "post-drain payments did not become quiet".to_owned())??;
    evidence["before"] = before.clone();
    let started = tokio::time::Instant::now();
    let until = started + Duration::from_secs(7);
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (current, ready) = idle_cost_snapshot(configs, npubs).await?;
        evidence["after"] = current.clone();
        evidence["elapsed_ms"] = json!(started.elapsed().as_millis());
        if !ready || current != before {
            return Err("idle epoch, priced usage or payment requests changed".into());
        }
        if tokio::time::Instant::now() >= until {
            evidence["passed"] = true.into();
            return Ok(());
        }
    }
}
