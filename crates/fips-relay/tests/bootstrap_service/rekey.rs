//! Unpaid reverse traffic must not break a paid forward key rotation.
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
    let mut evidence = json!({"passed": false, "return_allowance": false});
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
    if configs.iter().any(|config| config.return_allowance) {
        return Err("the fixture must keep complimentary replies disabled".into());
    }
    let initial = session(destination, &npubs[0]).await?;
    evidence["before"] = json!({
        "source": session(source, &npubs[last]).await?,
        "destination": initial,
    });
    // Observe a real recovery rekey's drain, including one already in progress.
    // This needs no packet injection, wallet contention or topology change.
    tokio::time::timeout(Duration::from_secs(70), async {
        loop {
            let state = session(destination, &npubs[0]).await?;
            if state["state"] == "established"
                && (state["session_start_ms"] != initial["session_start_ms"]
                    || initial["is_draining"] == true)
                && state["is_draining"] == false
            {
                evidence["after_drain"] = json!({
                    "source": session(source, &npubs[last]).await?,
                    "destination": state,
                });
                return Ok::<(), String>(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "recipient did not complete a real rekey drain".to_owned())??;

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
    evidence["passed"] = (delivery.is_ok_and(|result| result.is_ok())
        && sent["submitted_packets"] == COUNT
        && sent["stopped_reason"].is_null())
    .into();
    // The caller settles the original channels before asserting this verdict.
    // It must not replay the stream, reset accounts or issue replacement funds.
    Ok(())
}
