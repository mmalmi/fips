//! Restart funded relays while a seed carrier or the mint is unavailable.
use super::*;

pub(super) async fn deny_mint(gate: &proxy::StreamProxy) -> usize {
    use tokio::{io::AsyncReadExt, net::TcpStream};
    gate.set_available(false).await;
    let connected = gate.connections();
    assert!(connected > 0, "funding must have used the gated mint");
    let rejected = gate.rejected_connections();
    let mut probe = TcpStream::connect(gate.address).await.unwrap();
    let mut byte = [0];
    let result = tokio::time::timeout(Duration::from_secs(2), probe.read(&mut byte))
        .await
        .expect("unavailable mint closes a fresh connection");
    assert!(matches!(result, Ok(0) | Err(_)));
    assert!(gate.rejected_connections() > rejected);
    assert_eq!(gate.connections(), connected);
    connected
}

pub(super) async fn assert_retained_accounts(
    bench: &MixedBench,
    before: &[Value],
    funding: &[serde_json::Map<String, Value>],
) {
    assert!(
        bench.funding_intents(false) == funding,
        "outage changed funding identities"
    );
    for (old, offline) in before.iter().zip(bench.states().await) {
        assert_eq!(offline["history"], old["history"]);
        for field in ["wallet_debited_sat", "pending_reserved_sat"] {
            assert_eq!(
                offline["funding_budget"][field],
                old["funding_budget"][field]
            );
        }
        assert!(
            offline["remaining_budget_sat"].as_u64().unwrap()
                <= old["remaining_budget_sat"].as_u64().unwrap()
        );
    }
}

pub(super) async fn middle(
    bench: &mut MixedBench,
    before: &[Value],
    funding: &[serde_json::Map<String, Value>],
) {
    let tls_connections = bench.tls.as_ref().map(tls::TlsProxy::connections);
    let partition = if let Some(proxy) = bench.seed_carrier() {
        let counters = (proxy.connections(), proxy.rejected_connections());
        assert!(proxy.set_available(false).await > 0);
        Some(counters)
    } else {
        None
    };
    bench.children[1].kill().await.unwrap();
    bench.children[1] = process_support::start(&bench.paths[1]).await;

    if let Some((connected, rejected)) = partition {
        bench.set_stage("restarted-during-partition");
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                assert!(bench.children[1].try_wait().unwrap().is_none());
                let middle = request(&bench.configs[1], &AdminRequest::Status).await;
                let end = request(&bench.configs[2], &AdminRequest::Status)
                    .await
                    .unwrap();
                let proxy = bench.seed_carrier().unwrap();
                assert_eq!(proxy.connections(), connected);
                if let Ok(middle) = middle
                    && disconnected(&middle, &bench.npubs[2])
                    && disconnected(&end, &bench.npubs[1])
                    && proxy.rejected_connections() >= rejected + 2
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("restarted relay and seed must remain disconnected across reconnect attempts");

        assert_retained_accounts(bench, before, funding).await;
        let proxy = bench.seed_carrier().unwrap();
        eprintln!(
            "partition survived relay restart: rejected_reconnects={}",
            proxy.rejected_connections() - rejected
        );
        assert_eq!(proxy.set_available(true).await, 0);
    }

    process_support::ready(
        &bench.configs,
        &bench.paths,
        &bench.npubs,
        &mut bench.children,
    )
    .await;
    bench.assert_carriers().await;
    if let Some((previous, _)) = partition {
        assert!(bench.seed_carrier().unwrap().connections() > previous);
    }
    if let Some(previous) = tls_connections {
        assert!(bench.tls.as_ref().unwrap().connections() > previous);
    }
    // The caller requires fresh paid traffic, bounded crash-exposure renewal,
    // exact retained funding identities and final conservation of all test sats.
}

fn disconnected(status: &Value, peer: &str) -> bool {
    !status["peers"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entry| entry["npub"] == peer && entry["connected"] == true)
}
