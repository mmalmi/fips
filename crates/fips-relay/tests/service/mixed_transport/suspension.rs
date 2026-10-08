//! A live provider resumes after both its native links and route quotes expire.
use super::*;
use std::process::Command;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "same-process suspension through quote expiry; run explicitly"]
async fn suspended_provider_renews_expired_routes_without_resetting_authority() {
    lifecycle::run(SecondHop::Udp, lifecycle::Workload::SuspendedProvider).await;
}

pub(super) async fn exercise(bench: &mut MixedBench) {
    bench.set_stage("provider-suspension-setup");
    bench.assert_carriers().await;
    for (source, destination) in [(0, 2), (2, 0)] {
        request(
            &bench.configs[source],
            &AdminRequest::Buy {
                destination: bench.npubs[destination].clone(),
            },
        )
        .await
        .unwrap();
    }
    bench.deliver_bidirectional([0, 2]).await;
    let before = bench.states().await;
    let funding = bench.funding_intents(false);
    let channels: Vec<_> = [0, 2]
        .map(|node| {
            before[node]["purchases"][0]["channel"]["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .into();
    tokio::join!(bench.wait_paid(&channels[0]), bench.wait_paid(&channels[1]));
    let expires = [0, 2]
        .map(|node| {
            before[node]["purchases"][0]["contract"]["expires_unix"]
                .as_u64()
                .unwrap()
        })
        .into_iter()
        .max()
        .unwrap();
    let wait = expires.saturating_sub(unix_now()).saturating_add(2);
    assert!(
        (35..=92).contains(&wait),
        "pause must cross normal liveness and quote deadlines"
    );

    bench.set_stage("provider-suspended");
    let pid = bench.children[1].id().unwrap();
    let mut stopped = StoppedProcess::new(pid);
    tokio::time::timeout(Duration::from_secs(2), async {
        while !stopped.is_stopped() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("owned provider should stop executing");
    let started = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(wait)).await;
    assert!(stopped.is_stopped());
    assert!(unix_now() > expires);
    for node in [0, 2] {
        let state = request(&bench.configs[node], &AdminRequest::Status)
            .await
            .unwrap();
        assert!(
            !state["peers"]
                .as_array()
                .unwrap()
                .iter()
                .any(|peer| peer["npub"] == bench.npubs[1] && peer["connected"] == true),
            "an expired provider link must be observed unavailable"
        );
        let budget: FundingBudget =
            serde_json::from_value(state["funding_budget"].clone()).unwrap();
        let policy = &bench.configs[node].terms.controller;
        assert!(budget.exposure_sat <= policy.max_wallet_spend_sat);
        assert!(budget.locked_sat <= policy.max_locked_sat);
        assert!(
            state["remaining_budget_sat"].as_u64().unwrap()
                <= before[node]["remaining_budget_sat"].as_u64().unwrap()
        );
    }
    eprintln!(
        "provider suspension: stopped_ms={} both_quotes_expired=true both_links_unavailable=true",
        started.elapsed().as_millis()
    );
    stopped.resume();
    bench.set_stage("provider-resumed");
    process_support::ready(
        &bench.configs,
        &bench.paths,
        &bench.npubs,
        &mut bench.children,
    )
    .await;
    bench.wait_replacements(&channels).await;
    bench.deliver_bidirectional([0, 2]).await;
    let after = bench.states().await;
    let replacements: Vec<_> = [0, 2]
        .map(|node| {
            after[node]["purchases"][0]["channel"]["id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .into();
    tokio::join!(
        bench.wait_paid(&replacements[0]),
        bench.wait_paid(&replacements[1])
    );
    assert_replacement_accounts(bench, &before, &bench.states().await, &funding, [1, 0, 1]).await;
    assert_eq!(bench.children[1].id(), Some(pid));
    assert!(bench.children[1].try_wait().unwrap().is_none());
    assert!(stopped.is_original_process());
    eprintln!(
        "provider suspension: same_process=true replacements=2 fresh_delivery_and_credit=true original_authority_retained=true"
    );
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct StoppedProcess {
    pid: u32,
    started: u64,
    stopped: bool,
}

impl StoppedProcess {
    fn new(pid: u32) -> Self {
        let guard = Self {
            pid,
            started: process_state(pid).unwrap().1,
            stopped: true,
        };
        assert!(guard.signal("-STOP"));
        guard
    }

    fn is_original_process(&self) -> bool {
        process_state(self.pid).is_some_and(|(_, started)| started == self.started)
    }

    fn is_stopped(&self) -> bool {
        process_state(self.pid) == Some(('T', self.started))
    }

    fn signal(&self, signal: &str) -> bool {
        self.is_original_process()
            && Command::new("kill")
                .args([signal, &self.pid.to_string()])
                .status()
                .is_ok_and(|status| status.success())
    }

    fn resume(&mut self) {
        assert!(
            self.signal("-CONT"),
            "resume the exact owned provider process"
        );
        self.stopped = false;
    }
}

impl Drop for StoppedProcess {
    fn drop(&mut self) {
        if self.stopped && !self.signal("-CONT") {
            eprintln!("owned provider could not be resumed during failure cleanup");
        }
    }
}

fn process_state(pid: u32) -> Option<(char, u64)> {
    let data = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let fields: Vec<_> = data.rsplit_once(") ")?.1.split_whitespace().collect();
    Some((
        fields.first()?.chars().next()?,
        fields.get(19)?.parse().ok()?,
    ))
}
