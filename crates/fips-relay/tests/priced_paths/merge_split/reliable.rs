//! One TCP write survives a genuine paid mesh split without application replay.
use super::*;
use fips_tcp::{ConnectionId, MarkerStatus, State};
use fips_tcp_endpoint::FipsTcpEndpoint;
use tokio::{task::JoinSet, time::MissedTickBehavior};

const PORT: u16 = 44_753;
const BODY_LEN: usize = 4096;
const RECOVERY: Duration = Duration::from_secs(20);

struct Stream {
    client: FipsTcpEndpoint,
    server: FipsTcpEndpoint,
    outgoing: ConnectionId,
    incoming: Option<ConnectionId>,
    clock: Instant,
    tick: tokio::time::Interval,
}

impl Stream {
    fn now(&self) -> u64 {
        self.clock.elapsed().as_millis().try_into().unwrap()
    }

    async fn connect(bench: &Bench) -> Result<Self, String> {
        let mut client =
            FipsTcpEndpoint::bind(bench.nodes[0].clone(), PORT, fips_tcp::Config::default(), 1)
                .await
                .map_err(|e| e.to_string())?;
        let server =
            FipsTcpEndpoint::bind(bench.nodes[5].clone(), PORT, fips_tcp::Config::default(), 2)
                .await
                .map_err(|e| e.to_string())?;
        let clock = Instant::now();
        let outgoing = client
            .connect(bench.peers[5], 0)
            .await
            .map_err(|e| e.to_string())?;
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        let mut stream = Self {
            client,
            server,
            outgoing,
            incoming: None,
            clock,
            tick,
        };
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                stream.pump().await?;
                if stream.incoming.is_none() {
                    stream.incoming = stream.server.accept();
                }
                if stream.established() {
                    return Ok::<_, String>(());
                }
            }
        })
        .await
        .map_err(|_| "initial TCP handshake exceeded 20s")??;
        if stream
            .server
            .peer(stream.incoming.unwrap())
            .map(|p| *p.node_addr())
            != Some(*bench.peers[0].node_addr())
        {
            return Err("TCP accepted the wrong authenticated source".into());
        }
        Ok(stream)
    }

    fn established(&self) -> bool {
        self.client.state(self.outgoing) == Some(State::Established)
            && self
                .incoming
                .is_some_and(|id| self.server.state(id) == Some(State::Established))
    }

    // The same adapter receive/poll operations and 10ms clock drive as the
    // production ControlTransport. FIPS and payment actors run independently.
    async fn pump(&mut self) -> Result<(), String> {
        let now = self.now();
        tokio::select! {
            result = self.client.receive_report(now) => result.map(|_| ()).map_err(|e| e.to_string()),
            result = self.server.receive_report(now) => result.map(|_| ()).map_err(|e| e.to_string()),
            _ = self.tick.tick() => {
                let now = self.now();
                self.client.poll(now).await.map_err(|e| e.to_string())?;
                self.server.poll(now).await.map_err(|e| e.to_string())
            }
        }
    }

    async fn wait_for_split(&mut self, bench: &Bench) -> Result<u128, String> {
        let started = Instant::now();
        let mut observation = tokio::time::interval(Duration::from_millis(200));
        observation.set_missed_tick_behavior(MissedTickBehavior::Skip);
        // Reuse the ordinary topology predicate and its existing 100s bound:
        // exact internal peers, absent bridge owners and distinct component roots.
        tokio::time::timeout(Duration::from_secs(100), async {
            loop {
                tokio::select! {
                    result = self.pump() => result?,
                    _ = observation.tick() => {
                        if topology(bench, false).await { return Ok::<_, String>(()); }
                    }
                }
                if !self.established() {
                    return Err(
                        "original TCP connection closed while waiting for genuine split".into(),
                    );
                }
            }
        })
        .await
        .map_err(|_| "ordinary bridge eviction/root split exceeded 100s")??;
        if !self.established() {
            return Err("split did not retain original TCP connection".into());
        }
        Ok(started.elapsed().as_millis())
    }
}

async fn accepted_write(bench: Arc<Bench>) -> Result<serde_json::Value, String> {
    let mut stream = Stream::connect(&bench).await?;
    let original = (stream.outgoing, stream.incoming.unwrap());
    bench.network.set_link_up("2", "3", false);
    let split_ms = stream.wait_for_split(&bench).await?;
    let body: Vec<_> = (0..BODY_LEN).map(|i| (i % 251) as u8).collect();
    let start = Instant::now();
    let deadline = start + RECOVERY;
    let network = bench.network.clone();
    let mut reopening = JoinSet::new();
    // Physical reopening is independent of TCP receives, polls and observations.
    // Dropping this owner on timeout also cancels an unvisited scheduled mutation.
    reopening.spawn(async move {
        tokio::time::sleep_until(start + Duration::from_secs(2)).await;
        let before = start.elapsed().as_micros();
        network.set_link_up("2", "3", true);
        [before, start.elapsed().as_micros()]
    });
    let offered = start.elapsed().as_micros();
    let now = stream.now();
    let (accepted, marker) = tokio::time::timeout_at(
        deadline,
        stream.client.write_with_marker(original.0, &body, now),
    )
    .await
    .map_err(|_| "single TCP write exceeded its original deadline")?
    .map_err(|e| e.to_string())?;
    let accepted_at = start.elapsed().as_micros();
    if accepted != body.len() {
        return Err(format!("single TCP write accepted only {accepted} bytes"));
    }
    if stream.client.marker_status(&marker) != MarkerStatus::Pending {
        return Err("partitioned write was already acknowledged".into());
    }
    let mut received = Vec::new();
    let mut first_received_at = None;
    let mut received_at = None;
    let mut acknowledged_at = None;
    let delivery = tokio::time::timeout_at(deadline, async {
        loop {
            stream.pump().await?;
            if !stream.established() || (stream.outgoing, stream.incoming.unwrap()) != original {
                return Err("recovery replaced or closed the original TCP connection".into());
            }
            let now = stream.now();
            let bytes = stream
                .server
                .read(original.1, BODY_LEN + 1, now)
                .await
                .map_err(|e| e.to_string())?;
            if !bytes.is_empty() {
                first_received_at.get_or_insert_with(|| start.elapsed().as_micros());
            }
            received.extend(bytes);
            if received.len() > body.len() || !body.starts_with(&received) {
                return Err("TCP delivered duplicate or different application bytes".into());
            }
            if received.len() == body.len() && received_at.is_none() {
                received_at = Some(start.elapsed().as_micros());
            }
            match stream.client.marker_status(&marker) {
                MarkerStatus::Acked => {
                    acknowledged_at.get_or_insert_with(|| start.elapsed().as_micros());
                }
                MarkerStatus::Pending => {}
                other => {
                    return Err(format!(
                        "accepted TCP write lost its acknowledgment boundary: {other:?}"
                    ));
                }
            }
            if received_at.is_some() && acknowledged_at.is_some() {
                return Ok::<_, String>(());
            }
        }
    })
    .await
    .map_err(|_| {
        format!(
            "original TCP write did not recover within 20s: received={}/{} ack={:?}",
            received.len(),
            body.len(),
            stream.client.marker_status(&marker)
        )
    })?;
    delivery?;
    let opening = reopening
        .join_next()
        .await
        .ok_or("missing reopening task")?
        .map_err(|e| e.to_string())?;
    if accepted_at >= opening[0]
        || first_received_at.unwrap() < opening[1]
        || acknowledged_at.unwrap() < opening[1]
    {
        return Err("accepted-write/rejoin/receipt ordering did not match the outage".into());
    }
    if opening[0] < 2_000_000 || opening[1] >= 2_500_000 {
        return Err(format!(
            "independent two-second reopening drifted: {opening:?}"
        ));
    }
    // The entire accepted byte range was read once; one further read is empty.
    let now = stream.now();
    if !stream
        .server
        .read(original.1, BODY_LEN, now)
        .await
        .map_err(|e| e.to_string())?
        .is_empty()
    {
        return Err("extra application bytes followed the accepted record".into());
    }
    Ok(serde_json::json!({
        "split_observed_ms": split_ms, "application_writes": 1, "accepted_bytes": accepted,
        "write_us": [offered, accepted_at], "reopening_us": opening,
        "first_received_us": first_received_at,
        "received_us": received_at, "acknowledged_us": acknowledged_at,
        "original_deadline_us": RECOVERY.as_micros(),
    }))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn accepted_tcp_write_recovers_after_bridge_rejoin() {
    tokio::time::timeout(Duration::from_secs(480), exercise())
        .await
        .expect("paid TCP split/rejoin and collection deadline");
}

async fn exercise() {
    let mut bench = bench::start(0, Scenario::MergeSplit, 153).await;
    converge(&bench, false, "TCP independent components").await;
    for (source, destination) in [(0, 2), (5, 3)] {
        watch(&bench, source, destination).await;
    }
    bench.network.set_link(
        "2",
        "3",
        SimLink {
            latency_ms: 2,
            ..Default::default()
        },
    );
    converge(&bench, true, "TCP initial merge").await;
    for (source, destination) in [(0, 5), (5, 0)] {
        watch(&bench, source, destination).await;
    }
    // Existing setup traffic funds/qualifies the routes before the measured write.
    for (source, destination, tag) in [(0, 5, 181), (5, 0, 182)] {
        traffic(&mut bench, source, destination, tag).await;
    }
    let baseline_paid = payments(&bench).await;
    let anchor = accounts(&bench).await;
    assert_eq!(baseline_paid.len(), 8);
    assert_watches(&bench).await;
    let before_hops = hop_usage(&bench).await;
    let bench = Arc::new(bench);
    // Retain cleanup ownership outside the fallible measured task, including panic.
    let mut attempt = tokio::spawn(accepted_write(bench.clone()));
    let outcome = match tokio::time::timeout(Duration::from_secs(150), &mut attempt).await {
        Ok(joined) => joined.map_err(|e| e.to_string()).and_then(|r| r),
        Err(_) => {
            attempt.abort();
            let _ = attempt.await;
            Err("TCP setup/split/recovery task exceeded 150s".into())
        }
    };
    eprintln!("paid reliable write outcome: {outcome:?}");
    // Restoration and collection run even when the measured write fails. No
    // fresh application traffic is offered to repair that recorded verdict.
    bench.network.set_link_up("2", "3", true);
    converge(&bench, true, "TCP collection route").await;
    let payment_bench = bench.clone();
    let payment = tokio::spawn(async move { payments(&payment_bench).await }).await;
    let after_hops = hop_usage(&bench).await;
    let final_accounts = accounts(&bench).await;
    let credited = after_hops
        .iter()
        .map(|((_, seller), usage)| {
            (
                usage.channel.clone(),
                bench.sellers[*seller]
                    .channel_usage(&usage.channel)
                    .unwrap()
                    .paid_msat,
            )
        })
        .collect();
    let bench =
        Arc::try_unwrap(bench).unwrap_or_else(|_| panic!("measured task retained bench ownership"));
    collect(bench, &final_accounts, &credited).await;
    outcome.expect("the one accepted reliable write must survive native bridge split/rejoin");
    payment.expect("automatic all-hop payments must catch up without an explicit flush");
    retain(&anchor, &final_accounts, true);
    // Aggregate accounting establishes retained all-hop authority and fresh
    // supported usage; the TCP marker and exact read separately prove delivery.
    // These shared channel counters do not attribute upkeep to the TCP record.
    fresh_hops(&before_hops, &after_hops);
}
