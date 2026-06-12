fn make_snap(t: u64) -> Snapshot {
    Snapshot {
        mesh_size: Some(10 + t),
        tree_depth: 2,
        peer_count: 3,
        parent_switches_total: t,
        bytes_in_total: 100 * t,
        bytes_out_total: 200 * t,
        packets_in_total: t,
        packets_out_total: 2 * t,
        loss_rate: 0.01 * t as f64,
        active_sessions: t,
    }
}

fn make_addr(tag: u8) -> NodeAddr {
    NodeAddr::from_bytes([tag; 16])
}

fn make_peer_snap(tag: u8, now: Instant, t: u64) -> PeerSnapshot {
    PeerSnapshot {
        node_addr: make_addr(tag),
        last_seen: now,
        srtt_ms: Some(10.0 + t as f64),
        loss_rate: Some(0.01 * t as f64),
        bytes_in_total: 50 * t,
        bytes_out_total: 75 * t,
        packets_in_total: t,
        packets_out_total: 2 * t,
        ecn_ce_total: 0,
    }
}

#[test]
fn push_and_query_fast_ring() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    for i in 0..10 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    let s = h.query(Metric::MeshSize, Duration::from_secs(5), Granularity::Fast);
    assert_eq!(s.values.len(), 5);
    assert_eq!(s.values, vec![15.0, 16.0, 17.0, 18.0, 19.0]);
    assert_eq!(s.granularity_seconds, 1);
}

#[test]
fn fast_ring_wraps_at_capacity() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    for i in 0..3610u64 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    let s = h.query(
        Metric::MeshSize,
        Duration::from_secs(FAST_RING_CAPACITY as u64 * 2),
        Granularity::Fast,
    );
    assert_eq!(s.values.len(), FAST_RING_CAPACITY);
    assert_eq!(s.values[0], 20.0);
    assert_eq!(*s.values.last().unwrap(), 3619.0);
}

#[test]
fn delta_for_counter_metric() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    let totals = [0, 0, 2, 5];
    for (i, &v) in totals.iter().enumerate() {
        let mut s = make_snap(i as u64);
        s.parent_switches_total = v;
        h.tick(t0 + Duration::from_secs(i as u64), &s, &[]);
    }
    let s = h.query(
        Metric::ParentSwitches,
        Duration::from_secs(10),
        Granularity::Fast,
    );
    assert_eq!(s.values.len(), 10);
    assert!(s.values[..6].iter().all(|v| v.is_nan()));
    assert_eq!(s.values[6..], [0.0, 0.0, 2.0, 3.0]);
}

#[test]
fn downsample_last_aggregation() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    for i in 0..60u64 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    let s = h.query(
        Metric::MeshSize,
        Duration::from_secs(60 * 5),
        Granularity::Slow,
    );
    assert_eq!(s.values.len(), 5);
    assert!(s.values[..4].iter().all(|v| v.is_nan()));
    assert_eq!(s.values[4], 69.0);
    assert_eq!(s.granularity_seconds, 60);
}

#[test]
fn downsample_mean_aggregation() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    for i in 0..60u64 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    let s = h.query(Metric::LossRate, Duration::from_secs(60), Granularity::Slow);
    assert_eq!(s.values.len(), 1);
    assert!((s.values[0] - 0.295).abs() < 1e-9);
}

#[test]
fn downsample_sum_aggregation() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    for i in 0..60u64 {
        let mut s = make_snap(0);
        s.parent_switches_total = i;
        h.tick(t0 + Duration::from_secs(i), &s, &[]);
    }
    let s = h.query(
        Metric::ParentSwitches,
        Duration::from_secs(60),
        Granularity::Slow,
    );
    assert_eq!(s.values.len(), 1);
    assert_eq!(s.values[0], 59.0);
}

#[test]
fn query_pads_front_with_nan_when_ring_is_short() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    for i in 0..3u64 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    let s = h.query(Metric::MeshSize, Duration::from_secs(10), Granularity::Fast);
    assert_eq!(s.values.len(), 10);
    assert!(s.values[..7].iter().all(|v| v.is_nan()));
    assert_eq!(s.values[7..], [10.0, 11.0, 12.0]);
}

#[test]
fn fast_query_young_ring_returns_full_hour_with_leading_nan() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    // 5 minutes of data.
    for i in 0..300u64 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    let s = h.query(
        Metric::MeshSize,
        Duration::from_secs(3600),
        Granularity::Fast,
    );
    assert_eq!(s.values.len(), 3600);
    assert!(s.values[..3300].iter().all(|v| v.is_nan()));
    assert_eq!(s.values[3300], 10.0);
    assert_eq!(*s.values.last().unwrap(), 309.0);
}

#[test]
fn slow_query_young_ring_returns_full_day_with_leading_nan() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    // 30 minutes of data → 30 slow samples flushed.
    for i in 0u64..1800 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    let s = h.query(
        Metric::MeshSize,
        Duration::from_secs(24 * 3600),
        Granularity::Slow,
    );
    assert_eq!(s.values.len(), 1440);
    assert!(s.values[..1410].iter().all(|v| v.is_nan()));
    assert!(s.values[1410..].iter().all(|v| !v.is_nan()));
}

#[test]
fn metric_parse_roundtrip() {
    for m in ALL_METRICS {
        assert_eq!(Metric::from_str(m.name()).unwrap(), *m);
    }
    assert!(Metric::from_str("bogus").is_err());
}

#[test]
fn peer_metric_parse_roundtrip() {
    for m in ALL_PEER_METRICS {
        assert_eq!(PeerMetric::from_str(m.name()).unwrap(), *m);
    }
    assert!(PeerMetric::from_str("bogus").is_err());
}

#[test]
fn granularity_parse() {
    assert_eq!(Granularity::from_str("1s").unwrap(), Granularity::Fast);
    assert_eq!(Granularity::from_str("1m").unwrap(), Granularity::Slow);
    assert!(Granularity::from_str("1h").is_err());
}

#[test]
fn latest_and_recent() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    for i in 0..5u64 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    assert_eq!(h.latest(Metric::MeshSize), Some(14.0));
    let r = h.recent(Metric::MeshSize, 3);
    assert_eq!(r, vec![12.0, 13.0, 14.0]);
    let r2 = h.recent(Metric::MeshSize, 100);
    assert_eq!(r2.len(), 5);
}

#[test]
fn active_sessions_is_sampled_as_gauge() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    for i in 0..3u64 {
        let mut s = make_snap(i);
        s.active_sessions = 10 + i;
        h.tick(t0 + Duration::from_secs(i), &s, &[]);
    }
    let s = h.query(
        Metric::ActiveSessions,
        Duration::from_secs(5),
        Granularity::Fast,
    );
    assert_eq!(s.values.len(), 5);
    assert!(s.values[..2].iter().all(|v| v.is_nan()));
    assert_eq!(s.values[2..], [10.0, 11.0, 12.0]);
}

#[test]
fn new_peer_backfills_nan_to_align_with_node_rings() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    // Tick 5 times with no peers (node rings fill up).
    for i in 0..5u64 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    // Peer A joins on tick 6.
    let a = make_addr(1);
    h.tick(
        t0 + Duration::from_secs(5),
        &make_snap(5),
        &[make_peer_snap(1, t0 + Duration::from_secs(5), 5)],
    );
    // A's srtt ring has 5 NaN backfill + 1 real = 6 samples. A 60s
    // window front-pads with 54 more NaN so the real value lands at
    // the tail.
    let s = h
        .peer_query(
            &a,
            PeerMetric::SrttMs,
            Duration::from_secs(60),
            Granularity::Fast,
        )
        .unwrap();
    assert_eq!(s.values.len(), 60);
    assert!(s.values[..59].iter().all(|v| v.is_nan()));
    assert_eq!(s.values[59], 15.0);
}

#[test]
fn absent_peer_gets_nan_sample() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    let a = make_addr(1);
    // Tick 3 times with A present.
    for i in 0..3u64 {
        h.tick(
            t0 + Duration::from_secs(i),
            &make_snap(i),
            &[make_peer_snap(1, t0 + Duration::from_secs(i), i)],
        );
    }
    // A disappears for 2 ticks.
    for i in 3..5u64 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    let s = h
        .peer_query(
            &a,
            PeerMetric::SrttMs,
            Duration::from_secs(60),
            Granularity::Fast,
        )
        .unwrap();
    assert_eq!(s.values.len(), 60);
    // 55 NaN front-pad, then 3 real, then 2 NaN (A gone).
    assert!(s.values[..55].iter().all(|v| v.is_nan()));
    assert_eq!(s.values[55], 10.0);
    assert_eq!(s.values[57], 12.0);
    assert!(s.values[58].is_nan());
    assert!(s.values[59].is_nan());
}

#[test]
fn counter_decrease_emits_nan_and_rebaselines() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    let a = make_addr(1);
    // Three ticks with bytes_in increasing.
    for (i, total) in [(0u64, 100u64), (1, 200), (2, 300)].iter().copied() {
        let mut ps = make_peer_snap(1, t0 + Duration::from_secs(i), i);
        ps.bytes_in_total = total;
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[ps]);
    }
    // Fourth tick: bytes_in drops to 50 (link reconnected).
    let mut ps = make_peer_snap(1, t0 + Duration::from_secs(3), 3);
    ps.bytes_in_total = 50;
    h.tick(t0 + Duration::from_secs(3), &make_snap(3), &[ps]);
    // Fifth tick: bytes_in grows to 80.
    let mut ps = make_peer_snap(1, t0 + Duration::from_secs(4), 4);
    ps.bytes_in_total = 80;
    h.tick(t0 + Duration::from_secs(4), &make_snap(4), &[ps]);

    let s = h
        .peer_query(
            &a,
            PeerMetric::BytesIn,
            Duration::from_secs(60),
            Granularity::Fast,
        )
        .unwrap();
    assert_eq!(s.values.len(), 60);
    // 55 NaN front-pad, then the 5 per-tick samples at the tail.
    assert!(s.values[..55].iter().all(|v| v.is_nan()));
    // First real tick has no prev → NaN.
    assert!(s.values[55].is_nan());
    assert_eq!(s.values[56], 100.0);
    assert_eq!(s.values[57], 100.0);
    // Decrease → NaN, rebaseline to 50.
    assert!(s.values[58].is_nan());
    // Next delta from new baseline.
    assert_eq!(s.values[59], 30.0);
}

#[test]
fn peer_eviction_fires_after_24h_of_silence() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    let a = make_addr(1);
    // One real sample for A at t=0.
    h.tick(t0, &make_snap(0), &[make_peer_snap(1, t0, 0)]);
    assert!(h.has_peer(&a));
    // Keep ticking every minute without A for 24 hours + 1 minute.
    // (we tick at 60s intervals to avoid building a 24h fast ring)
    let eviction = Duration::from_secs(PEER_EVICTION_SECS);
    let mut i = 1u64;
    loop {
        let t = t0 + Duration::from_secs(i * 60);
        h.tick(t, &make_snap(i), &[]);
        if t.duration_since(t0) >= eviction {
            break;
        }
        i += 1;
    }
    assert!(!h.has_peer(&a));
}

#[test]
fn nan_mean_downsample_skips_nan_samples() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    let a = make_addr(1);
    // 60 ticks alternating present / absent — 30 real SRTT samples
    // at values 10, 12, 14, ..., 68, mean = 39.
    for i in 0..60u64 {
        if i.is_multiple_of(2) {
            h.tick(
                t0 + Duration::from_secs(i),
                &make_snap(i),
                &[make_peer_snap(1, t0 + Duration::from_secs(i), i)],
            );
        } else {
            h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
        }
    }
    let s = h
        .peer_query(
            &a,
            PeerMetric::SrttMs,
            Duration::from_secs(60),
            Granularity::Slow,
        )
        .unwrap();
    assert_eq!(s.values.len(), 1);
    let expected: f64 = (0..60u64)
        .filter(|i| i.is_multiple_of(2))
        .map(|i| 10.0 + i as f64)
        .sum::<f64>()
        / 30.0;
    assert!((s.values[0] - expected).abs() < 1e-9);
}

#[test]
fn all_nan_window_downsamples_to_nan() {
    let mut h = StatsHistory::new();
    let t0 = Instant::now();
    let a = make_addr(1);
    // Introduce A, then silence it for 60+ ticks so one full slow
    // sample accumulates entirely of NaN.
    h.tick(t0, &make_snap(0), &[make_peer_snap(1, t0, 0)]);
    for i in 1..=60u64 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    let s = h
        .peer_query(
            &a,
            PeerMetric::SrttMs,
            Duration::from_secs(60 * 5),
            Granularity::Slow,
        )
        .unwrap();
    // We got one slow sample after 60 fast ticks. First 60 samples
    // in the fast ring were 1 real + 59 NaN → Last = 10.0. But the
    // boundary lands at fast_pushes == 60, AFTER pushing tick 59
    // (index 59). So the slow window covers fast indices 0..59, i.e.
    // tick 0 (real) + ticks 1..59 (NaN) → Last = 10.0. Not all-NaN.
    //
    // Window is 300s / 60s = 5 slots; ring has 1 slow sample, so 4
    // leading NaN from the front-pad and the real value at the tail.
    //
    // Let's instead assert that the NEXT slow flush (after another
    // 60 all-NaN ticks) is NaN.
    assert_eq!(s.values.len(), 5);
    assert!(s.values[..4].iter().all(|v| v.is_nan()));
    assert_eq!(s.values[4], 10.0);

    for i in 61..=120u64 {
        h.tick(t0 + Duration::from_secs(i), &make_snap(i), &[]);
    }
    let s = h
        .peer_query(
            &a,
            PeerMetric::SrttMs,
            Duration::from_secs(60 * 5),
            Granularity::Slow,
        )
        .unwrap();
    // 3 leading NaN from front-pad, then 2 real slow samples: the
    // first Last=10.0, the second a fully-NaN slow window → NaN.
    assert_eq!(s.values.len(), 5);
    assert!(s.values[..3].iter().all(|v| v.is_nan()));
    assert_eq!(s.values[3], 10.0);
    assert!(s.values[4].is_nan());
}

#[test]
fn nan_serializes_to_json_null() {
    let series = Series {
        metric: "srtt_ms",
        unit: "ms",
        granularity_seconds: 1,
        values: vec![1.0, f64::NAN, 3.0],
    };
    let json = serde_json::to_value(&series).unwrap();
    let values = json.get("values").unwrap().as_array().unwrap();
    assert!(values[0].is_f64());
    assert!(values[1].is_null());
    assert!(values[2].is_f64());
}
use super::*;
