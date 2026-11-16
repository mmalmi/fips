//! Whole daemon process observations include concurrent forwarding and waiting.
use super::*;

pub(super) struct Window {
    pid: u32,
    started: Instant,
    before: Counters,
    released: Option<(u128, Counters)>,
    peak_rss_kib: u64,
}

#[derive(Clone, serde::Serialize)]
struct Counters {
    user_ticks: u64,
    system_ticks: u64,
    rss_kib: u64,
    lifetime_hwm_kib: u64,
}

fn counters(pid: u32) -> Counters {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let fields: Vec<_> = stat
        .rsplit_once(')')
        .unwrap()
        .1
        .split_whitespace()
        .collect();
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    let kib = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    Counters {
        user_ticks: fields[11].parse().unwrap(),
        system_ticks: fields[12].parse().unwrap(),
        rss_kib: kib("VmRSS:"),
        lifetime_hwm_kib: kib("VmHWM:"),
    }
}

impl Window {
    pub(super) fn new(pid: u32) -> Self {
        let before = counters(pid);
        Self {
            pid,
            started: Instant::now(),
            peak_rss_kib: before.rss_kib,
            before,
            released: None,
        }
    }

    pub(super) fn elapsed_us(&self) -> u128 {
        self.started.elapsed().as_micros()
    }

    pub(super) fn sample(&mut self) {
        self.peak_rss_kib = self.peak_rss_kib.max(counters(self.pid).rss_kib);
    }

    pub(super) fn release(&mut self) {
        let counters = counters(self.pid);
        self.peak_rss_kib = self.peak_rss_kib.max(counters.rss_kib);
        self.released = Some((self.elapsed_us(), counters));
    }

    pub(super) fn finish(&mut self) -> Value {
        self.sample();
        let after = counters(self.pid);
        self.peak_rss_kib = self.peak_rss_kib.max(after.rss_kib);
        let (held_us, released) = self.released.as_ref().unwrap();
        let ticks = std::process::Command::new("getconf")
            .arg("CLK_TCK")
            .output()
            .unwrap();
        assert!(ticks.status.success());
        let ticks_per_second: u64 = std::str::from_utf8(&ticks.stdout)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        json!({"whole_observation_us":self.started.elapsed().as_micros(),"held_writer_us":held_us,
            "released_to_collection_us":self.started.elapsed().as_micros()-held_us,
            "cpu_ticks_per_second":ticks_per_second,
            "whole_user_ticks":after.user_ticks-self.before.user_ticks,
            "whole_system_ticks":after.system_ticks-self.before.system_ticks,
            "released_user_ticks":after.user_ticks-released.user_ticks,
            "released_system_ticks":after.system_ticks-released.system_ticks,
            "sampled_peak_rss_kib":self.peak_rss_kib,"before":self.before,"after":after,
            "scope":"whole relay process, including paid forwarding; HWM is lifetime, RSS is sampled"})
    }
}

fn progress_values(sample: &Value) -> [u64; 5] {
    [
        sample["delivered"].as_u64().unwrap(),
        sample["payments"][0]["authorized_sat"].as_u64().unwrap(),
        sample["payments"][1]["authorized_sat"].as_u64().unwrap(),
        sample["credits"][0].as_u64().unwrap(),
        sample["credits"][1].as_u64().unwrap(),
    ]
}

// These are gaps between observed cumulative-counter advances, including the
// first and last partial windows. They include observer delay, not packet latency.
pub(super) fn progress(baseline: &Value, samples: &[Value], limit_us: u64) -> Value {
    assert!(
        samples.len() >= 2,
        "progress needs a full observation window"
    );
    let first = progress_values(baseline);
    let start = baseline["elapsed_us"].as_u64().unwrap();
    let mut previous = first;
    let mut previous_time = start;
    let mut advanced_at = [start; 5];
    let mut max_gaps = [0; 5];
    for sample in samples {
        let time = sample["elapsed_us"].as_u64().unwrap();
        assert!(time > previous_time, "observation time must increase");
        let current = progress_values(sample);
        for index in 0..5 {
            assert!(current[index] >= previous[index], "progress counter reset");
            max_gaps[index] = max_gaps[index].max(time - advanced_at[index]);
            if current[index] > previous[index] {
                advanced_at[index] = time;
            }
        }
        previous = current;
        previous_time = time;
    }
    let advanced = previous
        .iter()
        .zip(first)
        .all(|(last, first)| *last > first);
    let within_limit = max_gaps.iter().all(|gap| *gap <= limit_us);
    let during_cleanup = samples.iter().enumerate().any(|(index, a)| {
        a["cleanup_pending"] == true
            && samples[index + 1..].iter().any(|b| {
                b["cleanup_pending"] == true
                    && progress_values(b)
                        .iter()
                        .zip(progress_values(a))
                        .all(|(b, a)| *b > a)
            })
    });
    json!({"counter_order":["delivered","source_authorized_sat","relay_authorized_sat",
        "first_provider_credit_msat","second_provider_credit_msat"],
        "max_observed_gap_us":max_gaps,"limit_us":limit_us,
        "all_counters_advanced":advanced,"within_limit":within_limit,
        "progress_between_unfinished_cleanup_samples":during_cleanup,
        "observation_us":previous_time-start})
}

#[test]
fn progress_window_rejects_stalls_and_keeps_fast_cleanup_honest() {
    let sample = |time: u64, value: u64, pending: bool| {
        json!({"elapsed_us":time,"delivered":value,"credits":[value,value],
            "payments":[{"authorized_sat":value},{"authorized_sat":value}],
            "cleanup_pending":pending})
    };
    let baseline = sample(0, 0, true);
    let mut samples = vec![
        sample(1_000_000, 1, true),
        sample(1_500_000, 2, true),
        sample(2_000_000, 3, false),
    ];
    let report = progress(&baseline, &samples, 2_000_000);
    assert_eq!(report["all_counters_advanced"], true);
    assert_eq!(report["within_limit"], true);
    assert_eq!(report["progress_between_unfinished_cleanup_samples"], true);
    samples[0]["cleanup_pending"] = false.into();
    samples[1]["cleanup_pending"] = false.into();
    assert_eq!(
        progress(&baseline, &samples, 2_000_000)["progress_between_unfinished_cleanup_samples"],
        false
    );
    // A late catch-up must not hide one stalled hop, or an idle tail at the end.
    samples[0]["credits"][1] = 0.into();
    samples[1]["elapsed_us"] = 2_500_001.into();
    samples[2]["elapsed_us"] = 2_600_000.into();
    assert_eq!(
        progress(&baseline, &samples, 2_000_000)["within_limit"],
        false
    );
    samples = vec![sample(1, 1, false), sample(2_000_002, 1, false)];
    assert_eq!(
        progress(&baseline, &samples, 2_000_000)["within_limit"],
        false
    );
    samples = vec![sample(1, 0, true), sample(1_000_000, 0, false)];
    assert_eq!(
        progress(&baseline, &samples, 2_000_000)["all_counters_advanced"],
        false
    );
}
