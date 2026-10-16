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

    pub(super) fn finish(mut self) -> Value {
        self.sample();
        let after = counters(self.pid);
        self.peak_rss_kib = self.peak_rss_kib.max(after.rss_kib);
        let (held_us, released) = self.released.unwrap();
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
