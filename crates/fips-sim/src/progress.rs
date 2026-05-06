use crate::SimConfig;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub(crate) struct ProgressReporter {
    state: Option<Arc<ProgressState>>,
}

pub(crate) struct ProgressSession {
    state: Option<Arc<ProgressState>>,
    stop: Option<Arc<(Mutex<bool>, Condvar)>>,
    handle: Option<thread::JoinHandle<()>>,
}

struct ProgressState {
    started_at: Instant,
    mode: String,
    node_count: usize,
    edge_count: usize,
    phase: Mutex<String>,
    stage: Mutex<String>,
    endpoint_total: AtomicUsize,
    endpoint_started: AtomicUsize,
    route_total: AtomicUsize,
    route_attempted: AtomicUsize,
    route_delivered: AtomicUsize,
    route_failed_send: AtomicUsize,
    route_timed_out: AtomicUsize,
    stream_total: AtomicUsize,
    stream_started: AtomicUsize,
    stream_setup_delivered: AtomicUsize,
    stream_setup_failed_send: AtomicUsize,
    stream_setup_timed_out: AtomicUsize,
    chunks_attempted: AtomicUsize,
    chunks_sent: AtomicUsize,
    chunks_send_failed: AtomicUsize,
    chunks_delivered: AtomicUsize,
    background_total: AtomicUsize,
    background_attempted: AtomicUsize,
    background_sent: AtomicUsize,
    background_failed_send: AtomicUsize,
}

impl ProgressSession {
    pub(crate) fn start(config: &SimConfig, edge_count: usize) -> Self {
        if config.progress_interval_ms == 0 {
            return Self {
                state: None,
                stop: None,
                handle: None,
            };
        }

        let interval = Duration::from_millis(config.progress_interval_ms.max(100));
        let state = Arc::new(ProgressState::new(config, edge_count));
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let thread_state = Arc::clone(&state);
        let thread_stop = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            loop {
                let (lock, condvar) = &*thread_stop;
                let stopped = lock.lock().expect("progress stop lock");
                let (stopped, _) = condvar
                    .wait_timeout(stopped, interval)
                    .expect("progress stop condvar");
                if *stopped {
                    break;
                }
                eprintln!("{}", thread_state.format_line());
            }
        });

        Self {
            state: Some(state),
            stop: Some(stop),
            handle: Some(handle),
        }
    }

    pub(crate) fn reporter(&self) -> ProgressReporter {
        ProgressReporter {
            state: self.state.clone(),
        }
    }
}

impl Drop for ProgressSession {
    fn drop(&mut self) {
        if let Some(stop) = &self.stop {
            let (lock, condvar) = &**stop;
            if let Ok(mut stopped) = lock.lock() {
                *stopped = true;
                condvar.notify_one();
            }
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl ProgressReporter {
    pub(crate) fn stage(&self, stage: &str) {
        if let Some(state) = &self.state {
            state.set_stage(stage);
        }
    }

    pub(crate) fn start_endpoints(&self, total: usize) {
        if let Some(state) = &self.state {
            state.set_phase("startup");
            state.set_stage("starting-endpoints");
            state.endpoint_total.store(total, Ordering::Relaxed);
            state.endpoint_started.store(0, Ordering::Relaxed);
        }
    }

    pub(crate) fn endpoint_started(&self, count: usize) {
        if let Some(state) = &self.state {
            state.endpoint_started.store(count, Ordering::Relaxed);
        }
    }

    pub(crate) fn start_phase(&self, label: &str, config: &SimConfig) {
        if let Some(state) = &self.state {
            state.set_phase(label);
            state.set_stage("traffic");
            state
                .route_total
                .store(config.route_probe_count, Ordering::Relaxed);
            state.route_attempted.store(0, Ordering::Relaxed);
            state.route_delivered.store(0, Ordering::Relaxed);
            state.route_failed_send.store(0, Ordering::Relaxed);
            state.route_timed_out.store(0, Ordering::Relaxed);
            state
                .stream_total
                .store(config.stream_probe_count, Ordering::Relaxed);
            state.stream_started.store(0, Ordering::Relaxed);
            state.stream_setup_delivered.store(0, Ordering::Relaxed);
            state.stream_setup_failed_send.store(0, Ordering::Relaxed);
            state.stream_setup_timed_out.store(0, Ordering::Relaxed);
            state.chunks_attempted.store(0, Ordering::Relaxed);
            state.chunks_sent.store(0, Ordering::Relaxed);
            state.chunks_send_failed.store(0, Ordering::Relaxed);
            state.chunks_delivered.store(0, Ordering::Relaxed);
            state
                .background_total
                .store(config.background_packet_count, Ordering::Relaxed);
            state.background_attempted.store(0, Ordering::Relaxed);
            state.background_sent.store(0, Ordering::Relaxed);
            state.background_failed_send.store(0, Ordering::Relaxed);
        }
    }

    pub(crate) fn route_attempted(&self) {
        self.add(|state| &state.route_attempted, 1);
    }

    pub(crate) fn route_delivered(&self) {
        self.add(|state| &state.route_delivered, 1);
    }

    pub(crate) fn route_failed_send(&self) {
        self.add(|state| &state.route_failed_send, 1);
    }

    pub(crate) fn route_timed_out(&self) {
        self.add(|state| &state.route_timed_out, 1);
    }

    pub(crate) fn stream_started(&self) {
        self.add(|state| &state.stream_started, 1);
    }

    pub(crate) fn stream_setup_delivered(&self) {
        self.add(|state| &state.stream_setup_delivered, 1);
    }

    pub(crate) fn stream_setup_failed_send(&self) {
        self.add(|state| &state.stream_setup_failed_send, 1);
    }

    pub(crate) fn stream_setup_timed_out(&self) {
        self.add(|state| &state.stream_setup_timed_out, 1);
    }

    pub(crate) fn chunks_attempted(&self, count: usize) {
        self.add(|state| &state.chunks_attempted, count);
    }

    pub(crate) fn chunk_sent(&self) {
        self.add(|state| &state.chunks_sent, 1);
    }

    pub(crate) fn chunk_send_failed(&self) {
        self.add(|state| &state.chunks_send_failed, 1);
    }

    pub(crate) fn chunks_delivered(&self, count: usize) {
        self.add(|state| &state.chunks_delivered, count);
    }

    pub(crate) fn background_attempted(&self) {
        self.add(|state| &state.background_attempted, 1);
    }

    pub(crate) fn background_sent(&self) {
        self.add(|state| &state.background_sent, 1);
    }

    pub(crate) fn background_failed_send(&self) {
        self.add(|state| &state.background_failed_send, 1);
    }

    fn add(&self, field: fn(&ProgressState) -> &AtomicUsize, count: usize) {
        if let Some(state) = &self.state {
            field(state).fetch_add(count, Ordering::Relaxed);
        }
    }
}

impl ProgressState {
    fn new(config: &SimConfig, edge_count: usize) -> Self {
        Self {
            started_at: Instant::now(),
            mode: config.routing_mode.to_string(),
            node_count: config.node_count,
            edge_count,
            phase: Mutex::new("startup".to_string()),
            stage: Mutex::new("initializing".to_string()),
            endpoint_total: AtomicUsize::new(config.node_count),
            endpoint_started: AtomicUsize::new(0),
            route_total: AtomicUsize::new(config.route_probe_count),
            route_attempted: AtomicUsize::new(0),
            route_delivered: AtomicUsize::new(0),
            route_failed_send: AtomicUsize::new(0),
            route_timed_out: AtomicUsize::new(0),
            stream_total: AtomicUsize::new(config.stream_probe_count),
            stream_started: AtomicUsize::new(0),
            stream_setup_delivered: AtomicUsize::new(0),
            stream_setup_failed_send: AtomicUsize::new(0),
            stream_setup_timed_out: AtomicUsize::new(0),
            chunks_attempted: AtomicUsize::new(0),
            chunks_sent: AtomicUsize::new(0),
            chunks_send_failed: AtomicUsize::new(0),
            chunks_delivered: AtomicUsize::new(0),
            background_total: AtomicUsize::new(config.background_packet_count),
            background_attempted: AtomicUsize::new(0),
            background_sent: AtomicUsize::new(0),
            background_failed_send: AtomicUsize::new(0),
        }
    }

    fn set_phase(&self, phase: &str) {
        if let Ok(mut current) = self.phase.lock() {
            *current = phase.to_string();
        }
    }

    fn set_stage(&self, stage: &str) {
        if let Ok(mut current) = self.stage.lock() {
            *current = stage.to_string();
        }
    }

    fn format_line(&self) -> String {
        let phase = self
            .phase
            .lock()
            .map(|value| value.clone())
            .unwrap_or_else(|_| "unknown".to_string());
        let stage = self
            .stage
            .lock()
            .map(|value| value.clone())
            .unwrap_or_else(|_| "unknown".to_string());
        let load = |counter: &AtomicUsize| counter.load(Ordering::Relaxed);
        format!(
            "fips-sim progress: wall={}s mode={} nodes={} edges={} phase={} stage={} endpoints={}/{} route={}/{} delivered={} timed_out={} failed_send={} streams={}/{} setup={} setup_timeout={} setup_failed={} chunks_sent={}/{} chunks_delivered={} chunk_send_failed={} bg={}/{} bg_sent={} bg_failed={}",
            self.started_at.elapsed().as_secs(),
            self.mode,
            self.node_count,
            self.edge_count,
            phase,
            stage,
            load(&self.endpoint_started),
            load(&self.endpoint_total),
            load(&self.route_attempted),
            load(&self.route_total),
            load(&self.route_delivered),
            load(&self.route_timed_out),
            load(&self.route_failed_send),
            load(&self.stream_started),
            load(&self.stream_total),
            load(&self.stream_setup_delivered),
            load(&self.stream_setup_timed_out),
            load(&self.stream_setup_failed_send),
            load(&self.chunks_sent),
            load(&self.chunks_attempted),
            load(&self.chunks_delivered),
            load(&self.chunks_send_failed),
            load(&self.background_attempted),
            load(&self.background_total),
            load(&self.background_sent),
            load(&self.background_failed_send),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SimConfig;

    #[test]
    fn progress_line_reports_phase_and_counters() {
        let config = SimConfig {
            node_count: 10,
            target_edges: 20,
            route_probe_count: 3,
            stream_probe_count: 2,
            background_packet_count: 5,
            progress_interval_ms: 10_000,
            ..SimConfig::default()
        };
        let state = Arc::new(ProgressState::new(&config, 20));
        let reporter = ProgressReporter {
            state: Some(Arc::clone(&state)),
        };

        reporter.start_endpoints(10);
        reporter.endpoint_started(4);
        reporter.start_phase("baseline", &config);
        reporter.route_attempted();
        reporter.route_delivered();
        reporter.stream_started();
        reporter.stream_setup_delivered();
        reporter.chunks_attempted(8);
        reporter.chunk_sent();
        reporter.chunks_delivered(1);
        reporter.background_attempted();
        reporter.background_sent();

        let line = state.format_line();
        assert!(line.contains("phase=baseline"));
        assert!(line.contains("endpoints=4/10"));
        assert!(line.contains("route=1/3"));
        assert!(line.contains("streams=1/2"));
        assert!(line.contains("chunks_sent=1/8"));
        assert!(line.contains("bg=1/5"));
    }
}
