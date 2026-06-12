use super::TorTransport;
use std::time::Duration;
use tokio::time::Instant;
use tracing::{info, warn};

impl TorTransport {
    /// Spawn a background task that periodically queries the Tor control
    /// port for daemon status and caches the result.
    pub(super) fn spawn_monitoring_task(&mut self) {
        let Some(client) = self.control_client.clone() else {
            return;
        };
        let cache = self.cached_monitoring.clone();
        let stats = self.stats.clone();
        let transport_id = self.transport_id;

        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(10));
            let mut last_bootstrap: u8 = 0;
            let mut last_liveness = String::new();
            let mut was_dormant = false;
            let mut stall_warned = false;
            let started_at = Instant::now();

            loop {
                interval.tick().await;
                let mut guard = client.lock().await;
                match guard.monitoring_snapshot().await {
                    Ok(info) => {
                        // Log bootstrap milestones
                        for &milestone in &[25u8, 50, 75, 100] {
                            if info.bootstrap >= milestone && last_bootstrap < milestone {
                                info!(
                                    transport_id = %transport_id,
                                    bootstrap = info.bootstrap,
                                    "Tor bootstrap {}%",
                                    milestone
                                );
                            }
                        }

                        // Bootstrap stall warning
                        if info.bootstrap < 100
                            && started_at.elapsed() > Duration::from_secs(60)
                            && !stall_warned
                        {
                            warn!(
                                transport_id = %transport_id,
                                bootstrap = info.bootstrap,
                                "Tor bootstrap stalled — not at 100% after 60s"
                            );
                            stall_warned = true;
                        }
                        if info.bootstrap == 100 {
                            stall_warned = false;
                        }

                        last_bootstrap = info.bootstrap;

                        // Network liveness transitions
                        if !last_liveness.is_empty() && info.network_liveness != last_liveness {
                            warn!(
                                transport_id = %transport_id,
                                from = %last_liveness,
                                to = %info.network_liveness,
                                "Tor network liveness changed"
                            );
                        }
                        last_liveness = info.network_liveness.clone();

                        // Dormant mode entry
                        if info.dormant && !was_dormant {
                            warn!(
                                transport_id = %transport_id,
                                "Tor daemon entered dormant mode"
                            );
                        }
                        was_dormant = info.dormant;

                        if let Ok(mut w) = cache.write() {
                            *w = Some(info);
                        }
                    }
                    Err(e) => {
                        stats.record_control_error();
                        warn!(
                            transport_id = %transport_id,
                            error = %e,
                            "Tor monitoring query failed"
                        );
                    }
                }
            }
        });

        self.monitoring_task = Some(handle);
    }
}
