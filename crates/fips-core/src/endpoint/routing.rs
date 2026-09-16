//! Explicit application source-route choice, backed by native FSP measurements.
use super::*;

#[derive(Clone, Debug, Default)]
pub struct SourceRouteQuality {
    /// Actual most recent outbound carrier, not an advertised route.
    pub next_hop: Option<NodeAddr>,
    /// Whether session receiver reports are enabled. Minimal mode instead
    /// relies on native data-return evidence, which cannot verify one-way delivery.
    pub receiver_reports_enabled: bool,
    /// Native recent delivery evidence. This is a routing signal, not a receipt
    /// proving individual packet delivery or honest behavior by every hop.
    pub has_recent_delivery_feedback: bool,
    /// An unanswered outbound burst exceeded the caller's feedback window.
    pub delivery_feedback_timed_out: bool,
    /// Session-smoothed RTT; its history may include previous paths. Numerical
    /// estimates are omitted when native delivery feedback is stale or absent.
    pub rtt_ms: Option<f64>,
    /// Most recent forward-loss sample, when available, as a fraction (0..1).
    pub loss_rate: Option<f64>,
    /// Session estimate of useful bytes per second, not a capacity guarantee.
    pub goodput_bps: Option<f64>,
    /// Session application-data totals; rebinding does not reset these counters.
    pub sent_packets: u64,
    pub sent_bytes: u64,
}

impl FipsEndpoint {
    /// Bind the first hop of locally originated session payload and reports.
    /// Transit routing is unchanged. The caller must validate the complete path
    /// and any financial authority first. At most 64 bindings are retained.
    /// A missing chosen peer fails closed; None restores native route choice.
    /// Binding resets feedback attribution, including when the next hop is unchanged.
    /// Bindings are volatile and persist until explicitly changed or cleared.
    /// Already admitted in-flight packets may still use the previous carrier.
    /// Noise setup/replies retain their native handshake routing rules.
    pub async fn set_source_route(
        &self,
        destination: PeerIdentity,
        next_hop: Option<PeerIdentity>,
    ) -> Result<(), FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.control(
            "source route binding",
            NodeEndpointControlCommand::SetSourceRoute {
                destination,
                next_hop,
                response_tx,
            },
            response_rx,
        )
        .await?
        .map_err(FipsEndpointError::Node)
    }

    /// Native receiver-report quality attributed to the actual outbound carrier.
    /// A timed-out unanswered burst remains failed even if the sender goes idle.
    /// Missing feedback is unknown, rather than a zero-loss measurement.
    /// The window is clamped to 50 ms..60 s; choose one long enough for the
    /// configured report cadence and path latency (session intervals reach 10 s).
    pub async fn source_route_quality(
        &self,
        destination: PeerIdentity,
        feedback_window: Duration,
    ) -> Result<SourceRouteQuality, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.control(
            "source route quality",
            NodeEndpointControlCommand::SourceRouteQuality {
                destination: *destination.node_addr(),
                feedback_window_ms: feedback_window.as_millis().clamp(50, 60_000) as u64,
                response_tx,
            },
            response_rx,
        )
        .await
    }
}
