use super::*;
use crate::endpoint::SourceRouteQuality;

impl Node {
    pub(in crate::node) fn set_endpoint_source_route(
        &mut self,
        destination: PeerIdentity,
        next: Option<PeerIdentity>,
    ) -> Result<(), NodeError> {
        let dest = *destination.node_addr();
        if dest == *self.node_addr() {
            return Err(NodeError::LocalRouteUnavailable("local destination".into()));
        }
        if next.is_none() && !self.source_routes.contains_key(&dest) {
            return Ok(());
        }
        if let Some(next) = next {
            if !self
                .peers
                .get(next.node_addr())
                .is_some_and(|p| p.can_send())
            {
                return Err(NodeError::PeerNotFound(*next.node_addr()));
            }
            if self.source_routes.len() >= 64 && !self.source_routes.contains_key(&dest) {
                return Err(NodeError::LocalRouteUnavailable(
                    "source route capacity".into(),
                ));
            }
        }
        if !self.register_endpoint_identity(dest, destination.pubkey_full()) {
            return Err(NodeError::LocalRouteUnavailable("identity capacity".into()));
        }
        let old: Vec<_> = [
            self.dataplane.fsp_owner_next_hop(&dest),
            self.dataplane
                .fsp_owner_activity(&dest)
                .and_then(|activity| activity.last_outbound_next_hop()),
        ]
        .into_iter()
        .flatten()
        .collect();
        match next {
            Some(next) => {
                self.source_routes.insert(dest, *next.node_addr());
            }
            None => {
                self.source_routes.remove(&dest);
            }
        }
        self.dataplane.invalidate_fsp_carrier_activity(dest, &old);
        // Do not retain the old fast-path carrier when rebinding a paid path.
        self.dataplane.clear_fsp_output_route(dest);
        self.refresh_dataplane_fsp_owner_routes(&dest);
        Ok(())
    }

    pub(in crate::node) fn endpoint_source_route_quality(
        &self,
        destination: NodeAddr,
        window: u64,
    ) -> SourceRouteQuality {
        let Some(activity) = self.dataplane.fsp_owner_activity(&destination) else {
            return SourceRouteQuality::default();
        };
        let next_hop = activity.last_outbound_next_hop();
        let now = Self::now_ms();
        let fresh = next_hop
            .is_some_and(|next| activity.has_recent_delivery_feedback_from(&next, now, window));
        let timed_out = next_hop
            .is_some_and(|next| activity.has_unacknowledged_outbound_from(&next, now, window));
        let snapshot = self.dataplane.fsp_mmp_snapshot(&destination);
        let receiver_reports_enabled = snapshot
            .as_ref()
            .is_some_and(|m| m.mode != crate::mmp::MmpMode::Minimal);
        let metrics = snapshot.filter(|_| fresh);
        SourceRouteQuality {
            next_hop,
            has_recent_delivery_feedback: fresh,
            delivery_feedback_timed_out: timed_out,
            receiver_reports_enabled,
            rtt_ms: metrics.as_ref().and_then(|m| m.rtt_ms),
            loss_rate: metrics
                .as_ref()
                .filter(|m| m.last_forward_loss_age_ms.is_some_and(|age| age <= window))
                .and_then(|m| m.last_forward_loss_sample.map(|(_, loss)| loss)),
            goodput_bps: metrics.as_ref().map(|m| m.goodput_bps),
            sent_packets: activity.traffic_counters().0,
            sent_bytes: activity.traffic_counters().2,
        }
    }
}
