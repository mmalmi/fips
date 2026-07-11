#[derive(Clone, Debug)]
pub(crate) struct OwnerConfig {
    generation: u64,
    in_flight_limit: usize,
    next_send_counter: u64,
    send_counter_authority: Option<crate::noise::SendCounterAuthority>,
    fmp_session_start_ms: Option<u64>,
    fmp_send_headers: Option<DataplaneFmpSendHeaders>,
    fmp_current_k_bit: Option<bool>,
    fmp_previous_draining_k_bit: Option<bool>,
    fmp_mmp: Option<DataplaneFmpMmpConfig>,
    fsp_session_start_ms: Option<u64>,
    fsp_send_headers: Option<DataplaneFspSendHeaders>,
    fsp_current_k_bit: Option<bool>,
    fsp_previous_draining_k_bit: Option<bool>,
    fsp_coords_warmup: Option<(u8, Vec<u8>)>,
    fsp_mmp: Option<DataplaneFspMmpConfig>,
    source_peer: Option<crate::PeerIdentity>,
}

#[derive(Clone, Debug)]
struct DataplaneFmpMmpConfig {
    config: crate::mmp::MmpConfig,
    is_initiator: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneFmpSendHeaders {
    receiver_idx: u32,
    flags: u8,
}

impl DataplaneFmpSendHeaders {
    pub(crate) fn new(receiver_idx: u32, flags: u8) -> Self {
        Self {
            receiver_idx,
            flags,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneFmpSendContext {
    generation: u64,
    receiver_idx: u32,
    flags: u8,
}

impl DataplaneFmpSendContext {
    fn new(generation: u64, headers: DataplaneFmpSendHeaders) -> Self {
        Self {
            generation,
            receiver_idx: headers.receiver_idx,
            flags: headers.flags,
        }
    }

    pub(crate) fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) fn receiver_idx(self) -> u32 {
        self.receiver_idx
    }

    pub(crate) fn flags(self) -> u8 {
        self.flags
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct DataplaneFmpReceiverReportResult {
    pub(crate) first_rtt: bool,
    pub(crate) srtt_ms: Option<f64>,
    pub(crate) loss_rate: f64,
    pub(crate) etx: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct DataplaneFmpLinkMetrics {
    pub(crate) node_addr: NodeAddr,
    pub(crate) mode: crate::mmp::MmpMode,
    pub(crate) spin_bit_initiator: bool,
    pub(crate) srtt_ms: Option<f64>,
    pub(crate) srtt_age_ms: Option<u64>,
    pub(crate) loss_rate: f64,
    pub(crate) loss_rate_for_log: Option<f64>,
    pub(crate) smoothed_loss: Option<f64>,
    pub(crate) etx: f64,
    pub(crate) smoothed_etx: Option<f64>,
    pub(crate) jitter_ms: f64,
    pub(crate) goodput_bps: f64,
    pub(crate) rtt_trend: Option<(f64, f64)>,
    pub(crate) loss_trend: Option<(f64, f64)>,
    pub(crate) goodput_trend: Option<(f64, f64)>,
    pub(crate) jitter_trend: Option<(f64, f64)>,
    pub(crate) delivery_ratio_forward: f64,
    pub(crate) delivery_ratio_reverse: f64,
    pub(crate) last_forward_loss_sample: Option<(u64, f64)>,
    pub(crate) tx_packets: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_packets: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) ecn_ce_count: u32,
    pub(crate) last_recv_age_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataplaneFmpMmpReportKind {
    Sender,
    Receiver,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataplaneFmpMmpReport {
    pub(crate) node_addr: NodeAddr,
    pub(crate) encoded: Vec<u8>,
    pub(crate) kind: DataplaneFmpMmpReportKind,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct DataplaneFmpMmpReportBatch {
    pub(crate) reports: Vec<DataplaneFmpMmpReport>,
    pub(crate) metric_logs: Vec<DataplaneFmpLinkMetrics>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataplaneFmpMmpSkip {
    UnknownOwner,
    MmpDisabled,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneFspSendHeaders {
    fsp_flags: u8,
    inner_flags: u8,
}

impl DataplaneFspSendHeaders {
    pub(crate) fn new(fsp_flags: u8, inner_flags: u8) -> Self {
        Self {
            fsp_flags,
            inner_flags,
        }
    }
}

#[derive(Clone, Debug)]
struct DataplaneFspMmpConfig {
    config: crate::config::SessionMmpConfig,
    is_initiator: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneFspSendContext {
    generation: u64,
    fsp_flags: u8,
    inner_flags: u8,
}

impl DataplaneFspSendContext {
    fn new(generation: u64, headers: DataplaneFspSendHeaders) -> Self {
        Self {
            generation,
            fsp_flags: headers.fsp_flags,
            inner_flags: headers.inner_flags,
        }
    }

    pub(crate) fn generation(self) -> u64 {
        self.generation
    }

    pub(crate) fn fsp_flags(self) -> u8 {
        self.fsp_flags
    }

    pub(crate) fn inner_flags(self) -> u8 {
        self.inner_flags
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DataplaneFspMmpReport {
    pub(crate) dest_addr: NodeAddr,
    pub(crate) msg_type: u8,
    pub(crate) encoded: Vec<u8>,
    pub(crate) prior_failures: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DataplaneFspMmpSnapshot {
    pub(crate) dest_addr: NodeAddr,
    pub(crate) fallback_session_name: String,
    pub(crate) mode: crate::mmp::MmpMode,
    pub(crate) rtt_ms: Option<f64>,
    pub(crate) loss_rate: f64,
    pub(crate) smoothed_loss: Option<f64>,
    pub(crate) last_forward_loss_sample: Option<(u64, f64)>,
    pub(crate) etx: f64,
    pub(crate) smoothed_etx: Option<f64>,
    pub(crate) goodput_bps: f64,
    pub(crate) delivery_ratio_forward: f64,
    pub(crate) delivery_ratio_reverse: f64,
    pub(crate) spin_bit_initiator: bool,
    pub(crate) send_mtu: u16,
    pub(crate) observed_mtu: u16,
    pub(crate) jitter_ms: f64,
    pub(crate) tx_packets: u64,
    pub(crate) tx_bytes: u64,
    pub(crate) rx_packets: u64,
    pub(crate) rx_bytes: u64,
    pub(crate) ecn_ce_count: u32,
}

impl DataplaneFspMmpSnapshot {
    fn from_mmp(
        dest_addr: NodeAddr,
        fallback_session_name: String,
        mmp: &crate::mmp::MmpSessionState,
    ) -> Self {
        let metrics = &mmp.metrics;
        Self {
            dest_addr,
            fallback_session_name,
            mode: mmp.mode(),
            rtt_ms: metrics.srtt_ms(),
            loss_rate: metrics.loss_rate(),
            smoothed_loss: metrics.smoothed_loss(),
            last_forward_loss_sample: metrics.last_forward_loss_sample(),
            etx: metrics.etx,
            smoothed_etx: metrics.smoothed_etx(),
            goodput_bps: metrics.goodput_bps(),
            delivery_ratio_forward: metrics.delivery_ratio_forward,
            delivery_ratio_reverse: metrics.delivery_ratio_reverse,
            spin_bit_initiator: mmp.spin_bit.is_initiator(),
            send_mtu: mmp.path_mtu.current_mtu(),
            observed_mtu: mmp.path_mtu.last_observed_mtu(),
            jitter_ms: mmp.receiver.jitter_us() as f64 / 1000.0,
            tx_packets: mmp.sender.cumulative_packets_sent(),
            tx_bytes: mmp.sender.cumulative_bytes_sent(),
            rx_packets: mmp.receiver.cumulative_packets_recv(),
            rx_bytes: mmp.receiver.cumulative_bytes_recv(),
            ecn_ce_count: metrics.last_ecn_ce_count(),
        }
    }

}

#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct DataplaneFspMmpReportBatch {
    pub(crate) reports: Vec<DataplaneFspMmpReport>,
    pub(crate) metric_logs: Vec<DataplaneFspMmpSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct DataplaneFspReceiverReportResult {
    pub(crate) sample: Option<(u64, f64)>,
    pub(crate) used_direct_next_hop: bool,
    pub(crate) srtt_ms: Option<f64>,
    pub(crate) mode: crate::mmp::MmpMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataplaneFspMmpSkip {
    UnknownOwner,
    MmpDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DataplaneFspPathMtuChange {
    pub(crate) old_mtu: u16,
    pub(crate) new_mtu: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataplaneFspPathMtuApplyResult {
    Changed(DataplaneFspPathMtuChange),
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DataplaneFspMmpReportingResumed {
    pub(crate) dest_addr: NodeAddr,
    pub(crate) consecutive_failures: u32,
}

impl OwnerConfig {
    pub(crate) fn new(generation: u64, in_flight_limit: usize) -> Self {
        Self {
            generation,
            in_flight_limit,
            next_send_counter: 0,
            send_counter_authority: None,
            fmp_session_start_ms: None,
            fmp_send_headers: None,
            fmp_current_k_bit: None,
            fmp_previous_draining_k_bit: None,
            fmp_mmp: None,
            fsp_session_start_ms: None,
            fsp_send_headers: None,
            fsp_current_k_bit: None,
            fsp_previous_draining_k_bit: None,
            fsp_coords_warmup: None,
            fsp_mmp: None,
            source_peer: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_next_send_counter(mut self, next_send_counter: u64) -> Self {
        self.next_send_counter = next_send_counter;
        self
    }

    pub(crate) fn with_send_counter_authority(
        mut self,
        authority: crate::noise::SendCounterAuthority,
    ) -> Self {
        self.next_send_counter = authority.current();
        self.send_counter_authority = Some(authority);
        self
    }

    pub(crate) fn with_fmp_session_start_ms(mut self, session_start_ms: u64) -> Self {
        self.fmp_session_start_ms = Some(session_start_ms);
        self
    }

    pub(crate) fn with_fmp_send_headers(mut self, receiver_idx: u32, flags: u8) -> Self {
        self.fmp_send_headers = Some(DataplaneFmpSendHeaders::new(receiver_idx, flags));
        self
    }

    pub(crate) fn with_fmp_epoch(
        mut self,
        current_k_bit: bool,
        previous_draining_k_bit: Option<bool>,
    ) -> Self {
        self.fmp_current_k_bit = Some(current_k_bit);
        self.fmp_previous_draining_k_bit = previous_draining_k_bit;
        self
    }

    pub(crate) fn with_fmp_mmp(mut self, config: crate::mmp::MmpConfig, is_initiator: bool) -> Self {
        self.fmp_mmp = Some(DataplaneFmpMmpConfig {
            config,
            is_initiator,
        });
        self
    }

    pub(crate) fn with_fsp_session_start_ms(mut self, session_start_ms: u64) -> Self {
        self.fsp_session_start_ms = Some(session_start_ms);
        self
    }

    pub(crate) fn with_fsp_send_headers(
        mut self,
        fsp_flags: u8,
        inner_flags: u8,
    ) -> Self {
        self.fsp_send_headers = Some(DataplaneFspSendHeaders::new(fsp_flags, inner_flags));
        self
    }

    pub(crate) fn with_fsp_epoch(
        mut self,
        current_k_bit: bool,
        previous_draining_k_bit: Option<bool>,
    ) -> Self {
        self.fsp_current_k_bit = Some(current_k_bit);
        self.fsp_previous_draining_k_bit = previous_draining_k_bit;
        self
    }

    pub(crate) fn with_fsp_coords_warmup(mut self, remaining: u8, prefix: Vec<u8>) -> Self {
        if remaining == 0 || prefix.is_empty() {
            self.fsp_coords_warmup = None;
        } else {
            self.fsp_coords_warmup = Some((remaining, prefix));
        }
        self
    }

    pub(crate) fn with_fsp_mmp(
        mut self,
        config: crate::config::SessionMmpConfig,
        is_initiator: bool,
    ) -> Self {
        self.fsp_mmp = Some(DataplaneFspMmpConfig {
            config,
            is_initiator,
        });
        self
    }

    pub(crate) fn with_source_peer(mut self, peer: crate::PeerIdentity) -> Self {
        self.source_peer = Some(peer);
        self
    }
}

#[derive(Clone)]
pub(crate) struct OwnerCryptoKeys {
    open: AeadKey,
    seal: AeadKey,
}

impl OwnerCryptoKeys {
    pub(crate) fn new(open: AeadKey, seal: AeadKey) -> Self {
        Self { open, seal }
    }
}

impl std::fmt::Debug for OwnerCryptoKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerCryptoKeys").finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct OrderToken(u64);

impl OrderToken {
    fn next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerReservation {
    owner: OwnerId,
    owner_shard: usize,
    generation: u64,
    order: OrderToken,
    ingress_seq: u64,
    counter: u64,
    class: PacketClass,
    lane: Lane,
    source_path: Option<TransportPath>,
    previous_hop: Option<NodeAddr>,
    ce_flag: bool,
    path_mtu: u16,
    wire_flags: u8,
    receive_k_bit: Option<bool>,
    source_peer: Option<crate::PeerIdentity>,
    output_path: Option<TransportPath>,
    activity_tick: Option<ActivityTick>,
    fmp_timestamp_ms: Option<u32>,
    fsp_timestamp_ms: Option<u32>,
    send_token: Option<u64>,
}

impl OwnerReservation {
    fn with_owner_shard(mut self, owner_shard: usize) -> Self {
        self.owner_shard = owner_shard;
        self
    }

    fn owner_shard(&self) -> usize {
        self.owner_shard
    }
}

#[derive(Debug)]
struct OwnerRetireSlot {
    slot: Arc<CryptoReadySlot>,
    order: OrderToken,
    results: Option<std::vec::IntoIter<CryptoOwnerRunItem>>,
}

impl OwnerRetireSlot {
    fn new(slot: Arc<CryptoReadySlot>) -> Self {
        let order = slot.first_order();
        Self {
            slot,
            order,
            results: None,
        }
    }

    fn is_ready(&self) -> bool {
        self.slot.is_ready()
    }

    fn generation(&self) -> u64 {
        self.slot.generation()
    }

    fn order(&self) -> OrderToken {
        self.order
    }

    fn lane(&self) -> Lane {
        self.slot.lane()
    }

    fn remaining(&self) -> usize {
        self.results
            .as_ref()
            .map_or_else(|| self.slot.len(), ExactSizeIterator::len)
    }

    fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn is_open_fsp_session_payload_run(&self) -> bool {
        self.slot.may_be_open_fsp_session_payload_run()
    }

    fn drain_results(
        &mut self,
        limit: usize,
        mut consume: impl FnMut(CryptoCompletion),
    ) -> usize {
        let drained = limit.min(self.remaining());
        for item in self.results().take(drained) {
            consume(item.into_completion());
        }
        self.order = OrderToken(self.order.0.wrapping_add(drained as u64));
        self.slot.retire(drained);
        drained
    }

    fn results(&mut self) -> &mut std::vec::IntoIter<CryptoOwnerRunItem> {
        if self.results.is_none() {
            self.results = Some(self.slot.take_results().into_iter());
        }
        self.results.as_mut().expect("owner results initialized")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerReserveError {
    Replay,
    InFlightFull,
    StaleGeneration,
    CounterExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerReserveBlockReason {
    TotalInFlight,
    BulkLane,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct DataplaneFspOwnerActivity {
    owner: NodeAddr,
    fsp_session_start_ms: Option<u64>,
    last_rx_activity: Option<ActivityTick>,
    last_rx_previous_hop: Option<NodeAddr>,
    last_rx_data_activity: Option<ActivityTick>,
    last_rx_data_previous_hop: Option<NodeAddr>,
    last_tx_data_activity: Option<ActivityTick>,
    last_outbound_next_hop: Option<NodeAddr>,
    current_k_bit: bool,
    previous_draining_k_bit: Option<bool>,
    current_epoch_confirmed: bool,
    send_counter: u64,
    current_path_mtu: Option<u16>,
    data_packets_sent: u64,
    data_packets_recv: u64,
    data_bytes_sent: u64,
    data_bytes_recv: u64,
}

impl DataplaneFspOwnerActivity {
    pub(crate) fn last_outbound_next_hop(self) -> Option<NodeAddr> {
        self.last_outbound_next_hop
    }

    pub(crate) fn last_rx_age_ms(self, now_ms: u64) -> Option<u64> {
        self.last_rx_activity.map(|tick| tick.age_ms(now_ms))
    }

    pub(crate) fn last_rx_data_age_ms(self, now_ms: u64) -> Option<u64> {
        self.last_rx_data_activity.map(|tick| tick.age_ms(now_ms))
    }

    pub(crate) fn has_recent_data_return_from(
        self,
        next_hop: &NodeAddr,
        now_ms: u64,
        timeout_ms: u64,
    ) -> bool {
        self.last_rx_data_previous_hop == Some(*next_hop)
            && self
                .last_rx_data_age_ms(now_ms)
                .is_some_and(|age_ms| age_ms <= timeout_ms)
    }

    pub(crate) fn fsp_session_start_ms(self) -> Option<u64> {
        self.fsp_session_start_ms
    }

    pub(crate) fn current_k_bit(self) -> bool {
        self.current_k_bit
    }

    pub(crate) fn is_draining(self) -> bool {
        self.previous_draining_k_bit.is_some()
    }

    pub(crate) fn current_epoch_confirmed(self) -> bool {
        self.current_epoch_confirmed
    }

    pub(crate) fn should_ignore_stale_epoch_decrypt_failure(self, received_k_bit: bool) -> bool {
        self.previous_draining_k_bit == Some(received_k_bit)
            && received_k_bit != self.current_k_bit
    }

    pub(crate) fn send_counter(self) -> u64 {
        self.send_counter
    }

    pub(crate) fn current_path_mtu(self) -> Option<u16> {
        self.current_path_mtu
    }

    pub(crate) fn has_recent_outbound_activity(self, now_ms: u64, timeout_ms: u64) -> bool {
        self.last_tx_data_activity
            .is_some_and(|tick| tick.age_ms(now_ms) <= timeout_ms)
    }

    pub(crate) fn has_recent_session_activity(self, now_ms: u64, timeout_ms: u64) -> bool {
        self.fsp_session_start_ms
            .is_some_and(|start_ms| now_ms.saturating_sub(start_ms) <= timeout_ms)
            || self
                .last_rx_data_activity
                .is_some_and(|tick| tick.age_ms(now_ms) <= timeout_ms)
            || self
                .last_tx_data_activity
                .is_some_and(|tick| tick.age_ms(now_ms) <= timeout_ms)
    }

    pub(crate) fn session_idle_activity_ms(self) -> Option<u64> {
        [
            self.fsp_session_start_ms,
            self.last_rx_data_activity.map(ActivityTick::get),
            self.last_tx_data_activity.map(ActivityTick::get),
        ]
        .into_iter()
        .flatten()
        .max()
    }

    pub(crate) fn has_stale_outbound_only_activity(self, now_ms: u64, timeout_ms: u64) -> bool {
        let last_inbound_ms = self
            .last_rx_activity
            .map(ActivityTick::get)
            .or(self.fsp_session_start_ms);
        self.data_packets_sent > 0
            && last_inbound_ms.is_some_and(|last_ms| now_ms.saturating_sub(last_ms) > timeout_ms)
    }

    pub(crate) fn has_recent_outbound_without_inbound(
        self,
        now_ms: u64,
        timeout_ms: u64,
    ) -> bool {
        let inbound_data_stale = self
            .last_rx_data_age_ms(now_ms)
            .is_none_or(|age_ms| age_ms > timeout_ms);
        self.data_packets_sent > 0
            && self.has_recent_outbound_activity(now_ms, timeout_ms)
            && inbound_data_stale
    }

    pub(crate) fn has_recent_outbound_without_data_return_from(
        self,
        next_hop: &NodeAddr,
        now_ms: u64,
        timeout_ms: u64,
    ) -> bool {
        self.data_packets_sent > 0
            && self.has_recent_outbound_activity(now_ms, timeout_ms)
            && !self.has_recent_data_return_from(next_hop, now_ms, timeout_ms)
    }

    fn tracks_next_hop(self, next_hop: &NodeAddr) -> bool {
        self.last_rx_previous_hop == Some(*next_hop) || self.tracks_outbound_next_hop(next_hop)
    }

    fn tracks_data_next_hop(self, next_hop: &NodeAddr) -> bool {
        self.last_rx_data_previous_hop == Some(*next_hop)
    }

    fn tracks_outbound_next_hop(self, next_hop: &NodeAddr) -> bool {
        self.last_outbound_next_hop == Some(*next_hop)
            || (self.owner == *next_hop && self.last_outbound_next_hop.is_none())
    }

    pub(crate) fn traffic_counters(self) -> (u64, u64, u64, u64) {
        (
            self.data_packets_sent,
            self.data_packets_recv,
            self.data_bytes_sent,
            self.data_bytes_recv,
        )
    }
}

#[derive(Debug)]
pub(crate) struct OwnerState {
    owner: OwnerId,
    generation: u64,
    in_flight_limit: usize,
    in_flight: usize,
    bulk_in_flight: usize,
    next_order: u64,
    next_retire: u64,
    next_send_counter: u64,
    send_counter_authority: Option<crate::noise::SendCounterAuthority>,
    crypto_keys: Option<OwnerCryptoKeys>,
    previous_fmp_open: Option<AeadKey>,
    pending_fmp_open: Option<AeadKey>,
    pending_fmp_k_bit: Option<bool>,
    pending_fmp_replay_window: Option<ReplayWindow>,
    previous_fsp_open: Option<AeadKey>,
    pending_fsp_open: Option<AeadKey>,
    pending_fsp_k_bit: Option<bool>,
    pending_fsp_replay_window: Option<ReplayWindow>,
    active_path: Option<TransportPath>,
    fmp_session_start_ms: Option<u64>,
    fmp_send_headers: Option<DataplaneFmpSendHeaders>,
    fmp_current_k_bit: bool,
    fmp_previous_draining_k_bit: Option<bool>,
    fmp_mmp: Option<crate::mmp::MmpPeerState>,
    fsp_session_start_ms: Option<u64>,
    fsp_send_headers: Option<DataplaneFspSendHeaders>,
    fsp_current_k_bit: bool,
    fsp_previous_draining_k_bit: Option<bool>,
    fsp_coords_warmup_remaining: u8,
    fsp_coords_prefix: Vec<u8>,
    fsp_wrap_route: Option<DataplaneFspWrapRoute>,
    fsp_mmp: Option<crate::mmp::MmpSessionState>,
    fsp_lifecycle_confirmed: bool,
    source_peer: Option<crate::PeerIdentity>,
    last_rx_activity: Option<ActivityTick>,
    last_rx_previous_hop: Option<NodeAddr>,
    last_rx_data_activity: Option<ActivityTick>,
    last_rx_data_previous_hop: Option<NodeAddr>,
    last_tx_activity: Option<ActivityTick>,
    last_tx_data_activity: Option<ActivityTick>,
    last_outbound_next_hop: Option<NodeAddr>,
    data_packets_sent: u64,
    data_packets_recv: u64,
    data_bytes_sent: u64,
    data_bytes_recv: u64,
    consecutive_decrypt_failures: u32,
    authenticated_counter_highest: u64,
    replay_window: ReplayWindow,
    pending_replay_counters: std::collections::HashSet<(bool, u64)>,
    previous_fmp_replay_window: Option<ReplayWindow>,
    previous_fsp_replay_window: Option<ReplayWindow>,
    pending: VecDeque<OwnerRetireSlot>,
}
