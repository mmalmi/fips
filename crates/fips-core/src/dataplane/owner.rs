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
    previous_fmp_replay_window: Option<ReplayWindow>,
    previous_fsp_replay_window: Option<ReplayWindow>,
    pending: VecDeque<OwnerRetireSlot>,
}

impl OwnerState {
    pub(crate) fn new(owner: OwnerId, config: OwnerConfig) -> Self {
        Self {
            owner,
            generation: config.generation,
            in_flight_limit: config.in_flight_limit,
            in_flight: 0,
            bulk_in_flight: 0,
            next_order: 0,
            next_retire: 0,
            next_send_counter: config.next_send_counter,
            send_counter_authority: config.send_counter_authority,
            crypto_keys: None,
            previous_fmp_open: None,
            pending_fmp_open: None,
            pending_fmp_k_bit: None,
            pending_fmp_replay_window: None,
            previous_fsp_open: None,
            pending_fsp_open: None,
            pending_fsp_k_bit: None,
            pending_fsp_replay_window: None,
            active_path: None,
            fmp_session_start_ms: config.fmp_session_start_ms,
            fmp_send_headers: config.fmp_send_headers,
            fmp_current_k_bit: config.fmp_current_k_bit.unwrap_or(false),
            fmp_previous_draining_k_bit: config.fmp_previous_draining_k_bit,
            fmp_mmp: config
                .fmp_mmp
                .map(|mmp| crate::mmp::MmpPeerState::new(&mmp.config, mmp.is_initiator)),
            fsp_session_start_ms: config.fsp_session_start_ms,
            fsp_send_headers: config.fsp_send_headers,
            fsp_current_k_bit: config.fsp_current_k_bit.unwrap_or(false),
            fsp_previous_draining_k_bit: config.fsp_previous_draining_k_bit,
            fsp_coords_warmup_remaining: config
                .fsp_coords_warmup
                .as_ref()
                .map_or(0, |(remaining, _)| *remaining),
            fsp_coords_prefix: config
                .fsp_coords_warmup
                .map_or_else(Vec::new, |(_, prefix)| prefix),
            fsp_wrap_route: None,
            fsp_mmp: config
                .fsp_mmp
                .map(|mmp| crate::mmp::MmpSessionState::new(&mmp.config, mmp.is_initiator)),
            fsp_lifecycle_confirmed: false,
            source_peer: config.source_peer,
            last_rx_activity: None,
            last_rx_previous_hop: None,
            last_rx_data_activity: None,
            last_rx_data_previous_hop: None,
            last_tx_activity: None,
            last_tx_data_activity: None,
            last_outbound_next_hop: None,
            data_packets_sent: 0,
            data_packets_recv: 0,
            data_bytes_sent: 0,
            data_bytes_recv: 0,
            consecutive_decrypt_failures: 0,
            authenticated_counter_highest: 0,
            replay_window: ReplayWindow::default(),
            previous_fmp_replay_window: None,
            previous_fsp_replay_window: None,
            pending: VecDeque::new(),
        }
    }

    pub(crate) fn rekey(&mut self, generation: u64) {
        self.generation = generation;
        self.replay_window.clear();
        self.next_send_counter = 0;
        self.send_counter_authority = None;
        self.crypto_keys = None;
        self.previous_fmp_open = None;
        self.pending_fmp_open = None;
        self.pending_fmp_k_bit = None;
        self.pending_fmp_replay_window = None;
        self.previous_fsp_open = None;
        self.pending_fsp_open = None;
        self.pending_fsp_k_bit = None;
        self.pending_fsp_replay_window = None;
        self.fmp_session_start_ms = None;
        self.fmp_send_headers = None;
        self.fmp_current_k_bit = false;
        self.fmp_previous_draining_k_bit = None;
        if let Some(mmp) = &mut self.fmp_mmp {
            mmp.reset_for_rekey(std::time::Instant::now());
        }
        self.fsp_session_start_ms = None;
        self.fsp_send_headers = None;
        self.fsp_current_k_bit = false;
        self.fsp_previous_draining_k_bit = None;
        self.fsp_coords_warmup_remaining = 0;
        self.fsp_coords_prefix.clear();
        self.fsp_wrap_route = None;
        if let Some(mmp) = &mut self.fsp_mmp {
            mmp.reset_for_rekey(std::time::Instant::now());
        }
        self.fsp_lifecycle_confirmed = false;
        self.source_peer = None;
        self.last_rx_activity = None;
        self.last_rx_previous_hop = None;
        self.last_rx_data_activity = None;
        self.last_rx_data_previous_hop = None;
        self.last_tx_data_activity = None;
        self.last_outbound_next_hop = None;
        self.data_packets_sent = 0;
        self.data_packets_recv = 0;
        self.data_bytes_sent = 0;
        self.data_bytes_recv = 0;
        self.consecutive_decrypt_failures = 0;
        self.authenticated_counter_highest = 0;
        self.previous_fmp_replay_window = None;
        self.previous_fsp_replay_window = None;
    }

    #[cfg(test)]
    pub(crate) fn set_crypto_keys(&mut self, keys: OwnerCryptoKeys) {
        self.crypto_keys = Some(keys);
    }

    pub(crate) fn install_fmp_session(
        &mut self,
        config: OwnerConfig,
        keys: OwnerCryptoKeys,
    ) -> bool {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return false;
        }

        let generation_changed = config.generation != self.generation;
        let previous_epoch = generation_changed && config.fmp_previous_draining_k_bit.is_some();
        let promoted_pending_replay =
            (generation_changed && config.fmp_current_k_bit == self.pending_fmp_k_bit)
                .then(|| self.pending_fmp_replay_window.take())
                .flatten();
        let previous_open = previous_epoch
            .then(|| self.crypto_keys.as_ref().map(|old_keys| old_keys.open.clone()))
            .flatten();
        let previous_replay = previous_open
            .is_some()
            .then(|| std::mem::take(&mut self.replay_window));

        self.apply_live_config(config);
        self.crypto_keys = Some(keys);
        if let Some(replay) = promoted_pending_replay {
            self.replay_window = replay;
            self.pending_fmp_open = None;
            self.pending_fmp_k_bit = None;
            self.pending_fmp_replay_window = None;
        }
        if let (Some(open), Some(replay)) = (previous_open, previous_replay) {
            self.previous_fmp_open = Some(open);
            self.previous_fmp_replay_window = Some(replay);
        } else if self.fmp_previous_draining_k_bit.is_none() {
            self.previous_fmp_open = None;
            self.previous_fmp_replay_window = None;
        }
        true
    }

    pub(crate) fn install_fsp_session(
        &mut self,
        config: OwnerConfig,
        keys: OwnerCryptoKeys,
    ) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return false;
        }

        let generation_changed = config.generation != self.generation;
        let previous_epoch = generation_changed && config.fsp_previous_draining_k_bit.is_some();
        let promoted_pending_replay =
            (generation_changed && self.pending_fsp_k_bit == config.fsp_current_k_bit)
                .then(|| self.pending_fsp_replay_window.take())
                .flatten();
        let previous_open = previous_epoch
            .then(|| self.crypto_keys.as_ref().map(|old_keys| old_keys.open.clone()))
            .flatten();
        let previous_replay = previous_open
            .is_some()
            .then(|| std::mem::take(&mut self.replay_window));

        self.apply_live_config(config);
        self.crypto_keys = Some(keys);
        if let Some(replay) = promoted_pending_replay {
            self.replay_window = replay;
            self.pending_fsp_open = None;
            self.pending_fsp_k_bit = None;
            self.pending_fsp_replay_window = None;
        }
        if let (Some(open), Some(replay)) = (previous_open, previous_replay) {
            self.previous_fsp_open = Some(open);
            self.previous_fsp_replay_window = Some(replay);
        } else if self.fsp_previous_draining_k_bit.is_none() {
            self.previous_fsp_open = None;
            self.previous_fsp_replay_window = None;
        }
        true
    }

    pub(crate) fn install_fmp_pending_receive_epoch(
        &mut self,
        pending_k_bit: bool,
        open: AeadKey,
    ) -> bool {
        if self.owner.protocol() != PacketProtocol::Fmp || pending_k_bit == self.fmp_current_k_bit
        {
            return false;
        }
        self.pending_fmp_open = Some(open);
        self.pending_fmp_k_bit = Some(pending_k_bit);
        self.pending_fmp_replay_window = Some(ReplayWindow::default());
        true
    }

    pub(crate) fn has_fmp_pending_receive_epoch(&self, received_k_bit: bool) -> bool {
        self.owner.protocol() == PacketProtocol::Fmp
            && self.pending_fmp_k_bit == Some(received_k_bit)
            && self.pending_fmp_open.is_some()
            && self.pending_fmp_replay_window.is_some()
    }

    pub(crate) fn install_fsp_pending_receive_epoch(
        &mut self,
        pending_k_bit: bool,
        open: AeadKey,
    ) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp || pending_k_bit == self.fsp_current_k_bit
        {
            return false;
        }
        self.pending_fsp_open = Some(open);
        self.pending_fsp_k_bit = Some(pending_k_bit);
        self.pending_fsp_replay_window = Some(ReplayWindow::default());
        true
    }

    pub(crate) fn has_fsp_pending_receive_epoch(&self, received_k_bit: bool) -> bool {
        self.owner.protocol() == PacketProtocol::Fsp
            && self.pending_fsp_k_bit == Some(received_k_bit)
            && self.pending_fsp_open.is_some()
            && self.pending_fsp_replay_window.is_some()
    }

    pub(crate) fn set_fmp_epoch(
        &mut self,
        current_k_bit: bool,
        previous_draining_k_bit: Option<bool>,
    ) -> bool {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return false;
        }
        self.fmp_current_k_bit = current_k_bit;
        self.fmp_previous_draining_k_bit = previous_draining_k_bit;
        if previous_draining_k_bit.is_none() {
            self.previous_fmp_open = None;
            self.previous_fmp_replay_window = None;
        }
        if self.pending_fmp_k_bit == Some(current_k_bit) {
            self.pending_fmp_open = None;
            self.pending_fmp_k_bit = None;
            self.pending_fmp_replay_window = None;
        }
        true
    }

    pub(crate) fn set_fsp_epoch(
        &mut self,
        current_k_bit: bool,
        previous_draining_k_bit: Option<bool>,
    ) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return false;
        }
        self.fsp_current_k_bit = current_k_bit;
        self.fsp_previous_draining_k_bit = previous_draining_k_bit;
        if previous_draining_k_bit.is_none() {
            self.previous_fsp_open = None;
            self.previous_fsp_replay_window = None;
        }
        if self.pending_fsp_k_bit == Some(current_k_bit) {
            self.pending_fsp_open = None;
            self.pending_fsp_k_bit = None;
            self.pending_fsp_replay_window = None;
        }
        true
    }

    pub(crate) fn set_fsp_wrap_route(&mut self, route: Option<DataplaneFspWrapRoute>) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return false;
        }
        self.fsp_wrap_route = route;
        true
    }

    pub(crate) fn set_fsp_coords_warmup(&mut self, remaining: u8, prefix: Vec<u8>) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return false;
        }
        if remaining == 0 || prefix.is_empty() {
            self.fsp_coords_warmup_remaining = 0;
            self.fsp_coords_prefix.clear();
        } else {
            self.fsp_coords_warmup_remaining = remaining;
            self.fsp_coords_prefix = prefix;
        }
        true
    }

    pub(crate) fn apply_live_config(&mut self, config: OwnerConfig) {
        if config.generation != self.generation {
            self.rekey(config.generation);
        }
        if let Some(authority) = config.send_counter_authority {
            self.set_send_counter_authority(authority);
        }
        if let Some(session_start_ms) = config.fmp_session_start_ms {
            self.fmp_session_start_ms = Some(session_start_ms);
        }
        if let Some(headers) = config.fmp_send_headers {
            self.fmp_send_headers = Some(headers);
        }
        if let Some(current_k_bit) = config.fmp_current_k_bit {
            self.set_fmp_epoch(current_k_bit, config.fmp_previous_draining_k_bit);
        }
        if self.fmp_mmp.is_none()
            && let Some(mmp) = config.fmp_mmp
        {
            self.fmp_mmp = Some(crate::mmp::MmpPeerState::new(
                &mmp.config,
                mmp.is_initiator,
            ));
        }
        if let Some(session_start_ms) = config.fsp_session_start_ms {
            self.fsp_session_start_ms = Some(session_start_ms);
        }
        if let Some(headers) = config.fsp_send_headers {
            self.fsp_send_headers = Some(headers);
        }
        if let Some(current_k_bit) = config.fsp_current_k_bit {
            self.set_fsp_epoch(current_k_bit, config.fsp_previous_draining_k_bit);
        }
        if let Some(peer) = config.source_peer {
            self.source_peer = Some(peer);
        }
        if self.fsp_mmp.is_none()
            && let Some(mmp) = config.fsp_mmp
        {
            self.fsp_mmp = Some(crate::mmp::MmpSessionState::new(
                &mmp.config,
                mmp.is_initiator,
            ));
        }
        // Coords warmup is transferred into the owner once; ordinary live
        // refreshes must not reload or erase the owner-local budget.
        if let Some((remaining, prefix)) = config.fsp_coords_warmup {
            self.fsp_coords_warmup_remaining = remaining;
            self.fsp_coords_prefix = prefix;
        }
    }

    pub(crate) fn set_send_counter_authority(
        &mut self,
        authority: crate::noise::SendCounterAuthority,
    ) {
        self.next_send_counter = authority.current();
        self.send_counter_authority = Some(authority);
    }

    fn seal_key(&self) -> Option<AeadKey> {
        self.crypto_keys.as_ref().map(|keys| keys.seal.clone())
    }

    fn open_key(&self, epoch: DataplaneReceiveEpoch) -> Option<AeadKey> {
        match (self.owner.protocol(), epoch) {
            (PacketProtocol::Fmp, DataplaneReceiveEpoch::Previous) => {
                self.previous_fmp_open.clone()
            }
            (PacketProtocol::Fmp, DataplaneReceiveEpoch::Pending) => {
                self.pending_fmp_open.clone()
            }
            (PacketProtocol::Fsp, DataplaneReceiveEpoch::Previous) => {
                self.previous_fsp_open.clone()
            }
            (PacketProtocol::Fsp, DataplaneReceiveEpoch::Pending) => {
                self.pending_fsp_open.clone()
            }
            (_, DataplaneReceiveEpoch::Current) => {
                self.crypto_keys.as_ref().map(|keys| keys.open.clone())
            }
        }
    }

    fn uses_previous_fmp_receive_epoch(&self, packet: &SocketPacket) -> bool {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return false;
        }
        if packet.receive_epoch == DataplaneReceiveEpoch::Previous {
            return self.previous_fmp_open.is_some() && self.previous_fmp_replay_window.is_some();
        }
        let received_k_bit = packet.wire_flags & crate::node::wire::FLAG_KEY_EPOCH != 0;
        self.fmp_previous_draining_k_bit == Some(received_k_bit)
            && received_k_bit != self.fmp_current_k_bit
            && self.previous_fmp_open.is_some()
            && self.previous_fmp_replay_window.is_some()
    }

    fn uses_pending_fmp_receive_epoch(&self, packet: &SocketPacket) -> bool {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return false;
        }
        if packet.receive_epoch == DataplaneReceiveEpoch::Pending {
            return self.pending_fmp_open.is_some() && self.pending_fmp_replay_window.is_some();
        }
        let received_k_bit = packet.wire_flags & crate::node::wire::FLAG_KEY_EPOCH != 0;
        self.pending_fmp_k_bit == Some(received_k_bit)
            && received_k_bit != self.fmp_current_k_bit
            && self.pending_fmp_open.is_some()
            && self.pending_fmp_replay_window.is_some()
    }

    fn uses_previous_fsp_receive_epoch(&self, packet: &SocketPacket) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return false;
        }
        let received_k_bit = packet.wire_flags & crate::node::session_wire::FSP_FLAG_K != 0;
        self.fsp_previous_draining_k_bit == Some(received_k_bit)
            && received_k_bit != self.fsp_current_k_bit
            && self.previous_fsp_open.is_some()
            && self.previous_fsp_replay_window.is_some()
    }

    fn uses_pending_fsp_receive_epoch(&self, packet: &SocketPacket) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return false;
        }
        let received_k_bit = packet.wire_flags & crate::node::session_wire::FSP_FLAG_K != 0;
        self.pending_fsp_k_bit == Some(received_k_bit)
            && received_k_bit != self.fsp_current_k_bit
            && self.pending_fsp_open.is_some()
            && self.pending_fsp_replay_window.is_some()
    }

    pub(crate) fn set_active_path(&mut self, path: TransportPath) {
        self.active_path = Some(path);
    }

    pub(crate) fn clear_active_path(&mut self) {
        self.active_path = None;
    }

    pub(crate) fn active_path(&self) -> Option<TransportPath> {
        self.active_path.clone()
    }

    pub(crate) fn fsp_wrap_next_hop(&self) -> Option<NodeAddr> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        self.fsp_wrap_route
            .map(DataplaneFspWrapRoute::next_hop_addr)
            .or_else(|| self.active_path.as_ref().map(|_| self.owner.node_addr()))
    }

    pub(crate) fn fmp_send_context(&self) -> Option<DataplaneFmpSendContext> {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return None;
        }
        let mut headers = self.fmp_send_headers?;
        if let Some(mmp) = &self.fmp_mmp
            && mmp.spin_bit.tx_bit()
        {
            headers.flags |= crate::node::wire::FLAG_SP;
        }
        Some(DataplaneFmpSendContext::new(self.generation, headers))
    }

    pub(crate) fn fsp_send_context(&self) -> Option<DataplaneFspSendContext> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        let mut headers = self.fsp_send_headers?;
        if let Some(mmp) = &self.fsp_mmp {
            headers.inner_flags = crate::protocol::FspInnerFlags {
                spin_bit: mmp.spin_bit.tx_bit(),
            }
            .to_byte();
        }
        Some(DataplaneFspSendContext::new(self.generation, headers))
    }

    pub(crate) fn can_reserve_class(&self, class: PacketClass) -> bool {
        self.reserve_block_reason(class).is_none()
    }

    pub(crate) fn reserve_block_reason(
        &self,
        class: PacketClass,
    ) -> Option<OwnerReserveBlockReason> {
        if self.in_flight >= self.in_flight_limit {
            return Some(OwnerReserveBlockReason::TotalInFlight);
        }
        if class.lane() == Lane::Bulk && self.bulk_in_flight >= self.bulk_lane_in_flight_limit() {
            return Some(OwnerReserveBlockReason::BulkLane);
        }
        None
    }

    fn bulk_lane_in_flight_limit(&self) -> usize {
        let priority_reserve = usize::from(self.in_flight_limit > 1);
        self.in_flight_limit
            .saturating_sub(priority_reserve)
            .max(1)
    }

    #[cfg(test)]
    pub(crate) fn last_rx_activity(&self) -> Option<ActivityTick> {
        self.last_rx_activity
    }

    #[cfg(test)]
    pub(crate) fn last_tx_activity(&self) -> Option<ActivityTick> {
        self.last_tx_activity
    }

    pub(crate) fn fsp_activity(&self) -> Option<DataplaneFspOwnerActivity> {
        (self.owner.protocol() == PacketProtocol::Fsp).then_some(DataplaneFspOwnerActivity {
            owner: self.owner.node_addr(),
            fsp_session_start_ms: self.fsp_session_start_ms,
            last_rx_activity: self.last_rx_activity,
            last_rx_previous_hop: self.last_rx_previous_hop,
            last_rx_data_activity: self.last_rx_data_activity,
            last_rx_data_previous_hop: self.last_rx_data_previous_hop,
            last_tx_data_activity: self.last_tx_data_activity,
            last_outbound_next_hop: self.last_outbound_next_hop,
            current_k_bit: self.fsp_current_k_bit,
            previous_draining_k_bit: self.fsp_previous_draining_k_bit,
            current_epoch_confirmed: self.fsp_lifecycle_confirmed,
            send_counter: self.next_send_counter,
            current_path_mtu: self
                .fsp_mmp
                .as_ref()
                .map(|mmp| mmp.path_mtu.current_mtu()),
            data_packets_sent: self.data_packets_sent,
            data_packets_recv: self.data_packets_recv,
            data_bytes_sent: self.data_bytes_sent,
            data_bytes_recv: self.data_bytes_recv,
        })
    }

    pub(crate) fn fsp_mmp_snapshot(&self) -> Option<DataplaneFspMmpSnapshot> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        let mmp = self.fsp_mmp.as_ref()?;
        let dest_addr = self.owner.node_addr();
        let fallback_session_name = self
            .source_peer
            .map(|peer| peer.short_npub())
            .unwrap_or_else(|| dest_addr.to_string());
        Some(DataplaneFspMmpSnapshot::from_mmp(
            dest_addr,
            fallback_session_name,
            mmp,
        ))
    }

    pub(crate) fn fmp_link_metrics(
        &self,
        now: std::time::Instant,
    ) -> Option<DataplaneFmpLinkMetrics> {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return None;
        }
        let mmp = self.fmp_mmp.as_ref()?;
        let metrics = &mmp.metrics;
        Some(DataplaneFmpLinkMetrics {
            node_addr: self.owner.node_addr(),
            mode: mmp.mode(),
            spin_bit_initiator: mmp.spin_bit.is_initiator(),
            srtt_ms: metrics.srtt_ms(),
            srtt_age_ms: metrics.srtt_age_ms(now),
            loss_rate: metrics.loss_rate(),
            loss_rate_for_log: metrics
                .loss_trend
                .initialized()
                .then(|| metrics.loss_trend.long()),
            smoothed_loss: metrics.smoothed_loss(),
            etx: metrics.etx,
            smoothed_etx: metrics.smoothed_etx(),
            jitter_ms: mmp.receiver.jitter_us() as f64 / 1000.0,
            goodput_bps: metrics.goodput_bps(),
            rtt_trend: metrics
                .rtt_trend
                .initialized()
                .then(|| (metrics.rtt_trend.short(), metrics.rtt_trend.long())),
            loss_trend: metrics
                .loss_trend
                .initialized()
                .then(|| (metrics.loss_trend.short(), metrics.loss_trend.long())),
            goodput_trend: metrics
                .goodput_trend
                .initialized()
                .then(|| (metrics.goodput_trend.short(), metrics.goodput_trend.long())),
            jitter_trend: metrics
                .jitter_trend
                .initialized()
                .then(|| (metrics.jitter_trend.short(), metrics.jitter_trend.long())),
            delivery_ratio_forward: metrics.delivery_ratio_forward,
            delivery_ratio_reverse: metrics.delivery_ratio_reverse,
            last_forward_loss_sample: metrics.last_forward_loss_sample(),
            tx_packets: mmp.sender.cumulative_packets_sent(),
            tx_bytes: mmp.sender.cumulative_bytes_sent(),
            rx_packets: mmp.receiver.cumulative_packets_recv(),
            rx_bytes: mmp.receiver.cumulative_bytes_recv(),
            ecn_ce_count: mmp.receiver.ecn_ce_count(),
            last_recv_age_ms: mmp
                .receiver
                .last_recv_time()
                .map(|last_recv| now.duration_since(last_recv).as_millis() as u64),
        })
    }

    pub(crate) fn fmp_link_cost(&self) -> Option<f64> {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return None;
        }
        let mmp = self.fmp_mmp.as_ref()?;
        let etx = mmp.metrics.etx;
        Some(match mmp.metrics.srtt_ms() {
            Some(srtt_ms) => etx * (1.0 + srtt_ms / 100.0),
            None => 1.0,
        })
    }

    pub(crate) fn fmp_has_srtt(&self) -> bool {
        self.owner.protocol() == PacketProtocol::Fmp
            && self
                .fmp_mmp
                .as_ref()
                .is_some_and(|mmp| mmp.metrics.srtt_ms().is_some())
    }

    pub(crate) fn record_fsp_decrypt_failure(&mut self) -> Option<u32> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        self.consecutive_decrypt_failures = self.consecutive_decrypt_failures.saturating_add(1);
        Some(self.consecutive_decrypt_failures)
    }

    pub(crate) fn reserve(
        &mut self,
        packet: &SocketPacket,
        ingress_seq: u64,
    ) -> Result<(OwnerReservation, DataplaneReceiveEpoch), OwnerReserveError> {
        if packet.generation != self.generation {
            return Err(OwnerReserveError::StaleGeneration);
        }
        let use_previous_fmp_epoch = self.uses_previous_fmp_receive_epoch(packet);
        let use_pending_fmp_epoch = self.uses_pending_fmp_receive_epoch(packet);
        let use_previous_fsp_epoch = self.uses_previous_fsp_receive_epoch(packet);
        let use_pending_fsp_epoch = self.uses_pending_fsp_receive_epoch(packet);
        let lane = packet.lane();
        if !self.can_reserve_class(packet.class) {
            return Err(OwnerReserveError::InFlightFull);
        }
        let replay_window = if use_previous_fmp_epoch {
            self.previous_fmp_replay_window
                .as_mut()
                .expect("previous FMP epoch checked before reservation")
        } else if use_pending_fmp_epoch {
            self.pending_fmp_replay_window
                .as_mut()
                .expect("pending FMP epoch checked before reservation")
        } else if use_previous_fsp_epoch {
            self.previous_fsp_replay_window
                .as_mut()
                .expect("previous FSP epoch checked before reservation")
        } else if use_pending_fsp_epoch {
            self.pending_fsp_replay_window
                .as_mut()
                .expect("pending FSP epoch checked before reservation")
        } else {
            &mut self.replay_window
        };

        if !replay_window.accept(packet.counter) {
            return Err(OwnerReserveError::Replay);
        }
        let receive_epoch = if use_previous_fmp_epoch || use_previous_fsp_epoch {
            DataplaneReceiveEpoch::Previous
        } else if use_pending_fmp_epoch || use_pending_fsp_epoch {
            DataplaneReceiveEpoch::Pending
        } else {
            DataplaneReceiveEpoch::Current
        };
        if let Some(path) = packet.source_path.clone() {
            self.active_path = Some(path);
        }
        if let Some(tick) = packet.activity_tick {
            note_activity(&mut self.last_rx_activity, tick);
        }
        self.reserve_class(packet.class);
        let order = OrderToken(self.next_order);
        self.next_order = self.next_order.wrapping_add(1);
        Ok((
            OwnerReservation {
                owner: self.owner,
                owner_shard: 0,
                generation: self.generation,
                order,
                ingress_seq,
                counter: packet.counter,
                class: packet.class,
                lane,
                source_path: packet.source_path.clone(),
                previous_hop: packet.previous_hop,
                ce_flag: packet.ce_flag,
                path_mtu: packet.path_mtu,
                wire_flags: packet.wire_flags,
                source_peer: self.source_peer,
                output_path: None,
                activity_tick: packet.activity_tick,
                fmp_timestamp_ms: None,
                fsp_timestamp_ms: None,
                send_token: None,
            },
            receive_epoch,
        ))
    }

    pub(crate) fn reserve_outbound(
        &mut self,
        mut packet: OutboundPacket,
        ingress_seq: u64,
    ) -> Result<(OwnerReservation, OutboundPacket), OwnerReserveError> {
        if packet.generation != self.generation {
            return Err(OwnerReserveError::StaleGeneration);
        }
        let lane = packet.lane();
        if !self.can_reserve_class(packet.class) {
            return Err(OwnerReserveError::InFlightFull);
        }

        let counter = self.reserve_send_counter()?;
        let output_path = self.active_path.clone();
        let path_mtu = if self.owner.protocol() == PacketProtocol::Fsp
            && self.fsp_wrap_route.is_none()
            && output_path.is_some()
        {
            self.fsp_mmp
                .as_ref()
                .map(|mmp| mmp.path_mtu.current_mtu())
                .unwrap_or(u16::MAX)
        } else {
            u16::MAX
        };
        let fmp_timestamp_ms = self.reserve_fmp_timestamp(packet.activity_tick);
        let fsp_timestamp_ms = self.reserve_fsp_timestamp(packet.activity_tick);
        self.refresh_fsp_outbound_headers(&mut packet);
        self.apply_fsp_wrap_route(&mut packet);
        self.apply_fsp_direct_transport_flag(&mut packet);
        self.reserve_fsp_coords_warmup(&mut packet);
        let fsp_next_hop = packet.fsp_next_hop();
        let fsp_application_data_len = packet.fsp_application_data_len();
        if let Some(tick) = packet.activity_tick {
            note_activity(&mut self.last_tx_activity, tick);
            if fsp_application_data_len.is_some() {
                note_activity(&mut self.last_tx_data_activity, tick);
            }
        }
        if self.owner.protocol() == PacketProtocol::Fsp {
            if let Some(next_hop) = fsp_next_hop {
                self.last_outbound_next_hop = Some(next_hop);
            }
            if let Some(bytes) = fsp_application_data_len {
                self.data_packets_sent = self.data_packets_sent.saturating_add(1);
                self.data_bytes_sent = self.data_bytes_sent.saturating_add(bytes as u64);
            }
            if let (Some(mmp), Some(timestamp_ms)) = (&mut self.fsp_mmp, fsp_timestamp_ms) {
                let frame_bytes = FSP_INNER_HEADER_SIZE
                    .saturating_add(packet.payload.len())
                    .saturating_add(AEAD_TAG_SIZE);
                mmp.sender.record_sent(counter, timestamp_ms, frame_bytes);
            }
        }
        self.reserve_class(packet.class);
        let order = OrderToken(self.next_order);
        self.next_order = self.next_order.wrapping_add(1);
        let reservation = OwnerReservation {
            owner: self.owner,
            owner_shard: 0,
            generation: self.generation,
            order,
            ingress_seq,
            counter,
            class: packet.class,
            lane,
            source_path: None,
            previous_hop: None,
            ce_flag: false,
            path_mtu,
            wire_flags: 0,
            source_peer: self.source_peer,
            output_path,
            activity_tick: packet.activity_tick,
            fmp_timestamp_ms,
            fsp_timestamp_ms,
            send_token: packet.send_token,
        };
        Ok((reservation, packet))
    }

    pub(crate) fn record_authenticated_fsp_session(
        &mut self,
        session: DataplaneAuthenticatedFspSession,
    ) -> Option<bool> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        self.consecutive_decrypt_failures = 0;
        let DataplaneAuthenticatedFspSession {
            previous_hop,
            msg_type,
            body_len,
            sync,
            activity_tick,
            now,
            ..
        } = session;
        if let Some(mmp) = &mut self.fsp_mmp {
            mmp.receiver.record_recv(
                sync.counter,
                sync.timestamp,
                sync.plaintext_len,
                sync.ce_flag,
                now,
            );
            let _spin_rtt = mmp.spin_bit.rx_observe(sync.spin_bit, sync.counter, now);
            mmp.path_mtu.observe_incoming_mtu(sync.path_mtu);
        }
        if let Some(tick) = activity_tick
            && note_activity(&mut self.last_rx_activity, tick)
        {
            self.last_rx_previous_hop = Some(previous_hop);
        }
        if dataplane_fsp_message_is_application_data(msg_type)
            && (previous_hop == self.owner.node_addr()
                || self.last_outbound_next_hop == Some(previous_hop))
        {
            if let Some(tick) = activity_tick {
                note_activity(&mut self.last_rx_data_activity, tick);
            }
            self.last_rx_data_previous_hop = Some(previous_hop);
            self.data_packets_recv = self.data_packets_recv.saturating_add(1);
            self.data_bytes_recv = self.data_bytes_recv.saturating_add(body_len as u64);
        }
        let current_epoch_confirmed = sync.received_k_bit == self.fsp_current_k_bit;
        let newly_confirmed_current_epoch =
            current_epoch_confirmed && !self.fsp_lifecycle_confirmed;
        if current_epoch_confirmed {
            self.fsp_lifecycle_confirmed = true;
        }
        Some(newly_confirmed_current_epoch)
    }

    pub(crate) fn record_authenticated_fmp_receive(
        &mut self,
        receive: DataplaneAuthenticatedFmpMmpReceive,
    ) -> Result<Option<std::time::Duration>, DataplaneFmpMmpSkip> {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return Err(DataplaneFmpMmpSkip::UnknownOwner);
        }
        let Some(mmp) = &mut self.fmp_mmp else {
            return Err(DataplaneFmpMmpSkip::MmpDisabled);
        };
        mmp.receiver.record_recv(
            receive.counter,
            receive.timestamp_ms,
            receive.packet_len,
            receive.ce_flag,
            receive.now,
        );
        Ok(mmp
            .spin_bit
            .rx_observe(receive.spin_bit, receive.counter, receive.now))
    }

    pub(crate) fn record_fmp_send_result(
        &mut self,
        counter: u64,
        timestamp_ms: u32,
        bytes_sent: usize,
    ) {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return;
        }
        let Some(mmp) = &mut self.fmp_mmp else {
            return;
        };
        mmp.sender.record_sent(counter, timestamp_ms, bytes_sent);
    }

    pub(crate) fn process_fmp_mmp_receiver_report(
        &mut self,
        rr: &crate::mmp::report::ReceiverReport,
        now_ms: u64,
        now: std::time::Instant,
    ) -> Result<DataplaneFmpReceiverReportResult, DataplaneFmpMmpSkip> {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return Err(DataplaneFmpMmpSkip::UnknownOwner);
        }
        let session_start_ms = self
            .fmp_session_start_ms
            .ok_or(DataplaneFmpMmpSkip::MmpDisabled)?;
        let Some(mmp) = &mut self.fmp_mmp else {
            return Err(DataplaneFmpMmpSkip::MmpDisabled);
        };
        let our_timestamp_ms = now_ms.wrapping_sub(session_start_ms) as u32;
        let first_rtt = mmp.metrics.process_receiver_report(rr, our_timestamp_ms, now);
        if let Some(srtt_ms) = mmp.metrics.srtt_ms() {
            let srtt_us = (srtt_ms * 1000.0) as i64;
            mmp.sender.update_report_interval_from_srtt(srtt_us);
            mmp.receiver.update_report_interval_from_srtt(srtt_us);
        }
        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        mmp.metrics
            .update_reverse_delivery(our_recv_packets, peer_highest);
        Ok(DataplaneFmpReceiverReportResult {
            first_rtt,
            srtt_ms: mmp.metrics.srtt_ms(),
            loss_rate: mmp.metrics.loss_rate(),
            etx: mmp.metrics.etx,
        })
    }

    #[cfg(test)]
    pub(crate) fn record_fsp_data_sent(
        &mut self,
        next_hop: NodeAddr,
        bytes: usize,
        tick: ActivityTick,
    ) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return false;
        }
        self.last_outbound_next_hop = Some(next_hop);
        note_activity(&mut self.last_tx_activity, tick);
        note_activity(&mut self.last_tx_data_activity, tick);
        self.data_packets_sent = self.data_packets_sent.saturating_add(1);
        self.data_bytes_sent = self.data_bytes_sent.saturating_add(bytes as u64);
        true
    }

    fn collect_fsp_mmp_reports(
        &mut self,
        now: std::time::Instant,
        batch: &mut DataplaneFspMmpReportBatch,
    ) {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return;
        }
        let Some(mmp) = &mut self.fsp_mmp else {
            return;
        };

        let dest_addr = self.owner.node_addr();
        let fallback_session_name = self
            .source_peer
            .map(|peer| peer.short_npub())
            .unwrap_or_else(|| dest_addr.to_string());
        let mode = mmp.mode();
        let prior_failures = mmp.sender.consecutive_send_failures();

        if mode == crate::mmp::MmpMode::Full
            && mmp.sender.should_send_report(now)
            && let Some(sr) = mmp.sender.build_report(now)
        {
            let session_sr: crate::protocol::SessionSenderReport =
                crate::protocol::SessionSenderReport::from(&sr);
            batch.reports.push(DataplaneFspMmpReport {
                dest_addr,
                msg_type: crate::protocol::SessionMessageType::SenderReport.to_byte(),
                encoded: session_sr.encode(),
                prior_failures,
            });
        }

        if mode != crate::mmp::MmpMode::Minimal
            && mmp.receiver.should_send_report(now)
            && let Some(rr) = mmp.receiver.build_report(now)
        {
            let session_rr: crate::protocol::SessionReceiverReport =
                crate::protocol::SessionReceiverReport::from(&rr);
            batch.reports.push(DataplaneFspMmpReport {
                dest_addr,
                msg_type: crate::protocol::SessionMessageType::ReceiverReport.to_byte(),
                encoded: session_rr.encode(),
                prior_failures,
            });
        }

        if mmp.path_mtu.should_send_notification(now)
            && let Some(mtu_value) = mmp.path_mtu.build_notification(now)
        {
            let notif = crate::protocol::PathMtuNotification::new(mtu_value);
            batch.reports.push(DataplaneFspMmpReport {
                dest_addr,
                msg_type: crate::protocol::SessionMessageType::PathMtuNotification.to_byte(),
                encoded: notif.encode(),
                prior_failures,
            });
        }

        if mmp.should_log(now) {
            let snapshot = DataplaneFspMmpSnapshot::from_mmp(dest_addr, fallback_session_name, mmp);
            batch.metric_logs.push(snapshot);
            mmp.mark_logged(now);
        }
    }

    fn collect_fmp_mmp_reports(
        &mut self,
        now: std::time::Instant,
        batch: &mut DataplaneFmpMmpReportBatch,
    ) {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return;
        }
        let Some(mmp) = &mut self.fmp_mmp else {
            return;
        };

        let mode = mmp.mode();
        let node_addr = self.owner.node_addr();

        if mode == crate::mmp::MmpMode::Full
            && mmp.sender.should_send_report(now)
            && let Some(sr) = mmp.sender.build_report(now)
        {
            batch.reports.push(DataplaneFmpMmpReport {
                node_addr,
                encoded: sr.encode(),
                kind: DataplaneFmpMmpReportKind::Sender,
            });
        }

        if mode != crate::mmp::MmpMode::Minimal
            && mmp.receiver.should_send_report(now)
            && let Some(rr) = mmp.receiver.build_report(now)
        {
            batch.reports.push(DataplaneFmpMmpReport {
                node_addr,
                encoded: rr.encode(),
                kind: DataplaneFmpMmpReportKind::Receiver,
            });
        }

        if mmp.should_log(now) {
            let metrics = &mmp.metrics;
            batch.metric_logs.push(DataplaneFmpLinkMetrics {
                node_addr,
                mode: mmp.mode(),
                spin_bit_initiator: mmp.spin_bit.is_initiator(),
                srtt_ms: metrics
                    .rtt_trend
                    .initialized()
                    .then(|| metrics.rtt_trend.long() / 1000.0),
                srtt_age_ms: metrics.srtt_age_ms(now),
                loss_rate: metrics.loss_rate(),
                loss_rate_for_log: metrics
                    .loss_trend
                    .initialized()
                    .then(|| metrics.loss_trend.long()),
                smoothed_loss: metrics.smoothed_loss(),
                etx: metrics.etx,
                smoothed_etx: metrics.smoothed_etx(),
                jitter_ms: mmp.receiver.jitter_us() as f64 / 1000.0,
                goodput_bps: metrics.goodput_bps(),
                rtt_trend: metrics
                    .rtt_trend
                    .initialized()
                    .then(|| (metrics.rtt_trend.short(), metrics.rtt_trend.long())),
                loss_trend: metrics
                    .loss_trend
                    .initialized()
                    .then(|| (metrics.loss_trend.short(), metrics.loss_trend.long())),
                goodput_trend: metrics
                    .goodput_trend
                    .initialized()
                    .then(|| (metrics.goodput_trend.short(), metrics.goodput_trend.long())),
                jitter_trend: metrics
                    .jitter_trend
                    .initialized()
                    .then(|| (metrics.jitter_trend.short(), metrics.jitter_trend.long())),
                delivery_ratio_forward: metrics.delivery_ratio_forward,
                delivery_ratio_reverse: metrics.delivery_ratio_reverse,
                last_forward_loss_sample: metrics.last_forward_loss_sample(),
                tx_packets: mmp.sender.cumulative_packets_sent(),
                tx_bytes: mmp.sender.cumulative_bytes_sent(),
                rx_packets: mmp.receiver.cumulative_packets_recv(),
                rx_bytes: mmp.receiver.cumulative_bytes_recv(),
                ecn_ce_count: mmp.receiver.ecn_ce_count(),
                last_recv_age_ms: mmp
                    .receiver
                    .last_recv_time()
                    .map(|last_recv| now.duration_since(last_recv).as_millis() as u64),
            });
            mmp.mark_logged(now);
        }
    }

    fn record_fsp_mmp_send_result(
        &mut self,
        success: bool,
    ) -> Option<DataplaneFspMmpReportingResumed> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        let mmp = self.fsp_mmp.as_mut()?;
        if success {
            let prev = mmp.sender.record_send_success();
            (prev > 3).then_some(DataplaneFspMmpReportingResumed {
                dest_addr: self.owner.node_addr(),
                consecutive_failures: prev,
            })
        } else {
            mmp.sender.record_send_failure();
            None
        }
    }

    fn seed_fsp_path_mtu(&mut self, path_mtu: u16) -> Result<(), DataplaneFspMmpSkip> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return Err(DataplaneFspMmpSkip::UnknownOwner);
        }
        let Some(mmp) = &mut self.fsp_mmp else {
            return Err(DataplaneFspMmpSkip::MmpDisabled);
        };
        mmp.path_mtu.seed_source_mtu(path_mtu);
        Ok(())
    }

    fn process_fsp_mmp_receiver_report(
        &mut self,
        rr: &crate::mmp::report::ReceiverReport,
        last_outbound_next_hop: Option<NodeAddr>,
        now_ms: u64,
        now: std::time::Instant,
        min_loss_sample: u64,
    ) -> Result<DataplaneFspReceiverReportResult, DataplaneFspMmpSkip> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return Err(DataplaneFspMmpSkip::UnknownOwner);
        }
        let Some(session_start_ms) = self.fsp_session_start_ms else {
            return Err(DataplaneFspMmpSkip::MmpDisabled);
        };
        let Some(mmp) = &mut self.fsp_mmp else {
            return Err(DataplaneFspMmpSkip::MmpDisabled);
        };

        let our_timestamp_ms = now_ms.wrapping_sub(session_start_ms) as u32;
        mmp.metrics
            .process_receiver_report(rr, our_timestamp_ms, now);
        let sample = mmp.metrics.take_forward_loss_evidence(min_loss_sample);

        let srtt_ms = mmp.metrics.srtt_ms();
        if let Some(srtt_ms) = srtt_ms {
            let srtt_us = (srtt_ms * 1000.0) as i64;
            mmp.sender.update_report_interval_with_bounds(
                srtt_us,
                crate::mmp::MIN_SESSION_REPORT_INTERVAL_MS,
                crate::mmp::MAX_SESSION_REPORT_INTERVAL_MS,
            );
            mmp.receiver.update_report_interval_with_bounds(
                srtt_us,
                crate::mmp::MIN_SESSION_REPORT_INTERVAL_MS,
                crate::mmp::MAX_SESSION_REPORT_INTERVAL_MS,
            );
            mmp.path_mtu.update_interval_from_srtt(srtt_ms);
        }

        let our_recv_packets = mmp.receiver.cumulative_packets_recv();
        let peer_highest = mmp.receiver.highest_counter();
        mmp.metrics
            .update_reverse_delivery(our_recv_packets, peer_highest);

        Ok(DataplaneFspReceiverReportResult {
            sample,
            used_direct_next_hop: last_outbound_next_hop
                .is_none_or(|next_hop| next_hop == self.owner.node_addr()),
            srtt_ms,
            mode: mmp.mode(),
        })
    }

    fn apply_fsp_path_mtu_signal(
        &mut self,
        path_mtu: u16,
        now: std::time::Instant,
    ) -> Result<DataplaneFspPathMtuApplyResult, DataplaneFspMmpSkip> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return Err(DataplaneFspMmpSkip::UnknownOwner);
        }
        let Some(mmp) = &mut self.fsp_mmp else {
            return Err(DataplaneFspMmpSkip::MmpDisabled);
        };
        let old_mtu = mmp.path_mtu.current_mtu();
        if mmp.path_mtu.apply_notification(path_mtu, now) {
            Ok(DataplaneFspPathMtuApplyResult::Changed(
                DataplaneFspPathMtuChange {
                    old_mtu,
                    new_mtu: mmp.path_mtu.current_mtu(),
                },
            ))
        } else {
            Ok(DataplaneFspPathMtuApplyResult::Unchanged)
        }
    }

    fn reserve_fsp_coords_warmup(&mut self, packet: &mut OutboundPacket) {
        if self.owner.protocol() != PacketProtocol::Fsp
            || self.fsp_coords_warmup_remaining == 0
            || self.fsp_coords_prefix.is_empty()
            || !packet.fsp_auto_coords_warmup
            || !packet.fsp_cleartext_prefix.is_empty()
        {
            return;
        }

        let OutboundWire::Fsp { flags } = &mut packet.wire else {
            return;
        };
        *flags |= crate::node::session_wire::FSP_FLAG_CP;
        packet.fsp_cleartext_prefix = self.fsp_coords_prefix.clone();
        self.fsp_coords_warmup_remaining = self.fsp_coords_warmup_remaining.saturating_sub(1);
    }

    fn refresh_fsp_outbound_headers(&self, packet: &mut OutboundPacket) {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return;
        }
        let Some(mmp) = &self.fsp_mmp else {
            return;
        };
        packet.refresh_fsp_inner_flags(
            crate::protocol::FspInnerFlags {
                spin_bit: mmp.spin_bit.tx_bit(),
            }
            .to_byte(),
        );
    }

    fn apply_fsp_wrap_route(&self, packet: &mut OutboundPacket) {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return;
        }
        let Some(route) = self.fsp_wrap_route else {
            return;
        };
        packet.apply_fsp_owner_wrap_route(route);
    }

    fn apply_fsp_direct_transport_flag(&self, packet: &mut OutboundPacket) {
        if self.owner.protocol() != PacketProtocol::Fsp
            || self.fsp_wrap_route.is_some()
            || self.active_path.is_none()
        {
            return;
        }
        let OutboundWire::Fsp { flags } = &mut packet.wire else {
            return;
        };
        *flags |= crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT;
    }

    fn reserve_send_counter(&mut self) -> Result<u64, OwnerReserveError> {
        if let Some(authority) = &self.send_counter_authority {
            let counter = authority
                .reserve()
                .map_err(|_| OwnerReserveError::CounterExhausted)?;
            self.next_send_counter = authority.current();
            return Ok(counter);
        }

        let counter = self.next_send_counter;
        self.next_send_counter = self.next_send_counter.wrapping_add(1);
        Ok(counter)
    }

    fn reserve_fmp_timestamp(&self, activity_tick: Option<ActivityTick>) -> Option<u32> {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return None;
        }
        let session_start_ms = self.fmp_session_start_ms?;
        let activity_ms = activity_tick?.get();
        Some(activity_ms.wrapping_sub(session_start_ms) as u32)
    }

    fn reserve_fsp_timestamp(&self, activity_tick: Option<ActivityTick>) -> Option<u32> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        let session_start_ms = self.fsp_session_start_ms?;
        let activity_ms = activity_tick?.get();
        Some(activity_ms.wrapping_sub(session_start_ms) as u32)
    }

    fn stage_retire_slot(&mut self, slot: Arc<CryptoReadySlot>) -> bool {
        debug_assert_eq!(slot.owner(), self.owner);
        let was_empty = self.pending.is_empty();
        let slot = OwnerRetireSlot::new(slot);
        let order = slot.order();
        if self
            .pending
            .back()
            .is_none_or(|pending| pending.order() < order)
        {
            self.pending.push_back(slot);
        } else {
            let index = self
                .pending
                .partition_point(|pending| pending.order() < order);
            assert_ne!(
                self.pending[index].order(),
                order,
                "owner retire slot order reused"
            );
            self.pending.insert(index, slot);
        }
        was_empty
    }

    fn has_pending_retirements(&self) -> bool {
        !self.pending.is_empty()
    }

    fn has_ready_retirement(&self) -> bool {
        self.pending
            .front()
            .is_some_and(|slot| slot.order() == OrderToken(self.next_retire) && slot.is_ready())
    }

    fn take_pending_retirements(&mut self) -> Vec<OwnerRetireSlot> {
        self.pending.drain(..).collect()
    }

    fn retire_ready_slots_into(
        &mut self,
        limit: usize,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        drops: &mut Vec<PacketDrop>,
        compact_endpoint_data: bool,
    ) -> usize {
        let mut retired_count = 0usize;
        while retired_count < limit {
            let order = OrderToken(self.next_retire);
            let Some(front) = self.pending.front() else {
                break;
            };
            if front.order() != order || !front.is_ready() {
                break;
            }
            let mut slot = self.pending.pop_front().expect("owner retire head exists");

            let slot_limit = limit.saturating_sub(retired_count).min(slot.remaining());
            let stale_generation = slot.generation() != self.generation;
            let compact_fsp_run = !stale_generation
                && slot.is_open_fsp_session_payload_run();
            let drained = if stale_generation {
                slot.drain_results(slot_limit, |completion| {
                    drops.push(PacketDrop::from_completion(
                        &completion,
                        PacketDropReason::StaleCompletionGeneration,
                        None,
                    ));
                })
            } else if compact_fsp_run {
                self.retire_ready_open_fsp_session_payload_slot_into(
                    &mut slot,
                    slot_limit,
                    retired,
                    compact_endpoint_data,
                )
            } else {
                slot.drain_results(slot_limit, |completion| {
                    self.retire_ready_completion_into(
                        completion,
                        retired,
                        drops,
                        compact_endpoint_data,
                    );
                })
            };

            self.next_retire = self.next_retire.wrapping_add(drained as u64);
            self.in_flight = self.in_flight.saturating_sub(drained);
            if slot.lane() == Lane::Bulk {
                self.bulk_in_flight = self.bulk_in_flight.saturating_sub(drained);
            }
            retired_count = retired_count.saturating_add(drained);
            if !slot.is_empty() {
                debug_assert_eq!(slot.order(), OrderToken(self.next_retire));
                self.pending.push_front(slot);
            }
        }
        retired_count
    }

    fn retire_ready_open_fsp_session_payload_slot_into(
        &mut self,
        slot: &mut OwnerRetireSlot,
        limit: usize,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        compact_endpoint_data: bool,
    ) -> usize {
        let mut endpoint_data_batch: Option<DataplaneEndpointDataBatch> = None;
        let mut endpoint_packets = 0usize;
        let record_endpoint_packets = crate::perf_profile::enabled();
        let mut direct_enqueued_at_ms = None;
        let received_at = std::time::Instant::now();
        let drained = slot.drain_results(limit, |completion| {
            let CryptoResult::Opened(output) = completion.result else {
                unreachable!("open FSP session payload slot contains only opened outputs");
            };
            self.authenticated_counter_highest = self
                .authenticated_counter_highest
                .max(completion.reservation.counter);
            let mut output = output;
            if compact_endpoint_data {
                let enqueued_at_ms =
                    *direct_enqueued_at_ms.get_or_insert_with(crate::time::now_ms);
                if let Some(ingress) =
                    DataplaneFspEndpointDataIngress::take_from_output(&mut output, enqueued_at_ms)
                {
                    self.record_retired_endpoint_data_ingress(&ingress, received_at);
                    if record_endpoint_packets {
                        endpoint_packets = endpoint_packets.saturating_add(1);
                    }
                    match &mut endpoint_data_batch {
                        Some(batch) => batch.push(ingress),
                        None => {
                            endpoint_data_batch =
                                Some(DataplaneEndpointDataBatch::from_ingress(ingress));
                        }
                    }
                    return;
                }
            }

            flush_retired_endpoint_data_batch(retired, &mut endpoint_data_batch);
            retired.push_output(output);
        });
        flush_retired_endpoint_data_batch(retired, &mut endpoint_data_batch);
        if record_endpoint_packets {
            crate::perf_profile::record_dataplane_established_fsp_data_retire_run(endpoint_packets);
        }
        drained
    }

    fn retire_ready_completion_into(
        &mut self,
        completion: CryptoCompletion,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        drops: &mut Vec<PacketDrop>,
        compact_endpoint_data: bool,
    ) {
        match completion.result {
            CryptoResult::Opened(output) => {
                self.authenticated_counter_highest = self
                    .authenticated_counter_highest
                    .max(completion.reservation.counter);
                self.retire_opened_output_into(output, retired, compact_endpoint_data);
            }
            CryptoResult::Sealed(output) => retired.push_output(output),
            CryptoResult::Outbound(packet) => retired.push_outbound(packet),
            CryptoResult::Failed(failure) => {
                drops.push(PacketDrop::from_completion_with_authenticated_highest(
                    &completion,
                    PacketDropReason::CryptoFailed,
                    failure,
                    self.authenticated_counter_highest,
                ));
            }
        }
    }

    fn retire_opened_output_into(
        &mut self,
        output: PacketOutput,
        retired: &mut DataplaneRetiredOutputSink<'_>,
        compact_endpoint_data: bool,
    ) {
        if compact_endpoint_data && matches!(output.target(), OutputTarget::SessionPayload { .. }) {
            let mut output = output;
            if let Some(ingress) =
                DataplaneFspEndpointDataIngress::take_from_output(&mut output, crate::time::now_ms())
            {
                self.record_retired_endpoint_data_ingress(&ingress, std::time::Instant::now());
                retired.push_endpoint_data_batch(ingress);
            } else {
                retired.push_output(output);
            }
            return;
        }

        retired.push_output(output);
    }

    fn record_retired_endpoint_data_ingress(
        &mut self,
        ingress: &DataplaneFspEndpointDataIngress,
        received_at: std::time::Instant,
    ) {
        let commit = ingress.commit();
        if self.owner != OwnerId::fsp_node(commit.source_addr()) {
            return;
        }
        let _ = self.record_authenticated_fsp_session(DataplaneAuthenticatedFspSession::new(
            commit.source_addr(),
            commit.previous_hop_addr(),
            crate::protocol::SessionMessageType::EndpointData.to_byte(),
            ingress.body_len,
            ingress.receive_sync,
            ingress.activity_tick,
            received_at,
        ));
    }

    fn reserve_class(&mut self, class: PacketClass) {
        self.in_flight = self.in_flight.saturating_add(1);
        if class.lane() == Lane::Bulk {
            self.bulk_in_flight = self.bulk_in_flight.saturating_add(1);
        }
    }
}

fn note_activity(slot: &mut Option<ActivityTick>, tick: ActivityTick) -> bool {
    match slot {
        Some(current) if *current >= tick => false,
        _ => {
            *slot = Some(tick);
            true
        }
    }
}

fn flush_retired_endpoint_data_batch(
    retired: &mut DataplaneRetiredOutputSink<'_>,
    endpoint_data_batch: &mut Option<DataplaneEndpointDataBatch>,
) {
    if let Some(batch) = endpoint_data_batch.take() {
        retired.append_endpoint_data_batch(batch);
    }
}

const REPLAY_BLOCK_BITS_LOG: u64 = 6;
const REPLAY_BLOCK_BITS: u64 = 1 << REPLAY_BLOCK_BITS_LOG;
const REPLAY_RING_BLOCKS: usize = 1 << 7;
const REPLAY_RING_BLOCKS_U64: u64 = REPLAY_RING_BLOCKS as u64;
const REPLAY_WINDOW_SIZE: u64 = (REPLAY_RING_BLOCKS_U64 - 1) * REPLAY_BLOCK_BITS;
const REPLAY_BLOCK_MASK: u64 = REPLAY_RING_BLOCKS_U64 - 1;
const REPLAY_BIT_MASK: u64 = REPLAY_BLOCK_BITS - 1;

#[derive(Debug)]
struct ReplayWindow {
    highest: Option<u64>,
    ring: [u64; REPLAY_RING_BLOCKS],
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            highest: None,
            ring: [0; REPLAY_RING_BLOCKS],
        }
    }
}

impl ReplayWindow {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn accept(&mut self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            return self.set_counter_bit(counter);
        };

        if counter > highest {
            self.advance(highest, counter);
            self.highest = Some(counter);
            return self.set_counter_bit(counter);
        }

        let behind = highest - counter;
        if behind > REPLAY_WINDOW_SIZE {
            return false;
        }

        self.set_counter_bit(counter)
    }

    fn advance(&mut self, highest: u64, counter: u64) {
        let current = counter_block(highest);
        let target = counter_block(counter);
        let mut diff = target - current;
        if diff > REPLAY_RING_BLOCKS_U64 {
            diff = REPLAY_RING_BLOCKS_U64;
        }
        for offset in 1..=diff {
            self.ring[((current + offset) & REPLAY_BLOCK_MASK) as usize] = 0;
        }
    }

    fn set_counter_bit(&mut self, counter: u64) -> bool {
        let index = ring_index(counter);
        let mask = counter_bit(counter);
        let old = self.ring[index];
        self.ring[index] = old | mask;
        old != self.ring[index]
    }
}

fn counter_block(counter: u64) -> u64 {
    counter >> REPLAY_BLOCK_BITS_LOG
}

fn ring_index(counter: u64) -> usize {
    (counter_block(counter) & REPLAY_BLOCK_MASK) as usize
}

fn counter_bit(counter: u64) -> u64 {
    1u64 << (counter & REPLAY_BIT_MASK)
}

#[cfg(test)]
mod replay_window_tests {
    use super::*;

    #[test]
    fn replay_window_tracks_duplicates_window_edges_and_wrapped_blocks() {
        let mut window = ReplayWindow::default();

        assert!(window.accept(10));
        assert!(window.accept(8));
        assert!(window.accept(9));
        assert!(!window.accept(10));
        assert!(!window.accept(8));

        let mut window = ReplayWindow::default();

        assert!(window.accept(1));
        assert!(window.accept(1 + REPLAY_WINDOW_SIZE));
        assert!(!window.accept(1));

        assert!(window.accept(2 + REPLAY_WINDOW_SIZE));
        assert!(!window.accept(1));
        assert!(window.accept(2));

        let mut window = ReplayWindow::default();

        assert!(window.accept(0));
        assert!(window.accept(REPLAY_BLOCK_BITS * REPLAY_RING_BLOCKS_U64));
        assert!(!window.accept(0));
        assert!(window.accept(REPLAY_BLOCK_BITS * REPLAY_RING_BLOCKS_U64 + 1));
    }
}
