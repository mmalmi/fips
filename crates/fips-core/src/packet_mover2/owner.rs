#[derive(Clone, Debug)]
pub(crate) struct OwnerConfig {
    generation: u64,
    in_flight_limit: usize,
    bulk_in_flight_limit: usize,
    reliable_bulk_in_flight_limit: usize,
    next_send_counter: u64,
    send_counter_authority: Option<crate::noise::SendCounterAuthority>,
    fmp_session_start_ms: Option<u64>,
    fsp_session_start_ms: Option<u64>,
    fsp_send_headers: Option<PacketMover2FspSendHeaders>,
    fsp_current_k_bit: Option<bool>,
    fsp_previous_draining_k_bit: Option<bool>,
    fsp_coords_warmup: Option<(u8, Vec<u8>)>,
    fsp_mmp: Option<PacketMover2FspMmpConfig>,
    source_peer: Option<crate::PeerIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FspSendHeaders {
    fsp_flags: u8,
    inner_flags: u8,
}

impl PacketMover2FspSendHeaders {
    pub(crate) fn new(fsp_flags: u8, inner_flags: u8) -> Self {
        Self {
            fsp_flags,
            inner_flags,
        }
    }
}

#[derive(Clone, Debug)]
struct PacketMover2FspMmpConfig {
    config: crate::config::SessionMmpConfig,
    is_initiator: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FspSendContext {
    generation: u64,
    fsp_flags: u8,
    inner_flags: u8,
}

impl PacketMover2FspSendContext {
    fn new(generation: u64, headers: PacketMover2FspSendHeaders) -> Self {
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
pub(crate) struct PacketMover2FspMmpReport {
    pub(crate) dest_addr: NodeAddr,
    pub(crate) msg_type: u8,
    pub(crate) encoded: Vec<u8>,
    pub(crate) prior_failures: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct PacketMover2FspMmpSnapshot {
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

impl PacketMover2FspMmpSnapshot {
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
pub(crate) struct PacketMover2FspMmpReportBatch {
    pub(crate) reports: Vec<PacketMover2FspMmpReport>,
    pub(crate) metric_logs: Vec<PacketMover2FspMmpSnapshot>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct PacketMover2FspReceiverReportResult {
    pub(crate) sample: Option<(u64, f64)>,
    pub(crate) used_direct_next_hop: bool,
    pub(crate) srtt_ms: Option<f64>,
    pub(crate) mode: crate::mmp::MmpMode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketMover2FspMmpSkip {
    UnknownOwner,
    MmpDisabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PacketMover2FspPathMtuChange {
    pub(crate) old_mtu: u16,
    pub(crate) new_mtu: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PacketMover2FspPathMtuApplyResult {
    Changed(PacketMover2FspPathMtuChange),
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PacketMover2FspMmpReportingResumed {
    pub(crate) dest_addr: NodeAddr,
    pub(crate) consecutive_failures: u32,
}

impl OwnerConfig {
    pub(crate) fn new(generation: u64, in_flight_limit: usize) -> Self {
        Self {
            generation,
            in_flight_limit,
            bulk_in_flight_limit: in_flight_limit,
            reliable_bulk_in_flight_limit: in_flight_limit,
            next_send_counter: 0,
            send_counter_authority: None,
            fmp_session_start_ms: None,
            fsp_session_start_ms: None,
            fsp_send_headers: None,
            fsp_current_k_bit: None,
            fsp_previous_draining_k_bit: None,
            fsp_coords_warmup: None,
            fsp_mmp: None,
            source_peer: None,
        }
    }

    pub(crate) fn with_bulk_in_flight_limit(mut self, bulk_in_flight_limit: usize) -> Self {
        self.bulk_in_flight_limit = bulk_in_flight_limit.min(self.in_flight_limit).max(1);
        self
    }

    pub(crate) fn with_reliable_bulk_in_flight_limit(
        mut self,
        reliable_bulk_in_flight_limit: usize,
    ) -> Self {
        self.reliable_bulk_in_flight_limit = reliable_bulk_in_flight_limit
            .min(self.in_flight_limit)
            .max(1);
        self
    }

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

    pub(crate) fn with_fsp_session_start_ms(mut self, session_start_ms: u64) -> Self {
        self.fsp_session_start_ms = Some(session_start_ms);
        self
    }

    pub(crate) fn with_fsp_send_headers(
        mut self,
        fsp_flags: u8,
        inner_flags: u8,
    ) -> Self {
        self.fsp_send_headers = Some(PacketMover2FspSendHeaders::new(fsp_flags, inner_flags));
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
        self.fsp_mmp = Some(PacketMover2FspMmpConfig {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OwnerReservation {
    owner: OwnerId,
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
    DiscardableBulk,
    ReliableBulk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PacketMover2FspOwnerActivity {
    owner: NodeAddr,
    fsp_session_start_ms: Option<u64>,
    last_rx_activity: Option<ActivityTick>,
    last_rx_data_activity: Option<ActivityTick>,
    last_tx_data_activity: Option<ActivityTick>,
    last_outbound_next_hop: Option<NodeAddr>,
    current_k_bit: bool,
    previous_draining_k_bit: Option<bool>,
    send_counter: u64,
    current_path_mtu: Option<u16>,
    data_packets_sent: u64,
    data_packets_recv: u64,
    data_bytes_sent: u64,
    data_bytes_recv: u64,
}

impl PacketMover2FspOwnerActivity {
    pub(crate) fn last_outbound_next_hop(self) -> Option<NodeAddr> {
        self.last_outbound_next_hop
    }

    pub(crate) fn last_rx_age_ms(self, now_ms: u64) -> Option<u64> {
        self.last_rx_activity.map(|tick| tick.age_ms(now_ms))
    }

    pub(crate) fn last_rx_data_age_ms(self, now_ms: u64) -> Option<u64> {
        self.last_rx_data_activity.map(|tick| tick.age_ms(now_ms))
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

    fn tracks_next_hop(self, next_hop: &NodeAddr) -> bool {
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
    bulk_in_flight_limit: usize,
    reliable_bulk_in_flight_limit: usize,
    in_flight: usize,
    bulk_in_flight: usize,
    discardable_bulk_in_flight: usize,
    reliable_bulk_in_flight: usize,
    next_order: u64,
    next_retire: u64,
    next_send_counter: u64,
    send_counter_authority: Option<crate::noise::SendCounterAuthority>,
    crypto_keys: Option<OwnerCryptoKeys>,
    active_path: Option<TransportPath>,
    fmp_session_start_ms: Option<u64>,
    fsp_session_start_ms: Option<u64>,
    fsp_send_headers: Option<PacketMover2FspSendHeaders>,
    fsp_current_k_bit: bool,
    fsp_previous_draining_k_bit: Option<bool>,
    fsp_coords_warmup_remaining: u8,
    fsp_coords_prefix: Vec<u8>,
    fsp_mmp: Option<crate::mmp::MmpSessionState>,
    fsp_lifecycle_confirmed: bool,
    source_peer: Option<crate::PeerIdentity>,
    last_rx_activity: Option<ActivityTick>,
    last_rx_data_activity: Option<ActivityTick>,
    last_tx_activity: Option<ActivityTick>,
    last_tx_data_activity: Option<ActivityTick>,
    last_hard_event: Option<ActivityTick>,
    last_outbound_next_hop: Option<NodeAddr>,
    data_packets_sent: u64,
    data_packets_recv: u64,
    data_bytes_sent: u64,
    data_bytes_recv: u64,
    consecutive_decrypt_failures: u32,
    hard_events: u64,
    authenticated_counter_highest: u64,
    replay_window: ReplayWindow,
    pending: BTreeMap<OrderToken, CryptoCompletion>,
}

impl OwnerState {
    pub(crate) fn new(owner: OwnerId, config: OwnerConfig) -> Self {
        Self {
            owner,
            generation: config.generation,
            in_flight_limit: config.in_flight_limit,
            bulk_in_flight_limit: config.bulk_in_flight_limit,
            reliable_bulk_in_flight_limit: config.reliable_bulk_in_flight_limit,
            in_flight: 0,
            bulk_in_flight: 0,
            discardable_bulk_in_flight: 0,
            reliable_bulk_in_flight: 0,
            next_order: 0,
            next_retire: 0,
            next_send_counter: config.next_send_counter,
            send_counter_authority: config.send_counter_authority,
            crypto_keys: None,
            active_path: None,
            fmp_session_start_ms: config.fmp_session_start_ms,
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
            fsp_mmp: config
                .fsp_mmp
                .map(|mmp| crate::mmp::MmpSessionState::new(&mmp.config, mmp.is_initiator)),
            fsp_lifecycle_confirmed: false,
            source_peer: config.source_peer,
            last_rx_activity: None,
            last_rx_data_activity: None,
            last_tx_activity: None,
            last_tx_data_activity: None,
            last_hard_event: None,
            last_outbound_next_hop: None,
            data_packets_sent: 0,
            data_packets_recv: 0,
            data_bytes_sent: 0,
            data_bytes_recv: 0,
            consecutive_decrypt_failures: 0,
            hard_events: 0,
            authenticated_counter_highest: 0,
            replay_window: ReplayWindow::default(),
            pending: BTreeMap::new(),
        }
    }

    pub(crate) fn rekey(&mut self, generation: u64) {
        self.generation = generation;
        self.replay_window.clear();
        self.next_send_counter = 0;
        self.send_counter_authority = None;
        self.crypto_keys = None;
        self.fmp_session_start_ms = None;
        self.fsp_session_start_ms = None;
        self.fsp_send_headers = None;
        self.fsp_current_k_bit = false;
        self.fsp_previous_draining_k_bit = None;
        self.fsp_coords_warmup_remaining = 0;
        self.fsp_coords_prefix.clear();
        if let Some(mmp) = &mut self.fsp_mmp {
            mmp.reset_for_rekey(std::time::Instant::now());
        }
        self.fsp_lifecycle_confirmed = false;
        self.source_peer = None;
        self.last_rx_data_activity = None;
        self.last_tx_data_activity = None;
        self.last_outbound_next_hop = None;
        self.data_packets_sent = 0;
        self.data_packets_recv = 0;
        self.data_bytes_sent = 0;
        self.data_bytes_recv = 0;
        self.consecutive_decrypt_failures = 0;
        self.authenticated_counter_highest = 0;
    }

    pub(crate) fn set_crypto_keys(&mut self, keys: OwnerCryptoKeys) {
        self.crypto_keys = Some(keys);
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

    fn crypto_keys(&self) -> Option<OwnerCryptoKeys> {
        self.crypto_keys.clone()
    }

    pub(crate) fn set_active_path(&mut self, path: TransportPath) {
        self.active_path = Some(path);
    }

    pub(crate) fn active_path(&self) -> Option<TransportPath> {
        self.active_path.clone()
    }

    pub(crate) fn fsp_send_context(&self) -> Option<PacketMover2FspSendContext> {
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
        Some(PacketMover2FspSendContext::new(self.generation, headers))
    }

    pub(crate) fn can_reserve_lane(&self, lane: Lane) -> bool {
        if self.in_flight >= self.in_flight_limit {
            return false;
        }
        lane != Lane::Bulk || self.bulk_in_flight < self.bulk_lane_in_flight_limit()
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
        match class {
            PacketClass::Bulk if self.discardable_bulk_in_flight >= self.bulk_in_flight_limit => {
                Some(OwnerReserveBlockReason::DiscardableBulk)
            }
            PacketClass::ReliableBulk
                if self.reliable_bulk_in_flight >= self.reliable_bulk_in_flight_limit =>
            {
                Some(OwnerReserveBlockReason::ReliableBulk)
            }
            PacketClass::Control
            | PacketClass::Rekey
            | PacketClass::Mmp
            | PacketClass::Liveness
            | PacketClass::Bulk
            | PacketClass::ReliableBulk => None,
        }
    }

    fn bulk_lane_in_flight_limit(&self) -> usize {
        let priority_reserve = usize::from(self.in_flight_limit > 1);
        self.in_flight_limit
            .saturating_sub(priority_reserve)
            .max(1)
    }

    pub(crate) fn last_rx_activity(&self) -> Option<ActivityTick> {
        self.last_rx_activity
    }

    pub(crate) fn last_tx_activity(&self) -> Option<ActivityTick> {
        self.last_tx_activity
    }

    pub(crate) fn fsp_activity(&self) -> Option<PacketMover2FspOwnerActivity> {
        (self.owner.protocol() == PacketProtocol::Fsp).then_some(PacketMover2FspOwnerActivity {
            owner: self.owner.node_addr(),
            fsp_session_start_ms: self.fsp_session_start_ms,
            last_rx_activity: self.last_rx_activity,
            last_rx_data_activity: self.last_rx_data_activity,
            last_tx_data_activity: self.last_tx_data_activity,
            last_outbound_next_hop: self.last_outbound_next_hop,
            current_k_bit: self.fsp_current_k_bit,
            previous_draining_k_bit: self.fsp_previous_draining_k_bit,
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

    pub(crate) fn fsp_mmp_snapshot(&self) -> Option<PacketMover2FspMmpSnapshot> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        let mmp = self.fsp_mmp.as_ref()?;
        let dest_addr = self.owner.node_addr();
        let fallback_session_name = self
            .source_peer
            .map(|peer| peer.short_npub())
            .unwrap_or_else(|| dest_addr.to_string());
        Some(PacketMover2FspMmpSnapshot::from_mmp(
            dest_addr,
            fallback_session_name,
            mmp,
        ))
    }

    pub(crate) fn last_hard_event(&self) -> Option<ActivityTick> {
        self.last_hard_event
    }

    pub(crate) fn hard_events(&self) -> u64 {
        self.hard_events
    }

    pub(crate) fn record_hard_event(&mut self, tick: ActivityTick) {
        self.hard_events = self.hard_events.saturating_add(1);
        note_activity(&mut self.last_hard_event, tick);
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
    ) -> Result<OwnerReservation, OwnerReserveError> {
        if packet.generation != self.generation {
            return Err(OwnerReserveError::StaleGeneration);
        }
        if self.replay_window.is_replay(packet.counter) {
            return Err(OwnerReserveError::Replay);
        }
        let lane = packet.lane();
        if !self.can_reserve_class(packet.class) {
            return Err(OwnerReserveError::InFlightFull);
        }

        if !self.replay_window.accept(packet.counter) {
            return Err(OwnerReserveError::Replay);
        }
        if let Some(path) = packet.source_path.clone() {
            self.active_path = Some(path);
        }
        if let Some(tick) = packet.activity_tick {
            note_activity(&mut self.last_rx_activity, tick);
        }
        self.reserve_class(packet.class);
        let order = OrderToken(self.next_order);
        self.next_order = self.next_order.wrapping_add(1);
        Ok(OwnerReservation {
            owner: self.owner,
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
        })
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
        let fsp_next_hop = packet.fsp_next_hop();
        let fsp_application_data_len = packet.fsp_application_data_len();
        let fmp_timestamp_ms = self.reserve_fmp_timestamp(packet.activity_tick);
        let fsp_timestamp_ms = self.reserve_fsp_timestamp(packet.activity_tick);
        self.refresh_fsp_outbound_headers(&mut packet);
        self.reserve_fsp_coords_warmup(&mut packet);
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
            generation: self.generation,
            order,
            ingress_seq,
            counter,
            class: packet.class,
            lane,
            source_path: None,
            previous_hop: None,
            ce_flag: false,
            path_mtu: u16::MAX,
            wire_flags: 0,
            source_peer: self.source_peer,
            output_path,
            activity_tick: packet.activity_tick,
            fmp_timestamp_ms,
            fsp_timestamp_ms,
        };
        Ok((reservation, packet))
    }

    pub(crate) fn record_authenticated_fsp_session(
        &mut self,
        previous_hop: NodeAddr,
        msg_type: u8,
        body_len: usize,
        sync: FspReceiveSync,
        activity_tick: Option<ActivityTick>,
        now: std::time::Instant,
    ) -> Option<FspReceiveLifecycle> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        self.consecutive_decrypt_failures = 0;
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
        if let Some(tick) = activity_tick {
            note_activity(&mut self.last_rx_activity, tick);
        }
        if packet_mover2_fsp_message_is_application_data(msg_type)
            && (previous_hop == self.owner.node_addr()
                || self.last_outbound_next_hop == Some(previous_hop))
        {
            if let Some(tick) = activity_tick {
                note_activity(&mut self.last_rx_data_activity, tick);
            }
            self.data_packets_recv = self.data_packets_recv.saturating_add(1);
            self.data_bytes_recv = self.data_bytes_recv.saturating_add(body_len as u64);
        }
        let current_epoch_confirmed = sync.received_k_bit == self.fsp_current_k_bit;
        let registry_sync_required = current_epoch_confirmed && !self.fsp_lifecycle_confirmed;
        if current_epoch_confirmed {
            self.fsp_lifecycle_confirmed = true;
        }
        Some(FspReceiveLifecycle {
            registry_sync_required,
            current_epoch_confirmed,
        })
    }

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
        batch: &mut PacketMover2FspMmpReportBatch,
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
            batch.reports.push(PacketMover2FspMmpReport {
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
            batch.reports.push(PacketMover2FspMmpReport {
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
            batch.reports.push(PacketMover2FspMmpReport {
                dest_addr,
                msg_type: crate::protocol::SessionMessageType::PathMtuNotification.to_byte(),
                encoded: notif.encode(),
                prior_failures,
            });
        }

        if mmp.should_log(now) {
            let snapshot = PacketMover2FspMmpSnapshot::from_mmp(dest_addr, fallback_session_name, mmp);
            batch.metric_logs.push(snapshot);
            mmp.mark_logged(now);
        }
    }

    fn record_fsp_mmp_send_result(
        &mut self,
        success: bool,
    ) -> Option<PacketMover2FspMmpReportingResumed> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return None;
        }
        let mmp = self.fsp_mmp.as_mut()?;
        if success {
            let prev = mmp.sender.record_send_success();
            (prev > 3).then_some(PacketMover2FspMmpReportingResumed {
                dest_addr: self.owner.node_addr(),
                consecutive_failures: prev,
            })
        } else {
            mmp.sender.record_send_failure();
            None
        }
    }

    fn seed_fsp_path_mtu(&mut self, path_mtu: u16) -> Result<(), PacketMover2FspMmpSkip> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return Err(PacketMover2FspMmpSkip::UnknownOwner);
        }
        let Some(mmp) = &mut self.fsp_mmp else {
            return Err(PacketMover2FspMmpSkip::MmpDisabled);
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
    ) -> Result<PacketMover2FspReceiverReportResult, PacketMover2FspMmpSkip> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return Err(PacketMover2FspMmpSkip::UnknownOwner);
        }
        let Some(session_start_ms) = self.fsp_session_start_ms else {
            return Err(PacketMover2FspMmpSkip::MmpDisabled);
        };
        let Some(mmp) = &mut self.fsp_mmp else {
            return Err(PacketMover2FspMmpSkip::MmpDisabled);
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

        Ok(PacketMover2FspReceiverReportResult {
            sample,
            used_direct_next_hop: last_outbound_next_hop
                .map_or(true, |next_hop| next_hop == self.owner.node_addr()),
            srtt_ms,
            mode: mmp.mode(),
        })
    }

    fn apply_fsp_path_mtu_signal(
        &mut self,
        path_mtu: u16,
        now: std::time::Instant,
    ) -> Result<PacketMover2FspPathMtuApplyResult, PacketMover2FspMmpSkip> {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return Err(PacketMover2FspMmpSkip::UnknownOwner);
        }
        let Some(mmp) = &mut self.fsp_mmp else {
            return Err(PacketMover2FspMmpSkip::MmpDisabled);
        };
        let old_mtu = mmp.path_mtu.current_mtu();
        if mmp.path_mtu.apply_notification(path_mtu, now) {
            Ok(PacketMover2FspPathMtuApplyResult::Changed(
                PacketMover2FspPathMtuChange {
                    old_mtu,
                    new_mtu: mmp.path_mtu.current_mtu(),
                },
            ))
        } else {
            Ok(PacketMover2FspPathMtuApplyResult::Unchanged)
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

    pub(crate) fn retire_into(
        &mut self,
        completion: CryptoCompletion,
        retired: &mut Vec<RetiredPacket>,
    ) {
        self.pending.insert(completion.reservation.order, completion);

        while let Some(completion) = self.pending.remove(&OrderToken(self.next_retire)) {
            self.next_retire = self.next_retire.wrapping_add(1);
            self.in_flight = self.in_flight.saturating_sub(1);
            if completion.reservation.lane == Lane::Bulk {
                self.bulk_in_flight = self.bulk_in_flight.saturating_sub(1);
                match completion.reservation.class {
                    PacketClass::Bulk => {
                        self.discardable_bulk_in_flight =
                            self.discardable_bulk_in_flight.saturating_sub(1);
                    }
                    PacketClass::ReliableBulk => {
                        self.reliable_bulk_in_flight =
                            self.reliable_bulk_in_flight.saturating_sub(1);
                    }
                    PacketClass::Control
                    | PacketClass::Rekey
                    | PacketClass::Mmp
                    | PacketClass::Liveness => {}
                }
            }

            if completion.reservation.generation != self.generation {
                retired.push(RetiredPacket::Drop(PacketDrop::from_completion(
                    &completion,
                    PacketDropReason::StaleCompletionGeneration,
                    None,
                )));
                continue;
            }

            match completion.result {
                CryptoResult::Opened(output) => {
                    self.authenticated_counter_highest = self
                        .authenticated_counter_highest
                        .max(completion.reservation.counter);
                    retired.push(RetiredPacket::Output(output));
                }
                CryptoResult::Sealed(output) => retired.push(RetiredPacket::Output(output)),
                CryptoResult::Outbound(packet) => retired.push(RetiredPacket::Outbound(packet)),
                CryptoResult::Failed(failure) => {
                    retired.push(RetiredPacket::Drop(
                        PacketDrop::from_completion_with_authenticated_highest(
                            &completion,
                            PacketDropReason::CryptoFailed,
                            failure,
                            self.authenticated_counter_highest,
                        ),
                    ));
                }
            }
        }
    }

    fn reserve_class(&mut self, class: PacketClass) {
        self.in_flight = self.in_flight.saturating_add(1);
        if class.lane() == Lane::Bulk {
            self.bulk_in_flight = self.bulk_in_flight.saturating_add(1);
            match class {
                PacketClass::Bulk => {
                    self.discardable_bulk_in_flight =
                        self.discardable_bulk_in_flight.saturating_add(1);
                }
                PacketClass::ReliableBulk => {
                    self.reliable_bulk_in_flight =
                        self.reliable_bulk_in_flight.saturating_add(1);
                }
                PacketClass::Control
                | PacketClass::Rekey
                | PacketClass::Mmp
                | PacketClass::Liveness => {}
            }
        }
    }
}

fn note_activity(slot: &mut Option<ActivityTick>, tick: ActivityTick) {
    match slot {
        Some(current) if *current >= tick => {}
        _ => *slot = Some(tick),
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

    fn is_replay(&self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            return false;
        };
        if counter > highest {
            return false;
        }

        let behind = highest - counter;
        if behind > REPLAY_WINDOW_SIZE {
            return true;
        }
        self.ring[ring_index(counter)] & counter_bit(counter) != 0
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
    fn replay_window_accepts_out_of_order_once_within_window() {
        let mut window = ReplayWindow::default();

        assert!(window.accept(10));
        assert!(window.accept(8));
        assert!(window.accept(9));
        assert!(!window.accept(10));
        assert!(!window.accept(8));
    }

    #[test]
    fn replay_window_rejects_packets_after_window_moves_past_them() {
        let mut window = ReplayWindow::default();

        assert!(window.accept(1));
        assert!(window.accept(1 + REPLAY_WINDOW_SIZE));
        assert!(!window.accept(1));

        assert!(window.accept(2 + REPLAY_WINDOW_SIZE));
        assert!(!window.accept(1));
        assert!(window.accept(2));
    }

    #[test]
    fn replay_window_clears_wrapped_ring_blocks_on_large_advance() {
        let mut window = ReplayWindow::default();

        assert!(window.accept(0));
        assert!(window.accept(REPLAY_BLOCK_BITS * REPLAY_RING_BLOCKS_U64));
        assert!(!window.accept(0));
        assert!(window.accept(REPLAY_BLOCK_BITS * REPLAY_RING_BLOCKS_U64 + 1));
    }
}
