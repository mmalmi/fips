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
    fsp_coords_warmup: Option<(u8, Vec<u8>)>,
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
            fsp_coords_warmup: None,
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

    pub(crate) fn with_fsp_coords_warmup(mut self, remaining: u8, prefix: Vec<u8>) -> Self {
        if remaining == 0 || prefix.is_empty() {
            self.fsp_coords_warmup = None;
        } else {
            self.fsp_coords_warmup = Some((remaining, prefix));
        }
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
    fsp_coords_warmup_remaining: u8,
    fsp_coords_prefix: Vec<u8>,
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
            fsp_coords_warmup_remaining: config
                .fsp_coords_warmup
                .as_ref()
                .map_or(0, |(remaining, _)| *remaining),
            fsp_coords_prefix: config
                .fsp_coords_warmup
                .map_or_else(Vec::new, |(_, prefix)| prefix),
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
        self.fsp_coords_warmup_remaining = 0;
        self.fsp_coords_prefix.clear();
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
        if let Some(peer) = config.source_peer {
            self.source_peer = Some(peer);
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
        self.fsp_send_headers
            .map(|headers| PacketMover2FspSendContext::new(self.generation, headers))
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
            data_packets_sent: self.data_packets_sent,
            data_packets_recv: self.data_packets_recv,
            data_bytes_sent: self.data_bytes_sent,
            data_bytes_recv: self.data_bytes_recv,
        })
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
        activity_tick: Option<ActivityTick>,
    ) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp {
            return false;
        }
        self.consecutive_decrypt_failures = 0;
        let Some(tick) = activity_tick else {
            return false;
        };
        note_activity(&mut self.last_rx_activity, tick);
        if packet_mover2_fsp_message_is_application_data(msg_type)
            && (previous_hop == self.owner.node_addr()
                || self.last_outbound_next_hop == Some(previous_hop))
        {
            note_activity(&mut self.last_rx_data_activity, tick);
            self.data_packets_recv = self.data_packets_recv.saturating_add(1);
            self.data_bytes_recv = self.data_bytes_recv.saturating_add(body_len as u64);
        }
        true
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
