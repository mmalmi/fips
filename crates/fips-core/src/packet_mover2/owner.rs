#[derive(Clone, Debug)]
pub(crate) struct OwnerConfig {
    generation: u64,
    in_flight_limit: usize,
    next_send_counter: u64,
    send_counter_authority: Option<crate::noise::SendCounterAuthority>,
    fmp_session_start_ms: Option<u64>,
    fsp_session_start_ms: Option<u64>,
    fsp_coords_warmup_remaining: u8,
    fsp_coords_prefix: Vec<u8>,
}

impl OwnerConfig {
    pub(crate) fn new(generation: u64, in_flight_limit: usize) -> Self {
        Self {
            generation,
            in_flight_limit,
            next_send_counter: 0,
            send_counter_authority: None,
            fmp_session_start_ms: None,
            fsp_session_start_ms: None,
            fsp_coords_warmup_remaining: 0,
            fsp_coords_prefix: Vec::new(),
        }
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

    pub(crate) fn with_fsp_coords_warmup(mut self, remaining: u8, prefix: Vec<u8>) -> Self {
        self.fsp_coords_warmup_remaining = remaining;
        self.fsp_coords_prefix = prefix;
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
    lane: Lane,
    source_path: Option<TransportPath>,
    previous_hop: Option<NodeAddr>,
    ce_flag: bool,
    wire_flags: u8,
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

#[derive(Debug)]
pub(crate) struct OwnerState {
    owner: OwnerId,
    generation: u64,
    in_flight_limit: usize,
    in_flight: usize,
    next_order: u64,
    next_retire: u64,
    next_send_counter: u64,
    send_counter_authority: Option<crate::noise::SendCounterAuthority>,
    crypto_keys: Option<OwnerCryptoKeys>,
    active_path: Option<TransportPath>,
    fmp_session_start_ms: Option<u64>,
    fsp_session_start_ms: Option<u64>,
    fsp_coords_warmup_remaining: u8,
    fsp_coords_prefix: Vec<u8>,
    last_rx_activity: Option<ActivityTick>,
    last_tx_activity: Option<ActivityTick>,
    last_hard_event: Option<ActivityTick>,
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
            in_flight: 0,
            next_order: 0,
            next_retire: 0,
            next_send_counter: config.next_send_counter,
            send_counter_authority: config.send_counter_authority,
            crypto_keys: None,
            active_path: None,
            fmp_session_start_ms: config.fmp_session_start_ms,
            fsp_session_start_ms: config.fsp_session_start_ms,
            fsp_coords_warmup_remaining: config.fsp_coords_warmup_remaining,
            fsp_coords_prefix: config.fsp_coords_prefix,
            last_rx_activity: None,
            last_tx_activity: None,
            last_hard_event: None,
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
        self.fsp_coords_warmup_remaining = 0;
        self.fsp_coords_prefix.clear();
        self.authenticated_counter_highest = 0;
    }

    pub(crate) fn set_crypto_keys(&mut self, keys: OwnerCryptoKeys) {
        self.crypto_keys = Some(keys);
    }

    pub(crate) fn set_send_counter_authority(
        &mut self,
        authority: crate::noise::SendCounterAuthority,
    ) {
        self.next_send_counter = authority.current();
        self.send_counter_authority = Some(authority);
    }

    pub(crate) fn set_fsp_session_start_ms(&mut self, session_start_ms: u64) {
        self.fsp_session_start_ms = Some(session_start_ms);
    }

    pub(crate) fn set_fsp_coords_warmup(&mut self, remaining: u8, prefix: Vec<u8>) {
        self.fsp_coords_warmup_remaining = remaining;
        self.fsp_coords_prefix = prefix;
    }

    pub(crate) fn set_fmp_session_start_ms(&mut self, session_start_ms: u64) {
        self.fmp_session_start_ms = Some(session_start_ms);
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

    pub(crate) fn last_rx_activity(&self) -> Option<ActivityTick> {
        self.last_rx_activity
    }

    pub(crate) fn last_tx_activity(&self) -> Option<ActivityTick> {
        self.last_tx_activity
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
        if self.in_flight >= self.in_flight_limit {
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
        self.in_flight += 1;
        let order = OrderToken(self.next_order);
        self.next_order = self.next_order.wrapping_add(1);
        Ok(OwnerReservation {
            owner: self.owner,
            generation: self.generation,
            order,
            ingress_seq,
            counter: packet.counter,
            lane: packet.lane(),
            source_path: packet.source_path.clone(),
            previous_hop: packet.previous_hop,
            ce_flag: packet.ce_flag,
            wire_flags: packet.wire_flags,
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
        if self.in_flight >= self.in_flight_limit {
            return Err(OwnerReserveError::InFlightFull);
        }

        let counter = self.reserve_send_counter()?;
        let output_path = self.active_path.clone();
        let fmp_timestamp_ms = self.reserve_fmp_timestamp(packet.activity_tick);
        let fsp_timestamp_ms = self.reserve_fsp_timestamp(packet.activity_tick);
        self.reserve_fsp_coords_warmup(&mut packet);
        if let Some(tick) = packet.activity_tick {
            note_activity(&mut self.last_tx_activity, tick);
        }
        self.in_flight += 1;
        let order = OrderToken(self.next_order);
        self.next_order = self.next_order.wrapping_add(1);
        let reservation = OwnerReservation {
            owner: self.owner,
            generation: self.generation,
            order,
            ingress_seq,
            counter,
            lane: packet.lane(),
            source_path: None,
            previous_hop: None,
            ce_flag: false,
            wire_flags: 0,
            output_path,
            activity_tick: packet.activity_tick,
            fmp_timestamp_ms,
            fsp_timestamp_ms,
        };
        Ok((reservation, packet))
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

    pub(crate) fn retire(&mut self, completion: CryptoCompletion) -> Vec<RetiredPacket> {
        self.pending
            .insert(completion.reservation.order, completion);
        let mut retired = Vec::new();

        while let Some(completion) = self.pending.remove(&OrderToken(self.next_retire)) {
            self.next_retire = self.next_retire.wrapping_add(1);
            self.in_flight = self.in_flight.saturating_sub(1);

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

        retired
    }

    #[cfg(test)]
    fn in_flight(&self) -> usize {
        self.in_flight
    }

    #[cfg(test)]
    fn next_send_counter(&self) -> u64 {
        self.next_send_counter
    }
}

fn note_activity(slot: &mut Option<ActivityTick>, tick: ActivityTick) {
    match slot {
        Some(current) if *current >= tick => {}
        _ => *slot = Some(tick),
    }
}

const REPLAY_WINDOW_BITS: u64 = u128::BITS as u64;

#[derive(Debug, Default)]
struct ReplayWindow {
    highest: Option<u64>,
    seen: u128,
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
        if behind >= REPLAY_WINDOW_BITS {
            return true;
        }
        self.seen & bit(behind) != 0
    }

    fn accept(&mut self, counter: u64) -> bool {
        let Some(highest) = self.highest else {
            self.highest = Some(counter);
            self.seen = 1;
            return true;
        };

        if counter > highest {
            let advance = counter - highest;
            self.seen = if advance >= REPLAY_WINDOW_BITS {
                0
            } else {
                self.seen << advance
            };
            self.seen |= 1;
            self.highest = Some(counter);
            return true;
        }

        let behind = highest - counter;
        if behind >= REPLAY_WINDOW_BITS {
            return false;
        }
        let mask = bit(behind);
        if self.seen & mask != 0 {
            return false;
        }
        self.seen |= mask;
        true
    }
}

fn bit(offset: u64) -> u128 {
    1u128 << offset
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
        assert!(window.accept(128));
        assert!(!window.accept(1));

        assert!(window.accept(129));
        assert!(!window.accept(1));
        assert!(window.accept(2));
    }
}
