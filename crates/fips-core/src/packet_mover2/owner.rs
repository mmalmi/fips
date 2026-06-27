#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerConfig {
    generation: u64,
    in_flight_limit: usize,
    next_send_counter: u64,
}

impl OwnerConfig {
    pub(crate) fn new(generation: u64, in_flight_limit: usize) -> Self {
        Self {
            generation,
            in_flight_limit,
            next_send_counter: 0,
        }
    }

    pub(crate) fn with_next_send_counter(mut self, next_send_counter: u64) -> Self {
        self.next_send_counter = next_send_counter;
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
    output_path: Option<TransportPath>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerReserveError {
    Replay,
    InFlightFull,
    StaleGeneration,
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
    crypto_keys: Option<OwnerCryptoKeys>,
    active_path: Option<TransportPath>,
    last_rx_activity: Option<ActivityTick>,
    last_tx_activity: Option<ActivityTick>,
    last_hard_event: Option<ActivityTick>,
    hard_events: u64,
    accepted_counters: HashSet<u64>,
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
            crypto_keys: None,
            active_path: None,
            last_rx_activity: None,
            last_tx_activity: None,
            last_hard_event: None,
            hard_events: 0,
            accepted_counters: HashSet::new(),
            pending: BTreeMap::new(),
        }
    }

    pub(crate) fn rekey(&mut self, generation: u64) {
        self.generation = generation;
        self.accepted_counters.clear();
        self.next_send_counter = 0;
        self.crypto_keys = None;
    }

    pub(crate) fn set_crypto_keys(&mut self, keys: OwnerCryptoKeys) {
        self.crypto_keys = Some(keys);
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
        if self.accepted_counters.contains(&packet.counter) {
            return Err(OwnerReserveError::Replay);
        }
        if self.in_flight >= self.in_flight_limit {
            return Err(OwnerReserveError::InFlightFull);
        }

        self.accepted_counters.insert(packet.counter);
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
            output_path: None,
        })
    }

    pub(crate) fn reserve_outbound(
        &mut self,
        packet: &OutboundPacket,
        ingress_seq: u64,
    ) -> Result<OwnerReservation, OwnerReserveError> {
        if packet.generation != self.generation {
            return Err(OwnerReserveError::StaleGeneration);
        }
        if self.in_flight >= self.in_flight_limit {
            return Err(OwnerReserveError::InFlightFull);
        }

        let counter = self.next_send_counter;
        let output_path = self.active_path.clone();
        if let Some(tick) = packet.activity_tick {
            note_activity(&mut self.last_tx_activity, tick);
        }
        self.next_send_counter = self.next_send_counter.wrapping_add(1);
        self.in_flight += 1;
        let order = OrderToken(self.next_order);
        self.next_order = self.next_order.wrapping_add(1);
        Ok(OwnerReservation {
            owner: self.owner,
            generation: self.generation,
            order,
            ingress_seq,
            counter,
            lane: packet.lane(),
            output_path,
        })
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
                )));
                continue;
            }

            match completion.result {
                CryptoResult::Opened(output) => retired.push(RetiredPacket::Output(output)),
                CryptoResult::Sealed(output) => retired.push(RetiredPacket::Output(output)),
                CryptoResult::Outbound(packet) => retired.push(RetiredPacket::Outbound(packet)),
                CryptoResult::Failed => {
                    retired.push(RetiredPacket::Drop(PacketDrop::from_completion(
                        &completion,
                        PacketDropReason::CryptoFailed,
                    )));
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
