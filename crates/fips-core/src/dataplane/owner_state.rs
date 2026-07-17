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
            pending_replay_counters: std::collections::HashSet::new(),
            previous_fmp_replay_window: None,
            previous_fsp_replay_window: None,
            pending: VecDeque::new(),
        }
    }

    pub(crate) fn rekey(&mut self, generation: u64) {
        self.generation = generation;
        self.replay_window.clear();
        self.pending_replay_counters.clear();
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

    pub(crate) fn clear_fmp_pending_receive_epoch(&mut self) -> bool {
        if self.owner.protocol() != PacketProtocol::Fmp {
            return false;
        }
        self.pending_fmp_open = None;
        self.pending_fmp_k_bit = None;
        self.pending_fmp_replay_window = None;
        true
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

    #[cfg(test)]
    pub(crate) fn fsp_coords_warmup_remaining(&self) -> u8 {
        self.fsp_coords_warmup_remaining
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

    fn complete_replay_reservation(
        &mut self,
        reservation: &OwnerReservation,
        authenticated: bool,
    ) -> bool {
        let Some(receive_k_bit) = reservation.receive_k_bit else {
            return true;
        };
        let was_pending = self
            .pending_replay_counters
            .remove(&(receive_k_bit, reservation.counter));
        if !authenticated {
            return true;
        }
        was_pending
            && self
                .replay_window_for_k_bit_mut(receive_k_bit)
                .is_some_and(|window| window.accept(reservation.counter))
    }

    fn replay_window_for_k_bit_mut(&mut self, receive_k_bit: bool) -> Option<&mut ReplayWindow> {
        match self.owner.protocol() {
            PacketProtocol::Fmp if self.fmp_current_k_bit == receive_k_bit => {
                Some(&mut self.replay_window)
            }
            PacketProtocol::Fmp if self.pending_fmp_k_bit == Some(receive_k_bit) => {
                self.pending_fmp_replay_window.as_mut()
            }
            PacketProtocol::Fmp if self.fmp_previous_draining_k_bit == Some(receive_k_bit) => {
                self.previous_fmp_replay_window.as_mut()
            }
            PacketProtocol::Fsp if self.fsp_current_k_bit == receive_k_bit => {
                Some(&mut self.replay_window)
            }
            PacketProtocol::Fsp if self.pending_fsp_k_bit == Some(receive_k_bit) => {
                self.pending_fsp_replay_window.as_mut()
            }
            PacketProtocol::Fsp if self.fsp_previous_draining_k_bit == Some(receive_k_bit) => {
                self.previous_fsp_replay_window.as_mut()
            }
            _ => None,
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
}
