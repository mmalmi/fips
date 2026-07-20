impl OwnerState {
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

        if !replay_window.can_accept(packet.counter) {
            return Err(OwnerReserveError::Replay);
        }
        let receive_epoch = if use_previous_fmp_epoch || use_previous_fsp_epoch {
            DataplaneReceiveEpoch::Previous
        } else if use_pending_fmp_epoch || use_pending_fsp_epoch {
            DataplaneReceiveEpoch::Pending
        } else {
            DataplaneReceiveEpoch::Current
        };
        let receive_k_bit = match self.owner.protocol() {
            PacketProtocol::Fmp => packet.wire_flags & crate::node::wire::FLAG_KEY_EPOCH != 0,
            PacketProtocol::Fsp => packet.wire_flags & crate::node::session_wire::FSP_FLAG_K != 0,
        };
        if !self
            .pending_replay_counters
            .insert((receive_k_bit, packet.counter))
        {
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
                receive_k_bit: Some(receive_k_bit),
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
            if let Some(bytes) = fsp_application_data_len {
                if let Some(next_hop) = fsp_next_hop {
                    self.last_outbound_next_hop = Some(next_hop);
                }
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
            receive_k_bit: None,
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
        if dataplane_fsp_message_is_application_data(msg_type) {
            if let Some(tick) = activity_tick
                && note_activity(&mut self.last_rx_data_activity, tick)
            {
                self.last_rx_data_previous_hop = Some(previous_hop);
            }
            if self.last_outbound_next_hop == Some(previous_hop)
                && let Some(tick) = activity_tick
                && note_activity(&mut self.last_data_return_activity, tick)
            {
                self.last_data_return_next_hop = Some(previous_hop);
            }
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

    pub(crate) fn forget_fsp_data_route(&mut self, next_hop: NodeAddr) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp
            || self.last_outbound_next_hop != Some(next_hop)
        {
            return false;
        }
        self.last_outbound_next_hop = None;
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
        if *flags & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT != 0 {
            return;
        }
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
        if *flags & crate::node::session_wire::FSP_FLAG_U != 0 {
            return;
        }
        // Coordinates are only useful to FMP transit routing. A direct
        // carrier has a fixed 12-byte FSP record header, so discard any
        // pre-attached coordinate prefix without consuming the automatic
        // warmup budget; it remains available if this owner later routes.
        *flags &= !crate::node::session_wire::FSP_FLAG_CP;
        packet.fsp_cleartext_prefix.clear();
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
}
