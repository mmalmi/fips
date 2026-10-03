impl DataplaneFspSessionIngress {
    pub(crate) fn received_k_bit(&self) -> bool {
        self.receive_sync.received_k_bit
    }

    pub(crate) fn is_pending_epoch(&self) -> bool {
        matches!(
            self.receive_sync.receive_epoch,
            Some((DataplaneReceiveEpoch::Pending, _))
        )
    }

    pub(crate) fn is_previous_epoch(&self) -> bool {
        matches!(
            self.receive_sync.receive_epoch,
            Some((DataplaneReceiveEpoch::Previous, _))
        )
    }
}

impl OwnerState {
    fn fsp_alternate_receive_epoch(
        &self,
        packet: &SocketPacket,
        selected: DataplaneReceiveEpoch,
    ) -> Option<(DataplaneReceiveEpoch, u64)> {
        if self.owner.protocol() != PacketProtocol::Fsp
            || selected != DataplaneReceiveEpoch::Current
            || (packet.wire_flags & crate::node::session_wire::FSP_FLAG_K != 0)
                != self.fsp_current_k_bit
        {
            return None;
        }
        if self.pending_fsp_open.is_some() && self.pending_fsp_replay_window.is_some() {
            Some((
                DataplaneReceiveEpoch::Pending,
                self.pending_receive_epoch_instance,
            ))
        } else if self.fsp_previous_draining_k_bit == Some(self.fsp_current_k_bit)
            && self.previous_fsp_open.is_some()
            && self.previous_fsp_replay_window.is_some()
        {
            Some((DataplaneReceiveEpoch::Previous, 0))
        } else {
            None
        }
    }

    fn resolved_receive_epoch(
        &self,
        reservation: &OwnerReservation,
        epoch: (DataplaneReceiveEpoch, u64),
    ) -> Option<(DataplaneReceiveEpoch, u64)> {
        if reservation.generation == self.generation {
            Some(epoch)
        } else if self.retains_draining_generation(reservation.generation) {
            self.remap_draining_receive_epoch(epoch)
        } else {
            None
        }
    }

    fn complete_replay_reservation(
        &mut self,
        reservation: &OwnerReservation,
        authenticated_epoch: Option<(DataplaneReceiveEpoch, u64)>,
    ) -> bool {
        let Some(primary) = reservation.receive_epoch else {
            return true;
        };
        let selected = authenticated_epoch.unwrap_or(primary);
        if selected != primary && Some(selected) != reservation.alternate_receive_epoch {
            return false;
        }
        let Some((epoch, instance)) = self.resolved_receive_epoch(reservation, selected) else {
            return false;
        };
        let reserved = if reservation.alternate_receive_epoch.is_some() {
            true
        } else {
            self.pending_replay_counters
                .remove(&((epoch, instance), reservation.counter))
        };
        if authenticated_epoch.is_none() {
            return true;
        }
        if epoch == DataplaneReceiveEpoch::Pending
            && instance != self.pending_receive_epoch_instance
        {
            return false;
        }
        let accepted = reserved
            && self
                .replay_window_for_epoch_mut(epoch)
                .is_some_and(|window| window.accept(reservation.counter));
        if accepted && epoch == DataplaneReceiveEpoch::Pending {
            match self.owner.protocol() {
                PacketProtocol::Fmp => {
                    self.pending_fmp_authenticated_k_bit.get_or_insert(
                        reservation.wire_flags & crate::node::wire::FLAG_KEY_EPOCH != 0,
                    );
                }
                PacketProtocol::Fsp => {
                    let k_bit = reservation.wire_flags & crate::node::session_wire::FSP_FLAG_K != 0;
                    self.pending_fsp_authenticated_k_bits |= 1 << u8::from(k_bit);
                }
            }
        }
        accepted
    }

    pub(crate) fn confirm_fsp_pending_receive_epoch(&mut self, received_k_bit: bool) -> bool {
        if self.owner.protocol() != PacketProtocol::Fsp
            || self.pending_fsp_authenticated_k_bits & (1 << u8::from(received_k_bit)) == 0
        {
            return false;
        }
        self.pending_fsp_k_bit = Some(received_k_bit);
        self.has_fsp_pending_receive_epoch(received_k_bit)
    }

    fn stamp_authenticated_receive_epoch(&self, completion: &mut CryptoCompletion) {
        if let CryptoResult::Opened(output) = &mut completion.result {
            output.authenticated_receive_epoch = output
                .authenticated_receive_epoch
                .or(completion.reservation.receive_epoch)
                .and_then(|epoch| self.resolved_receive_epoch(&completion.reservation, epoch));
        }
    }
}
