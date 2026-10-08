// Cancellation belongs to the physical generation, including the interval
// before asynchronous setup publishes a pending or connected logical owner.
impl PhysicalResources {
    pub(super) fn cancel_current_setup(&self, addr: &TransportAddr) -> Option<u64> {
        let mut state = self.0.state.lock().expect("WebRTC physical state");
        let slot = state.peers.get_mut(addr)?;
        slot.setup_cancelled = true;
        Some(slot.generation)
    }

    fn current_setup_generation(&self, addr: &TransportAddr) -> Option<u64> {
        if !self.is_accepting() {
            return None;
        }
        self.0
            .state
            .lock()
            .expect("WebRTC physical state")
            .peers
            .get(addr)
            .filter(|slot| {
                !slot.setup_cancelled
                    && matches!(slot.phase, PhysicalPhase::Creating | PhysicalPhase::Active)
            })
            .map(|slot| slot.generation)
    }

    pub(super) fn has_connecting_owner(&self, addr: &TransportAddr) -> bool {
        self.current_setup_generation(addr).is_some()
    }
}

impl PhysicalReservation {
    pub(super) fn setup_is_current(&self) -> bool {
        self.resources.current_setup_generation(&self.addr) == Some(self.generation)
    }
}

impl ManagedPeerConnection {
    pub(super) fn setup_is_current(&self) -> bool {
        self.lease
            .lock()
            .expect("WebRTC physical lease")
            .as_ref()
            .is_some_and(|lease| {
                lease.resources.current_setup_generation(&lease.addr) == Some(lease.generation)
            })
    }
}
