use super::*;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PhysicalPhase {
    Creating,
    Active,
    Closing,
}

#[derive(Clone, Copy, Debug)]
struct PhysicalSlot {
    generation: u64,
    phase: PhysicalPhase,
    replacement_waiter: bool,
}

#[derive(Default)]
struct PhysicalState {
    next_generation: u64,
    peers: HashMap<TransportAddr, PhysicalSlot>,
    offer_handlers: HashSet<TransportAddr>,
    creating: usize,
    active: usize,
    closing: usize,
    cleanup_inflight: usize,
    abandoned: usize,
    created_total: u64,
    closed_total: u64,
    peak_physical: usize,
}

struct PhysicalResourceInner {
    capacity: usize,
    permits: Arc<Semaphore>,
    accepting: AtomicBool,
    state: StdMutex<PhysicalState>,
    cleanup_tasks: StdMutex<JoinSet<()>>,
    abandoned_permits: StdMutex<Vec<OwnedSemaphorePermit>>,
    idle: Notify,
    straggler_waiters: AtomicUsize,
    ice_stop_failures_total: AtomicU64,
}

/// Conservation counters for physical WebRTC peer connections.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WebRtcResourceSnapshot {
    /// Configured maximum simultaneous physical peer connections.
    pub capacity: usize,
    /// Capacity reserved before a peer connection is created.
    pub creating: usize,
    /// Created peer connections which are gathering, pending, or live.
    pub active: usize,
    /// Peer connections retaining capacity while physical close completes.
    pub closing: usize,
    /// Physical cleanup futures which have not completed.
    pub cleanup_inflight: usize,
    /// Closing owners whose cleanup was cancelled or unwound. Their permits
    /// remain retained so replacement fails closed.
    pub abandoned: usize,
    /// Cleanup jobs waiting for escaped raw peer-connection references.
    pub straggler_waiters: usize,
    /// Peer connections successfully created by this transport.
    pub created_total: u64,
    /// Peer connections whose physical cleanup completed.
    pub closed_total: u64,
    /// Explicit ICE stops which returned an error.
    pub ice_stop_failures_total: u64,
    /// Highest simultaneous `creating + active + closing` count.
    pub peak_physical: usize,
}

#[derive(Clone)]
pub(super) struct PhysicalResources(Arc<PhysicalResourceInner>);

#[derive(Clone)]
pub(super) struct WeakPhysicalResources(std::sync::Weak<PhysicalResourceInner>);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PhysicalReserveError {
    Stopped,
    PeerBusy(PhysicalPhase),
    Capacity,
}

pub(super) struct PhysicalReservation {
    resources: PhysicalResources,
    addr: TransportAddr,
    generation: u64,
    permit: Option<OwnedSemaphorePermit>,
}

struct PhysicalLease {
    resources: PhysicalResources,
    addr: TransportAddr,
    generation: u64,
    permit: Option<OwnedSemaphorePermit>,
}

pub(super) struct PhysicalCleanupGuard {
    resources: PhysicalResources,
    addr: TransportAddr,
    generation: u64,
    permit: Option<OwnedSemaphorePermit>,
}

pub(super) struct StragglerWaitGuard(PhysicalResources);

pub(super) struct PhysicalOfferGuard {
    resources: PhysicalResources,
    addr: TransportAddr,
}

struct PhysicalReleaseWaitGuard {
    resources: PhysicalResources,
    addr: TransportAddr,
    generation: u64,
}

pub(super) struct CleanupCompletion {
    done: AtomicBool,
    notify: Notify,
}

impl CleanupCompletion {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            done: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    pub(super) fn finish(&self) {
        self.done.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub(super) async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            if self.done.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

pub(super) struct ManagedPeerConnection {
    pc: Arc<RTCPeerConnection>,
    lease: StdMutex<Option<PhysicalLease>>,
    cleanup: Arc<CleanupCompletion>,
}

pub(super) type ManagedPeer = Arc<ManagedPeerConnection>;

#[derive(Clone)]
pub(super) struct WebRtcSessionOwner {
    pub(super) session_id: Option<String>,
    pub(super) pc: Option<std::sync::Weak<ManagedPeerConnection>>,
    pub(super) generation: Option<u64>,
}

impl WebRtcSessionOwner {
    pub(super) fn new(session_id: &str, pc: &ManagedPeer) -> Self {
        Self {
            session_id: Some(session_id.to_string()),
            pc: Some(Arc::downgrade(pc)),
            generation: None,
        }
    }

    pub(super) fn for_generation(generation: u64) -> Self {
        Self {
            session_id: None,
            pc: None,
            generation: Some(generation),
        }
    }

    pub(super) fn matches(&self, session_id: &str, pc: &ManagedPeer) -> bool {
        self.session_id
            .as_deref()
            .is_none_or(|expected| expected == session_id)
            && self
                .pc
                .as_ref()
                .is_none_or(|expected| expected.ptr_eq(&Arc::downgrade(pc)))
            && self
                .generation
                .is_none_or(|expected| pc.physical_generation() == Some(expected))
    }
}

impl std::ops::Deref for ManagedPeerConnection {
    type Target = RTCPeerConnection;

    fn deref(&self) -> &Self::Target {
        &self.pc
    }
}

impl PhysicalResources {
    pub(super) fn new(capacity: usize) -> Self {
        Self(Arc::new(PhysicalResourceInner {
            capacity,
            permits: Arc::new(Semaphore::new(capacity)),
            accepting: AtomicBool::new(true),
            state: StdMutex::new(PhysicalState::default()),
            cleanup_tasks: StdMutex::new(JoinSet::new()),
            abandoned_permits: StdMutex::new(Vec::new()),
            idle: Notify::new(),
            straggler_waiters: AtomicUsize::new(0),
            ice_stop_failures_total: AtomicU64::new(0),
        }))
    }

    pub(super) fn downgrade(&self) -> WeakPhysicalResources {
        WeakPhysicalResources(Arc::downgrade(&self.0))
    }

    pub(super) fn start_accepting(&self) {
        self.0.accepting.store(true, Ordering::Release);
    }

    pub(super) fn stop_accepting(&self) {
        self.0.accepting.store(false, Ordering::Release);
        self.0.idle.notify_waiters();
    }

    pub(super) fn is_accepting(&self) -> bool {
        self.0.accepting.load(Ordering::Acquire)
    }

    pub(super) fn generation(&self, addr: &TransportAddr) -> Option<u64> {
        self.0
            .state
            .lock()
            .expect("WebRTC physical state")
            .peers
            .get(addr)
            .map(|slot| slot.generation)
    }

    pub(super) fn reserve(
        &self,
        addr: &TransportAddr,
    ) -> Result<PhysicalReservation, PhysicalReserveError> {
        self.reap_cleanup_tasks();
        if !self.0.accepting.load(Ordering::Acquire) {
            return Err(PhysicalReserveError::Stopped);
        }

        let mut state = self.0.state.lock().expect("WebRTC physical state");
        if let Some(slot) = state.peers.get(addr) {
            return Err(PhysicalReserveError::PeerBusy(slot.phase));
        }
        let permit = Arc::clone(&self.0.permits)
            .try_acquire_owned()
            .map_err(|_| PhysicalReserveError::Capacity)?;
        let generation = state.next_generation;
        state.next_generation = state.next_generation.wrapping_add(1);
        state.peers.insert(
            addr.clone(),
            PhysicalSlot {
                generation,
                phase: PhysicalPhase::Creating,
                replacement_waiter: false,
            },
        );
        state.creating += 1;
        let physical = state.creating + state.active + state.closing;
        state.peak_physical = state.peak_physical.max(physical);
        drop(state);
        self.assert_conservation();
        Ok(PhysicalReservation {
            resources: self.clone(),
            addr: addr.clone(),
            generation,
            permit: Some(permit),
        })
    }

    pub(super) fn phase(&self, addr: &TransportAddr) -> Option<PhysicalPhase> {
        self.0
            .state
            .lock()
            .expect("WebRTC physical state")
            .peers
            .get(addr)
            .map(|slot| slot.phase)
    }

    pub(super) fn try_claim_offer(&self, addr: &TransportAddr) -> Option<PhysicalOfferGuard> {
        if !self.is_accepting() {
            return None;
        }
        let mut state = self.0.state.lock().expect("WebRTC physical state");
        if !state.offer_handlers.insert(addr.clone()) {
            return None;
        }
        Some(PhysicalOfferGuard {
            resources: self.clone(),
            addr: addr.clone(),
        })
    }

    pub(super) fn snapshot(&self) -> WebRtcResourceSnapshot {
        // Conservation counters are transitioned and sampled under the same
        // lock so callers never observe a legal phase change half-applied.
        let state = self.0.state.lock().expect("WebRTC physical state");
        WebRtcResourceSnapshot {
            capacity: self.0.capacity,
            creating: state.creating,
            active: state.active,
            closing: state.closing,
            cleanup_inflight: state.cleanup_inflight,
            abandoned: state.abandoned,
            straggler_waiters: self.0.straggler_waiters.load(Ordering::Acquire),
            created_total: state.created_total,
            closed_total: state.closed_total,
            ice_stop_failures_total: self.0.ice_stop_failures_total.load(Ordering::Acquire),
            peak_physical: state.peak_physical,
        }
    }

    pub(super) fn spawn_cleanup<F>(&self, cleanup: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        self.reap_cleanup_tasks();
        self.0
            .cleanup_tasks
            .lock()
            .expect("WebRTC cleanup task set")
            .spawn(cleanup);
    }

    fn reap_cleanup_tasks(&self) {
        let mut tasks = self
            .0
            .cleanup_tasks
            .lock()
            .expect("WebRTC cleanup task set");
        while tasks.try_join_next().is_some() {}
    }

    pub(super) async fn wait_for_quiescence(&self, timeout: Duration) -> bool {
        let wait = async {
            loop {
                let notified = self.0.idle.notified();
                let snapshot = self.snapshot();
                if snapshot.creating + snapshot.active + snapshot.closing == 0 {
                    return;
                }
                notified.await;
            }
        };
        let quiescent = tokio::time::timeout(timeout, wait).await.is_ok();
        self.reap_cleanup_tasks();
        quiescent
    }

    pub(super) async fn wait_for_peer_release(
        &self,
        addr: &TransportAddr,
        timeout: Duration,
    ) -> bool {
        let waiter = {
            let mut state = self.0.state.lock().expect("WebRTC physical state");
            let Some(slot) = state.peers.get_mut(addr) else {
                return self.is_accepting();
            };
            if slot.phase != PhysicalPhase::Closing || slot.replacement_waiter {
                return false;
            }
            slot.replacement_waiter = true;
            PhysicalReleaseWaitGuard {
                resources: self.clone(),
                addr: addr.clone(),
                generation: slot.generation,
            }
        };
        let wait = async {
            loop {
                let notified = self.0.idle.notified();
                if !self.is_accepting() {
                    return false;
                }
                let phase = {
                    let state = self.0.state.lock().expect("WebRTC physical state");
                    match state.peers.get(addr) {
                        None => return true,
                        Some(slot) if slot.generation != waiter.generation => return false,
                        Some(slot) => slot.phase,
                    }
                };
                match phase {
                    PhysicalPhase::Closing => notified.await,
                    PhysicalPhase::Creating | PhysicalPhase::Active => return false,
                }
            }
        };
        let released = tokio::time::timeout(timeout, wait).await.unwrap_or(false);
        drop(waiter);
        released
    }

    #[cfg(test)]
    pub(super) fn has_peer_release_waiter(&self, addr: &TransportAddr) -> bool {
        self.0
            .state
            .lock()
            .expect("WebRTC physical state")
            .peers
            .get(addr)
            .is_some_and(|slot| slot.replacement_waiter)
    }

    #[cfg(test)]
    pub(super) fn has_offer_handler(&self, addr: &TransportAddr) -> bool {
        self.0
            .state
            .lock()
            .expect("WebRTC physical state")
            .offer_handlers
            .contains(addr)
    }

    pub(super) fn note_ice_stop_failure(&self) {
        self.0
            .ice_stop_failures_total
            .fetch_add(1, Ordering::AcqRel);
    }

    pub(super) fn begin_straggler_wait(&self) -> StragglerWaitGuard {
        self.0.straggler_waiters.fetch_add(1, Ordering::AcqRel);
        StragglerWaitGuard(self.clone())
    }

    fn assert_conservation(&self) {
        let snapshot = self.snapshot();
        debug_assert!(snapshot.active + snapshot.closing <= snapshot.capacity);
        debug_assert!(snapshot.creating + snapshot.active + snapshot.closing <= self.0.capacity);
        debug_assert_eq!(
            snapshot.cleanup_inflight + snapshot.abandoned,
            snapshot.closing
        );
        debug_assert!(snapshot.created_total >= snapshot.closed_total);
        debug_assert_eq!(
            snapshot.created_total.checked_sub(snapshot.closed_total),
            Some((snapshot.active + snapshot.closing) as u64)
        );
    }
}

impl Drop for StragglerWaitGuard {
    fn drop(&mut self) {
        self.0.0.straggler_waiters.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for PhysicalOfferGuard {
    fn drop(&mut self) {
        self.resources
            .0
            .state
            .lock()
            .expect("WebRTC physical state")
            .offer_handlers
            .remove(&self.addr);
    }
}

impl Drop for PhysicalReleaseWaitGuard {
    fn drop(&mut self) {
        let mut state = self
            .resources
            .0
            .state
            .lock()
            .expect("WebRTC physical state");
        if let Some(slot) = state.peers.get_mut(&self.addr)
            && slot.generation == self.generation
        {
            slot.replacement_waiter = false;
        }
    }
}

impl WeakPhysicalResources {
    pub(super) fn upgrade(&self) -> Option<PhysicalResources> {
        self.0.upgrade().map(PhysicalResources)
    }
}

impl PhysicalReservation {
    fn into_lease(mut self) -> PhysicalLease {
        {
            let mut state = self
                .resources
                .0
                .state
                .lock()
                .expect("WebRTC physical state");
            let slot = state
                .peers
                .get_mut(&self.addr)
                .expect("reserved WebRTC peer");
            debug_assert_eq!(slot.generation, self.generation);
            debug_assert_eq!(slot.phase, PhysicalPhase::Creating);
            slot.phase = PhysicalPhase::Active;
            state.creating -= 1;
            state.active += 1;
            state.created_total += 1;
        }
        self.resources.assert_conservation();
        PhysicalLease {
            resources: self.resources.clone(),
            addr: self.addr.clone(),
            generation: self.generation,
            permit: self.permit.take(),
        }
    }

    pub(super) fn activate(self, pc: RTCPeerConnection) -> ManagedPeer {
        Arc::new(ManagedPeerConnection {
            pc: Arc::new(pc),
            lease: StdMutex::new(Some(self.into_lease())),
            cleanup: CleanupCompletion::new(),
        })
    }
}

impl Drop for PhysicalReservation {
    fn drop(&mut self) {
        if self.permit.is_none() {
            return;
        }
        let mut state = self
            .resources
            .0
            .state
            .lock()
            .expect("WebRTC physical state");
        if state.peers.get(&self.addr).is_some_and(|slot| {
            slot.generation == self.generation && slot.phase == PhysicalPhase::Creating
        }) {
            state.peers.remove(&self.addr);
            state.creating -= 1;
        }
        drop(state);
        self.resources.0.idle.notify_waiters();
        self.resources.assert_conservation();
    }
}

impl PhysicalLease {
    fn begin_cleanup(mut self) -> PhysicalCleanupGuard {
        {
            let mut state = self
                .resources
                .0
                .state
                .lock()
                .expect("WebRTC physical state");
            let slot = state.peers.get_mut(&self.addr).expect("active WebRTC peer");
            debug_assert_eq!(slot.generation, self.generation);
            debug_assert_eq!(slot.phase, PhysicalPhase::Active);
            slot.phase = PhysicalPhase::Closing;
            state.active -= 1;
            state.closing += 1;
            state.cleanup_inflight += 1;
        }
        self.resources.assert_conservation();
        PhysicalCleanupGuard {
            resources: self.resources.clone(),
            addr: self.addr.clone(),
            generation: self.generation,
            permit: self.permit.take(),
        }
    }
}

impl Drop for PhysicalCleanupGuard {
    fn drop(&mut self) {
        let Some(permit) = self.permit.take() else {
            return;
        };
        // Cancellation or unwind is not evidence that ICE/SCTP/DTLS closed.
        // Retain the physical permit and Closing slot for the lifetime of this
        // manager so no replacement can allocate around an unknown owner.
        {
            let mut state = self
                .resources
                .0
                .state
                .lock()
                .expect("WebRTC physical state");
            state.cleanup_inflight -= 1;
            state.abandoned += 1;
        }
        self.resources
            .0
            .abandoned_permits
            .lock()
            .expect("WebRTC abandoned permits")
            .push(permit);
        self.resources.0.idle.notify_waiters();
        self.resources.assert_conservation();
    }
}

impl PhysicalCleanupGuard {
    pub(super) fn complete(mut self) {
        let mut state = self
            .resources
            .0
            .state
            .lock()
            .expect("WebRTC physical state");
        let owns_closing_slot = state.peers.get(&self.addr).is_some_and(|slot| {
            slot.generation == self.generation && slot.phase == PhysicalPhase::Closing
        });
        if !owns_closing_slot {
            drop(state);
            return;
        }
        state.peers.remove(&self.addr);
        state.cleanup_inflight -= 1;
        state.closing -= 1;
        state.closed_total += 1;
        drop(state);
        let permit = self
            .permit
            .take()
            .expect("completed WebRTC cleanup owns its permit");
        drop(permit);
        self.resources.0.idle.notify_waiters();
        self.resources.assert_conservation();
    }

    pub(super) fn resources(&self) -> PhysicalResources {
        self.resources.clone()
    }
}

impl ManagedPeerConnection {
    #[cfg(test)]
    pub(super) fn raw(&self) -> Arc<RTCPeerConnection> {
        Arc::clone(&self.pc)
    }

    pub(super) fn begin_cleanup(
        &self,
    ) -> Option<(
        Arc<RTCPeerConnection>,
        PhysicalCleanupGuard,
        Arc<CleanupCompletion>,
    )> {
        let lease = self.lease.lock().expect("WebRTC physical lease").take()?;
        Some((
            Arc::clone(&self.pc),
            lease.begin_cleanup(),
            Arc::clone(&self.cleanup),
        ))
    }

    pub(super) fn is_closing(&self) -> bool {
        self.lease.lock().expect("WebRTC physical lease").is_none()
    }

    pub(super) fn physical_generation(&self) -> Option<u64> {
        self.lease
            .lock()
            .expect("WebRTC physical lease")
            .as_ref()
            .map(|lease| lease.generation)
    }

    pub(super) fn cleanup_completion(&self) -> Arc<CleanupCompletion> {
        Arc::clone(&self.cleanup)
    }
}

impl Drop for ManagedPeerConnection {
    fn drop(&mut self) {
        super::spawn_managed_peer_cleanup(self);
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;

    fn addr(value: &str) -> TransportAddr {
        TransportAddr::from_string(value)
    }

    #[test]
    fn physical_peer_owner_retains_cap_until_cleanup_finishes() {
        let resources = PhysicalResources::new(1);
        let reservation = resources.reserve(&addr("peer-a")).expect("first reserve");
        assert_eq!(resources.0.permits.available_permits(), 0);

        // Exercise the phase/permit state without constructing the library PC.
        let lease = reservation.into_lease();
        let cleanup = lease.begin_cleanup();

        assert_eq!(resources.snapshot().closing, 1);
        assert!(matches!(
            resources.reserve(&addr("peer-b")),
            Err(PhysicalReserveError::Capacity)
        ));
        cleanup.complete();
        assert_eq!(resources.snapshot().closing, 0);
        assert_eq!(resources.snapshot().closed_total, 1);
        assert!(resources.reserve(&addr("peer-b")).is_ok());
    }

    #[test]
    fn cancelled_cleanup_is_abandoned_and_retains_capacity() {
        let resources = PhysicalResources::new(1);
        let cleanup = resources
            .reserve(&addr("peer-a"))
            .expect("reserve")
            .into_lease()
            .begin_cleanup();

        drop(cleanup);
        let snapshot = resources.snapshot();
        assert_eq!(snapshot.capacity, 1);
        assert_eq!(snapshot.closing, 1);
        assert_eq!(snapshot.cleanup_inflight, 0);
        assert_eq!(snapshot.abandoned, 1);
        assert_eq!(snapshot.closed_total, 0);
        assert_eq!(snapshot.created_total - snapshot.closed_total, 1);
        assert!(matches!(
            resources.reserve(&addr("peer-b")),
            Err(PhysicalReserveError::Capacity)
        ));
    }

    #[test]
    fn same_peer_cannot_overlap_while_closing() {
        let resources = PhysicalResources::new(2);
        let reservation = resources.reserve(&addr("peer-a")).expect("reserve");
        assert!(matches!(
            resources.reserve(&addr("peer-a")),
            Err(PhysicalReserveError::PeerBusy(PhysicalPhase::Creating))
        ));
        drop(reservation);
        assert!(resources.reserve(&addr("peer-a")).is_ok());
    }

    #[test]
    fn zero_capacity_refuses_physical_peer_creation() {
        let resources = PhysicalResources::new(0);
        assert!(matches!(
            resources.reserve(&addr("peer-a")),
            Err(PhysicalReserveError::Capacity)
        ));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn release_waiter_does_not_follow_a_new_peer_generation() {
        let resources = PhysicalResources::new(1);
        let peer = addr("peer-a");
        let first_cleanup = resources
            .reserve(&peer)
            .expect("first reserve")
            .into_lease()
            .begin_cleanup();
        let old_resources = resources.clone();
        let old_peer = peer.clone();
        let old_waiter = tokio::spawn(async move {
            old_resources
                .wait_for_peer_release(&old_peer, Duration::from_secs(1))
                .await
        });
        while !resources.has_peer_release_waiter(&peer) {
            tokio::task::yield_now().await;
        }

        first_cleanup.complete();
        // Do not yield between generations: the old waiter must observe that
        // this Closing slot is a different owner rather than following it.
        let second_cleanup = resources
            .reserve(&peer)
            .expect("second reserve")
            .into_lease()
            .begin_cleanup();
        let new_resources = resources.clone();
        let new_peer = peer.clone();
        let new_waiter = tokio::spawn(async move {
            new_resources
                .wait_for_peer_release(&new_peer, Duration::from_secs(1))
                .await
        });

        let old_released = tokio::time::timeout(Duration::from_millis(100), old_waiter)
            .await
            .expect("old waiter does not follow the new generation")
            .expect("old waiter task");
        assert!(!old_released);
        while !resources.has_peer_release_waiter(&peer) {
            tokio::task::yield_now().await;
        }
        second_cleanup.complete();
        assert!(new_waiter.await.expect("new waiter task"));
    }

    #[test]
    fn concurrent_phase_changes_expose_only_conserved_snapshots() {
        let resources = PhysicalResources::new(4);
        let done = Arc::new(AtomicBool::new(false));
        let observer_resources = resources.clone();
        let observer_done = Arc::clone(&done);
        let observer = std::thread::spawn(move || {
            while !observer_done.load(Ordering::Acquire) {
                let snapshot = observer_resources.snapshot();
                assert!(
                    snapshot.creating + snapshot.active + snapshot.closing <= snapshot.capacity
                );
                assert_eq!(
                    snapshot.cleanup_inflight + snapshot.abandoned,
                    snapshot.closing
                );
                assert_eq!(
                    snapshot.created_total.checked_sub(snapshot.closed_total),
                    Some((snapshot.active + snapshot.closing) as u64)
                );
                std::thread::yield_now();
            }
        });

        let workers = (0..8)
            .map(|worker| {
                let resources = resources.clone();
                std::thread::spawn(move || {
                    let peer = addr(&format!("peer-{worker}"));
                    for iteration in 0..256 {
                        let reservation = loop {
                            match resources.reserve(&peer) {
                                Ok(reservation) => break reservation,
                                Err(PhysicalReserveError::Capacity) => std::thread::yield_now(),
                                Err(error) => panic!("unexpected reservation error: {error:?}"),
                            }
                        };
                        if iteration % 5 == 0 {
                            drop(reservation);
                        } else {
                            reservation.into_lease().begin_cleanup().complete();
                        }
                    }
                })
            })
            .collect::<Vec<_>>();
        let results = workers
            .into_iter()
            .map(std::thread::JoinHandle::join)
            .collect::<Vec<_>>();
        done.store(true, Ordering::Release);
        observer.join().expect("snapshot observer");
        for result in results {
            result.expect("lifecycle worker");
        }

        let snapshot = resources.snapshot();
        assert_eq!(snapshot.creating + snapshot.active + snapshot.closing, 0);
        assert_eq!(snapshot.created_total, snapshot.closed_total);
        assert!(snapshot.peak_physical <= snapshot.capacity);
    }
}
