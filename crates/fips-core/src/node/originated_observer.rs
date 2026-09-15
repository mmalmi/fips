//! Optional local evidence for an embedding application's outgoing accounting.

use super::ForwardingOutcome;
use crate::NodeAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

#[derive(Debug)]
pub struct OriginatedSessionRequest<'a> {
    /// Local sender identity; provenance comes from local packet creation,
    /// never by trusting a source address in received transit traffic.
    pub source: NodeAddr,
    pub destination: NodeAddr,
    pub next_hop: NodeAddr,
    /// Immutable session envelope, excluding FMP TTL/MTU and link headers.
    pub session_payload: &'a [u8],
}

/// Observe locally originated FMP session envelopes and their local transport
/// outcomes. This is not packet admission or proof of neighbor/destination
/// delivery. Returning `None` opts out of tracking and does not block sending.
///
/// Callbacks run on the packet-processing path and must not wait on disk,
/// networking or payment validation. Keep bounded in-memory evidence and let
/// the application's controller separately decide which payments it authorizes.
pub trait OriginatedSessionObserver: std::fmt::Debug + Send + Sync + 'static {
    fn observe(&self, request: &OriginatedSessionRequest<'_>) -> Option<u64>;
    fn complete(&self, token: u64, outcome: ForwardingOutcome);
}

#[derive(Debug)]
struct ObservationState {
    observer: Arc<dyn OriginatedSessionObserver>,
    token: u64,
    completed: AtomicBool,
}

/// Crypto work/output clones share one completion obligation. The final owner
/// reports an uncertain outcome if no complete local submission was observed.
#[derive(Debug, Clone)]
pub(crate) struct OriginatedSessionObservation(Arc<ObservationState>);

impl PartialEq for OriginatedSessionObservation {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for OriginatedSessionObservation {}

impl OriginatedSessionObservation {
    pub(crate) fn start(
        observer: &Arc<dyn OriginatedSessionObserver>,
        request: &OriginatedSessionRequest<'_>,
    ) -> Option<Self> {
        observer.observe(request).map(|token| {
            Self(Arc::new(ObservationState {
                observer: Arc::clone(observer),
                token,
                completed: AtomicBool::new(false),
            }))
        })
    }

    pub(crate) fn submitted(&self) {
        if !self.0.completed.swap(true, Ordering::AcqRel) {
            self.0
                .observer
                .complete(self.0.token, ForwardingOutcome::Submitted);
        }
    }
}

impl Drop for ObservationState {
    fn drop(&mut self) {
        if !self.completed.swap(true, Ordering::AcqRel) {
            self.observer
                .complete(self.token, ForwardingOutcome::Unconfirmed);
        }
    }
}

impl super::Node {
    pub fn set_originated_session_observer(
        &mut self,
        observer: Option<Arc<dyn OriginatedSessionObserver>>,
    ) {
        self.dataplane
            .set_originated_session_observer(observer.clone());
        self.originated_session_observer = observer;
    }

    pub(in crate::node) async fn send_dataplane_originated_session(
        &mut self,
        next_hop: &NodeAddr,
        encoded: &[u8],
    ) -> Result<(), super::NodeError> {
        let observation = self
            .originated_session_observer
            .as_ref()
            .and_then(|observer| {
                if encoded.first().copied()
                    != Some(crate::protocol::LinkMessageType::SessionDatagram.to_byte())
                {
                    return None;
                }
                let packet = crate::protocol::SessionDatagramRef::decode(&encoded[1..]).ok()?;
                if packet.src_addr != *self.node_addr() {
                    return None;
                }
                OriginatedSessionObservation::start(
                    observer,
                    &OriginatedSessionRequest {
                        source: packet.src_addr,
                        destination: packet.dest_addr,
                        next_hop: *next_hop,
                        session_payload: packet.payload,
                    },
                )
            });
        self.send_dataplane_fmp_link_plaintext(next_hop, encoded, false)
            .await?;
        if let Some(observation) = observation {
            observation.submitted();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Observer(Mutex<Vec<ForwardingOutcome>>);
    impl OriginatedSessionObserver for Observer {
        fn observe(&self, _: &OriginatedSessionRequest<'_>) -> Option<u64> {
            Some(1)
        }
        fn complete(&self, _: u64, outcome: ForwardingOutcome) {
            self.0.lock().unwrap().push(outcome);
        }
    }

    #[test]
    fn originated_observation_clones_submit_or_cancel_exactly_once() {
        for submitted in [false, true] {
            let observer = Arc::new(Observer::default());
            let policy: Arc<dyn OriginatedSessionObserver> = observer.clone();
            let observation = OriginatedSessionObservation::start(
                &policy,
                &OriginatedSessionRequest {
                    source: NodeAddr::from_bytes([1; 16]),
                    destination: NodeAddr::from_bytes([2; 16]),
                    next_hop: NodeAddr::from_bytes([3; 16]),
                    session_payload: b"opaque",
                },
            )
            .unwrap();
            let copy = observation.clone();
            drop(observation);
            assert!(observer.0.lock().unwrap().is_empty());
            if submitted {
                copy.submitted();
                copy.submitted();
            }
            drop(copy);
            assert_eq!(
                *observer.0.lock().unwrap(),
                vec![if submitted {
                    ForwardingOutcome::Submitted
                } else {
                    ForwardingOutcome::Unconfirmed
                }]
            );
        }
    }
}
