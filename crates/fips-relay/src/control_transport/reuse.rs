//! Idle entries retain only connection identity and expiry, with no admission permit.
use super::*;

const MAX_IDLE_STREAMS: usize = 8;
const IDLE_TIMEOUT: Duration = Duration::from_secs(5);

struct IdleStream {
    peer: PeerIdentity,
    outbound: bool,
    since: Instant,
}

#[derive(Default)]
pub(super) struct IdleStreams {
    streams: HashMap<ConnectionId, IdleStream>,
}

impl IdleStreams {
    pub(super) async fn park(
        &mut self,
        tcp: &mut FipsTcpEndpoint,
        id: ConnectionId,
        peer: PeerIdentity,
        outbound: bool,
        now: u64,
    ) {
        if tcp.state(id) != Some(State::Established) || tcp.is_read_closed(id) {
            let _ = tcp.close(id, now).await;
            return;
        }
        let previous = self.streams.iter().find_map(|(id, stream)| {
            (stream.peer == peer && stream.outbound == outbound).then_some(*id)
        });
        if let Some(previous) = previous {
            self.close(tcp, previous, now).await;
        }
        if self.streams.len() == MAX_IDLE_STREAMS {
            self.evict(tcp, None, now).await;
        }
        self.streams.insert(
            id,
            IdleStream {
                peer,
                outbound,
                since: Instant::now(),
            },
        );
    }

    pub(super) fn take(
        &mut self,
        tcp: &FipsTcpEndpoint,
        peer: PeerIdentity,
    ) -> Option<ConnectionId> {
        let id = self.streams.iter().find_map(|(id, stream)| {
            (stream.peer == peer
                && stream.outbound
                && tcp.state(*id) == Some(State::Established)
                && !tcp.is_read_closed(*id))
            .then_some(*id)
        })?;
        self.streams.remove(&id);
        Some(id)
    }

    pub(super) async fn evict(
        &mut self,
        tcp: &mut FipsTcpEndpoint,
        peer: Option<PeerIdentity>,
        now: u64,
    ) {
        let oldest = self
            .streams
            .iter()
            .min_by_key(|(_, stream)| (peer.is_some_and(|p| p != stream.peer), stream.since))
            .map(|(id, _)| *id);
        if let Some(id) = oldest {
            self.close(tcp, id, now).await;
        }
    }

    async fn close(&mut self, tcp: &mut FipsTcpEndpoint, id: ConnectionId, now: u64) {
        self.streams.remove(&id);
        // A completed response may still await its TCP acknowledgment. Graceful
        // closure preserves those bytes; eviction must never discard a reply.
        let _ = tcp.close(id, now).await;
    }

    pub(super) async fn ready(
        &mut self,
        tcp: &mut FipsTcpEndpoint,
        admission: Arc<ControlAdmission>,
        now: u64,
        statistics: &ControlStatistics,
    ) -> Vec<(ConnectionId, Exchange)> {
        let ids: Vec<_> = self.streams.keys().copied().collect();
        let mut requests = Vec::new();
        for id in ids {
            let stream = self.streams.remove(&id).expect("current idle stream");
            if stream.since.elapsed() >= IDLE_TIMEOUT
                || !matches!(tcp.state(id), Some(State::Established | State::CloseWait))
            {
                let _ = tcp.close(id, now).await;
                continue;
            }
            // Only a record prefix is read before fresh admission. Idle clients
            // reject unsolicited response bytes instead of carrying them into
            // a later request; a stream never has two outstanding requests.
            let received = tcp.read(id, 4, now).await;
            if let Ok(bytes) = &received
                && !bytes.is_empty()
            {
                statistics
                    .received
                    .fetch_add(bytes.len() as u64, Ordering::Relaxed);
            }
            match received {
                Ok(bytes) if !bytes.is_empty() && !stream.outbound => {
                    requests.push((
                        id,
                        Exchange::server(
                            stream.peer,
                            AdmissionCheck::start(admission.clone(), stream.peer, false),
                            bytes,
                        ),
                    ));
                }
                Ok(bytes) if bytes.is_empty() => {
                    if tcp.is_read_closed(id) {
                        let _ = tcp.close(id, now).await;
                    } else {
                        self.streams.insert(id, stream);
                    }
                }
                _ => {
                    let _ = tcp.abort(id).await;
                }
            }
        }
        requests
    }
}
