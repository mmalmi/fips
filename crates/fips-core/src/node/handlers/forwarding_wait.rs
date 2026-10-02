// Waiting here owns packet memory, never an accounting reservation.
use crate::transport::LinkId;

const ADMISSION_WAIT_PACKETS: usize = 512;
const ADMISSION_WAIT_BYTES: usize = 1024 * 1024;
const ADMISSION_WAIT_PEER_PACKETS: usize = 128;
const ADMISSION_WAIT_PEER_BYTES: usize = 256 * 1024;
const ADMISSION_RETRY_BATCH: usize = 32;
const ADMISSION_RETRY_DELAY: Duration = Duration::from_millis(50);
const ADMISSION_WAIT_LIMIT: Duration = Duration::from_secs(2);

struct WaitingAdmission {
    ingress: crate::PeerIdentity,
    link_id: LinkId,
    authenticated_at: u64,
    payload: Box<[u8]>,
    ce: bool,
    due: tokio::time::Instant,
    expires: tokio::time::Instant,
}

#[derive(Default)]
pub(in crate::node) struct WaitingAdmissions {
    packets: VecDeque<WaitingAdmission>,
    bytes: usize,
    peers: HashMap<NodeAddr, (usize, usize)>,
}

impl WaitingAdmissions {
    fn has_capacity(&self, peer: NodeAddr, len: usize) -> bool {
        let (count, bytes) = self.peers.get(&peer).copied().unwrap_or_default();
        self.packets.len() < ADMISSION_WAIT_PACKETS
            && len <= ADMISSION_WAIT_BYTES.saturating_sub(self.bytes)
            && count < ADMISSION_WAIT_PEER_PACKETS
            && len <= ADMISSION_WAIT_PEER_BYTES.saturating_sub(bytes)
    }

    fn insert(&mut self, packet: WaitingAdmission) -> bool {
        let len = packet.payload.len();
        let peer = *packet.ingress.node_addr();
        if !self.has_capacity(peer, len) {
            return false;
        }
        let (count, bytes) = self.peers.get(&peer).copied().unwrap_or_default();
        self.peers.insert(peer, (count + 1, bytes + len));
        self.bytes += len;
        if self
            .packets
            .back()
            .is_some_and(|last| last.due > packet.due)
        {
            let index = self
                .packets
                .iter()
                .position(|old| old.due > packet.due)
                .unwrap();
            self.packets.insert(index, packet);
        } else {
            self.packets.push_back(packet);
        }
        true
    }

    fn pop(&mut self) -> Option<WaitingAdmission> {
        let packet = self.packets.pop_front()?;
        Self::release_usage(&packet, &mut self.bytes, &mut self.peers);
        Some(packet)
    }

    fn release_usage(
        packet: &WaitingAdmission,
        bytes: &mut usize,
        peers: &mut HashMap<NodeAddr, (usize, usize)>,
    ) {
        *bytes -= packet.payload.len();
        let peer = packet.ingress.node_addr();
        let (count, bytes) = peers.get_mut(peer).expect("retained peer accounting");
        *count -= 1;
        *bytes -= packet.payload.len();
        if *count == 0 {
            peers.remove(peer);
        }
    }

    fn expire(&mut self, stats: &mut crate::node::stats::ForwardingStats) {
        let now = tokio::time::Instant::now();
        // Expiry covers the whole bounded queue, even if a send in the first
        // retry batch stalls. Retry order and expiry order can differ.
        self.packets.retain(|packet| {
            if packet.expires > now {
                return true;
            }
            Self::release_usage(packet, &mut self.bytes, &mut self.peers);
            stats.record_drop_policy_denied(packet.payload.len());
            false
        });
    }
}

impl Node {
    async fn handle_session_datagram_with_deadline(
        &mut self,
        datagram: AuthenticatedSessionDatagram<'_>,
        expires: Option<tokio::time::Instant>,
    ) {
        let payload = datagram.payload;
        match self
            .prepare_session_datagram_with_deadline(datagram, expires)
            .await
        {
            PreparedSessionDatagram::Forward(route) => {
                let plaintext = {
                    let _timer = crate::perf_profile::Timer::start(
                        crate::perf_profile::Stage::TransitEncode,
                    );
                    copy_forwarded_session_datagram(payload, route.ttl, route.path_mtu)
                };
                let forward = route.with_plaintext(PacketBuffer::new(plaintext));
                let result = self
                    .send_dataplane_fmp_link_plaintext_with_class(
                        &forward.next_hop_addr,
                        forward.plaintext.as_slice(),
                        forward.outgoing_ce,
                        Some(forwarding_packet_class(&forward)),
                    )
                    .await;
                self.finish_prepared_session_forward(forward, result, true)
                    .await;
            }
            PreparedSessionDatagram::NoRoute {
                ingress_peer,
                datagram,
                received_len,
                loop_failure,
            } => {
                self.finish_session_datagram_no_route(
                    ingress_peer,
                    datagram,
                    received_len,
                    loop_failure,
                )
                .await;
            }
            PreparedSessionDatagram::Done => {}
        }
    }

    fn wait_for_forwarding_admission(
        &mut self,
        ingress: crate::PeerIdentity,
        payload: &[u8],
        ce: bool,
        expires: Option<tokio::time::Instant>,
    ) -> bool {
        let Some(peer) = self.peers.get(ingress.node_addr()) else {
            return false;
        };
        let now = tokio::time::Instant::now();
        let is_new = expires.is_none();
        let expires = expires.unwrap_or(now + ADMISSION_WAIT_LIMIT);
        if now >= expires
            || !self
                .waiting_admissions
                .has_capacity(*ingress.node_addr(), payload.len())
        {
            return false;
        }
        let accepted = self.waiting_admissions.insert(WaitingAdmission {
            ingress,
            link_id: peer.link_id(),
            authenticated_at: peer.authenticated_at(),
            payload: payload.into(),
            ce,
            due: (now + ADMISSION_RETRY_DELAY).min(expires),
            expires,
        });
        if accepted && is_new {
            self.stats_mut()
                .forwarding
                .record_deferred_policy(payload.len());
        }
        accepted
    }

    pub(in crate::node) fn admission_work_deadline_ms(&self) -> Option<u64> {
        self.admission_work_delay()
            .map(|delay| Self::now_ms().saturating_add(delay.as_nanos().div_ceil(1_000_000) as u64))
    }

    pub(in crate::node) fn admission_work_delay(&self) -> Option<Duration> {
        self.waiting_admissions.packets.front().map(|packet| {
            packet
                .due
                .saturating_duration_since(tokio::time::Instant::now())
        })
    }

    pub(in crate::node) fn expire_waiting_admissions(&mut self) {
        if self
            .admission_work_delay()
            .is_some_and(|delay| delay.is_zero())
        {
            self.waiting_admissions.expire(&mut self.stats.forwarding);
        }
    }

    pub(in crate::node) fn cancel_waiting_admissions(&mut self) {
        while let Some(packet) = self.waiting_admissions.pop() {
            self.stats_mut()
                .forwarding
                .record_drop_policy_denied(packet.payload.len());
        }
    }

    pub(in crate::node) async fn service_waiting_admissions(&mut self) {
        self.expire_waiting_admissions();
        if tokio::time::timeout(ADMISSION_RETRY_DELAY, self.retry_forwarding_admissions())
            .await
            .is_err()
        {
            warn!("Forwarding admission retry timed out; continuing packet processing");
        }
        self.expire_waiting_admissions();
    }

    pub(in crate::node) async fn retry_forwarding_admissions(&mut self) {
        for _ in 0..ADMISSION_RETRY_BATCH {
            let now = tokio::time::Instant::now();
            if self
                .waiting_admissions
                .packets
                .front()
                .is_none_or(|packet| packet.due > now)
            {
                break;
            }
            let packet = self.waiting_admissions.pop().expect("due packet");
            let current_peer = self
                .peers
                .get(packet.ingress.node_addr())
                .is_some_and(|peer| {
                    peer.link_id() == packet.link_id
                        && peer.authenticated_at() == packet.authenticated_at
                });
            if now >= packet.expires || !current_peer {
                self.stats_mut()
                    .forwarding
                    .record_drop_policy_denied(packet.payload.len());
                continue;
            }
            // Route selection, policy and financial authorization all run again.
            // The saved envelope retains its original TTL until admission.
            self.handle_session_datagram_with_deadline(
                AuthenticatedSessionDatagram::new(packet.ingress, &packet.payload, packet.ce),
                Some(packet.expires),
            )
            .await;
        }
    }
}
