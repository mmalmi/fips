// Only original, unsealed source records may wait here. A tracked entry keeps
// charging both the existing admission capacity and these narrower wait bounds,
// including after its packet wakes into the ordinary owner queue.
const SOURCE_ADMISSION_MAX_PACKETS: usize = 512;
const SOURCE_ADMISSION_MAX_BYTES: usize = 1024 * 1024;
const SOURCE_ADMISSION_PEER_PACKETS: usize = 256;
const SOURCE_ADMISSION_PEER_BYTES: usize = 512 * 1024;
const SOURCE_ADMISSION_MAX_AGE: std::time::Duration = std::time::Duration::from_secs(2);
const SOURCE_ADMISSION_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

#[derive(Debug)]
struct SourceAdmissionCharge {
    owner: OwnerId,
    next_hop: NodeAddr,
    bytes: usize,
    expires: tokio::time::Instant,
}

#[derive(Debug)]
struct WaitingSourceAdmission {
    queued: QueuedOutboundPacket,
    due: tokio::time::Instant,
}

#[derive(Debug, Default)]
struct SourceAdmissionWait {
    packets: VecDeque<WaitingSourceAdmission>,
    tracked: HashMap<u64, SourceAdmissionCharge>,
    bytes: usize,
    peers: HashMap<NodeAddr, (usize, usize)>,
    next_due: Option<tokio::time::Instant>,
}

impl SourceAdmissionWait {
    fn retain(&mut self, queued: QueuedOutboundPacket) -> Option<QueuedOutboundPacket> {
        let now = tokio::time::Instant::now();
        let expires = queued.enqueued_at + SOURCE_ADMISSION_MAX_AGE;
        let Some(next_hop) = queued.packet.fsp_next_hop() else {
            return Some(queued);
        };
        if now >= expires {
            return Some(queued);
        }
        if self
            .tracked
            .get(&queued.ingress_seq)
            .is_some_and(|charge| charge.next_hop != next_hop)
        {
            self.release(queued.ingress_seq);
        }
        if !self.tracked.contains_key(&queued.ingress_seq) {
            let bytes = queued.packet.payload.len();
            let (peer_packets, peer_bytes) = self.peers.get(&next_hop).copied().unwrap_or_default();
            if self.tracked.len() >= SOURCE_ADMISSION_MAX_PACKETS
                || bytes > SOURCE_ADMISSION_MAX_BYTES.saturating_sub(self.bytes)
                || peer_packets >= SOURCE_ADMISSION_PEER_PACKETS
                || bytes > SOURCE_ADMISSION_PEER_BYTES.saturating_sub(peer_bytes)
            {
                return Some(queued);
            }
            self.bytes += bytes;
            self.peers
                .insert(next_hop, (peer_packets + 1, peer_bytes + bytes));
            self.tracked.insert(
                queued.ingress_seq,
                SourceAdmissionCharge {
                    owner: queued.packet.owner,
                    next_hop,
                    bytes,
                    expires,
                },
            );
        }
        let due = (now + SOURCE_ADMISSION_RETRY_DELAY).min(expires);
        self.next_due = Some(self.next_due.map_or(due, |previous| previous.min(due)));
        self.packets
            .push_back(WaitingSourceAdmission { queued, due });
        None
    }

    fn release(&mut self, sequence: u64) {
        let Some(charge) = self.tracked.remove(&sequence) else {
            return;
        };
        self.bytes -= charge.bytes;
        if self.tracked.is_empty() {
            self.next_due = None;
        }
        let peer = self
            .peers
            .get_mut(&charge.next_hop)
            .expect("source wait peer charge");
        peer.0 -= 1;
        peer.1 -= charge.bytes;
        if peer.0 == 0 {
            self.peers.remove(&charge.next_hop);
        }
    }

    fn parked_lens(&self) -> LaneLens {
        let mut lens = LaneLens::default();
        for waiting in &self.packets {
            lens.increment(waiting.queued.packet.lane());
        }
        lens
    }

    fn delay(&self) -> Option<std::time::Duration> {
        self.next_due
            .map(|due| due.saturating_duration_since(tokio::time::Instant::now()))
    }
}

impl Dataplane {
    fn cancel_source_admissions(&mut self, owner: Option<OwnerId>) {
        self.remove_source_admissions(|charge| owner.is_none_or(|owner| owner == charge.owner));
    }

    fn remove_source_admissions(&mut self, remove: impl Fn(&SourceAdmissionCharge) -> bool) {
        // Timer and replacement cleanup also visit woken packets that are still
        // queued behind in-flight crypto. Such packets must not outlive the hold.
        let removals: std::collections::HashSet<_> = self
            .source_wait
            .tracked
            .iter()
            .filter_map(|(seq, charge)| remove(charge).then_some(*seq))
            .collect();
        if removals.is_empty() {
            return;
        }
        let mut removed = LaneLens::default();
        self.source_wait.packets.retain(|waiting| {
            if !removals.contains(&waiting.queued.ingress_seq) {
                return true;
            }
            removed.increment(waiting.queued.packet.lane());
            self.drops.push(PacketDrop::from_queued_outbound(
                &waiting.queued,
                PacketDropReason::SourcePolicy,
            ));
            false
        });
        for shard in &mut self.shards {
            let queues = &mut shard.outbound_admission.queues;
            let mut shard_removed = LaneLens::default();
            queues.owners.retain(|_, lanes| {
                for lane in [Lane::Priority, Lane::Bulk, Lane::Background] {
                    lanes.lane_mut(lane).retain(|queued| {
                        if !removals.contains(&queued.ingress_seq) {
                            return true;
                        }
                        removed.increment(lane);
                        shard_removed.increment(lane);
                        self.drops.push(PacketDrop::from_queued_outbound(
                            queued,
                            PacketDropReason::SourcePolicy,
                        ));
                        false
                    });
                }
                !lanes.is_empty()
            });
            queues.priority_len -= shard_removed.priority;
            queues.bulk_len -= shard_removed.bulk;
            queues.background_len -= shard_removed.background;
        }
        self.outbound_admission_lens.saturating_sub_assign(removed);
        for seq in removals {
            self.source_wait.release(seq);
        }
    }

    fn service_source_admissions(&mut self) {
        if self
            .source_wait
            .delay()
            .is_none_or(|delay| !delay.is_zero())
        {
            return;
        }
        let now = tokio::time::Instant::now();
        self.remove_source_admissions(|charge| charge.expires <= now);
        let count = self.source_wait.packets.len();
        for _ in 0..count {
            let waiting = self
                .source_wait
                .packets
                .pop_front()
                .expect("source wait count");
            if waiting.due > now {
                self.source_wait.packets.push_back(waiting);
                continue;
            }
            let owner = waiting.queued.packet.owner;
            let shard = self.owner_shard_index(owner);
            self.shards[shard]
                .outbound_admission
                .queues
                .push(waiting.queued, false);
            self.shards[shard].outbound_admission.wake_owner(owner);
            self.mark_admission_ready_shard(shard);
        }
        self.source_wait.next_due = self
            .source_wait
            .packets
            .iter()
            .map(|packet| packet.due)
            .chain(
                self.source_wait
                    .tracked
                    .values()
                    .map(|charge| charge.expires),
            )
            .min();
    }
}

impl DataplaneLiveNode {
    pub(crate) fn source_admission_work_delay(&self) -> Option<std::time::Duration> {
        self.driver.mover.source_wait.delay()
    }

    pub(crate) fn service_source_admissions(&mut self) {
        self.driver.mover.service_source_admissions();
    }

    pub(crate) fn cancel_source_admissions(&mut self) {
        self.driver.mover.cancel_source_admissions(None);
    }
}
