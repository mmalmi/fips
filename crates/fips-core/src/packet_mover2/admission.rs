#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionConfig {
    priority_capacity: usize,
    bulk_capacity: usize,
}

impl AdmissionConfig {
    pub(crate) fn new(priority_capacity: usize, bulk_capacity: usize) -> Self {
        Self {
            priority_capacity,
            bulk_capacity,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdmissionDropReason {
    PriorityFull,
    BulkFull,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdmissionDrop {
    owner: OwnerId,
    counter: u64,
    class: PacketClass,
    lane: Lane,
    payload_len: usize,
    reason: AdmissionDropReason,
}

impl AdmissionDrop {
    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn counter(&self) -> u64 {
        self.counter
    }

    pub(crate) fn class(&self) -> PacketClass {
        self.class
    }

    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn reason(&self) -> AdmissionDropReason {
        self.reason
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedPacket {
    ingress_seq: u64,
    packet: SocketPacket,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueuedOutboundPacket {
    ingress_seq: u64,
    packet: OutboundPacket,
}

#[derive(Debug)]
pub(crate) struct AdmissionQueue {
    config: AdmissionConfig,
    next_ingress_seq: u64,
    priority: VecDeque<QueuedPacket>,
    bulk: VecDeque<QueuedPacket>,
}

impl AdmissionQueue {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        Self {
            config,
            next_ingress_seq: 0,
            priority: VecDeque::with_capacity(config.priority_capacity),
            bulk: VecDeque::with_capacity(config.bulk_capacity),
        }
    }

    pub(crate) fn admit(&mut self, packet: SocketPacket) -> Result<u64, AdmissionDrop> {
        let lane = packet.lane();
        let target = match lane {
            Lane::Priority => &mut self.priority,
            Lane::Bulk => &mut self.bulk,
        };
        let capacity = match lane {
            Lane::Priority => self.config.priority_capacity,
            Lane::Bulk => self.config.bulk_capacity,
        };

        if target.len() >= capacity {
            return Err(AdmissionDrop {
                owner: packet.owner,
                counter: packet.counter,
                class: packet.class,
                lane,
                payload_len: packet.payload.len(),
                reason: match lane {
                    Lane::Priority => AdmissionDropReason::PriorityFull,
                    Lane::Bulk => AdmissionDropReason::BulkFull,
                },
            });
        }

        let ingress_seq = self.next_ingress_seq;
        self.next_ingress_seq = self.next_ingress_seq.wrapping_add(1);
        target.push_back(QueuedPacket {
            ingress_seq,
            packet,
        });
        Ok(ingress_seq)
    }

    fn pop_next(&mut self) -> Option<QueuedPacket> {
        self.priority.pop_front().or_else(|| self.bulk.pop_front())
    }

    #[cfg(test)]
    fn lens(&self) -> (usize, usize) {
        (self.priority.len(), self.bulk.len())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OutboundAdmissionDrop {
    owner: OwnerId,
    class: PacketClass,
    lane: Lane,
    payload_len: usize,
    reason: AdmissionDropReason,
}

impl OutboundAdmissionDrop {
    pub(crate) fn owner(&self) -> OwnerId {
        self.owner
    }

    pub(crate) fn class(&self) -> PacketClass {
        self.class
    }

    pub(crate) fn lane(&self) -> Lane {
        self.lane
    }

    pub(crate) fn payload_len(&self) -> usize {
        self.payload_len
    }

    pub(crate) fn reason(&self) -> AdmissionDropReason {
        self.reason
    }
}

#[derive(Debug)]
pub(crate) struct OutboundAdmissionQueue {
    config: AdmissionConfig,
    next_ingress_seq: u64,
    priority: VecDeque<QueuedOutboundPacket>,
    bulk: VecDeque<QueuedOutboundPacket>,
}

impl OutboundAdmissionQueue {
    pub(crate) fn new(config: AdmissionConfig) -> Self {
        Self {
            config,
            next_ingress_seq: 0,
            priority: VecDeque::with_capacity(config.priority_capacity),
            bulk: VecDeque::with_capacity(config.bulk_capacity),
        }
    }

    pub(crate) fn admit(&mut self, packet: OutboundPacket) -> Result<u64, OutboundAdmissionDrop> {
        let lane = packet.lane();
        let target = match lane {
            Lane::Priority => &mut self.priority,
            Lane::Bulk => &mut self.bulk,
        };
        let capacity = match lane {
            Lane::Priority => self.config.priority_capacity,
            Lane::Bulk => self.config.bulk_capacity,
        };

        if target.len() >= capacity {
            return Err(OutboundAdmissionDrop {
                owner: packet.owner,
                class: packet.class,
                lane,
                payload_len: packet.payload.len(),
                reason: match lane {
                    Lane::Priority => AdmissionDropReason::PriorityFull,
                    Lane::Bulk => AdmissionDropReason::BulkFull,
                },
            });
        }

        let ingress_seq = self.next_ingress_seq;
        self.next_ingress_seq = self.next_ingress_seq.wrapping_add(1);
        target.push_back(QueuedOutboundPacket {
            ingress_seq,
            packet,
        });
        Ok(ingress_seq)
    }

    fn pop_next(&mut self) -> Option<QueuedOutboundPacket> {
        self.priority.pop_front().or_else(|| self.bulk.pop_front())
    }

    fn has_priority_pending(&self) -> bool {
        !self.priority.is_empty()
    }

    #[cfg(test)]
    fn lens(&self) -> (usize, usize) {
        (self.priority.len(), self.bulk.len())
    }
}

