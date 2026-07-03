use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};

use crate::transport::PacketBuffer;

const DEFAULT_TUN_WRITE_BULK_QUEUE_CAP: usize = 1024;
const MAX_TUN_WRITE_BULK_QUEUE_CAP: usize = 65_536;

/// Queue lane for packets waiting on the blocking TUN writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TunWriteLane {
    Priority,
    Bulk,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TunWriteErrorKind {
    Closed,
    BulkFull,
}

#[derive(Debug)]
pub(crate) struct TunWriteError {
    packet: TunWritePacket,
    kind: TunWriteErrorKind,
}

impl TunWriteError {
    pub(crate) fn kind(&self) -> TunWriteErrorKind {
        self.kind
    }

    pub(crate) fn into_packet(self) -> Vec<u8> {
        self.packet.into_vec()
    }
}

impl std::fmt::Display for TunWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            TunWriteErrorKind::Closed => write!(f, "TUN write channel closed"),
            TunWriteErrorKind::BulkFull => write!(f, "TUN bulk write queue full"),
        }
    }
}

impl std::error::Error for TunWriteError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TunWriteBatchError {
    pub(crate) index: usize,
    pub(crate) kind: TunWriteErrorKind,
}

#[derive(Debug)]
struct TunWriteQueue {
    state: Mutex<TunWriteState>,
    ready: Condvar,
}

#[derive(Debug)]
struct TunWriteState {
    priority: VecDeque<TunWritePacket>,
    bulk: VecDeque<TunWritePacket>,
    senders: usize,
    receiver_alive: bool,
    bulk_capacity: usize,
}

#[derive(Debug)]
pub(crate) enum TunWritePacket {
    Vec(Vec<u8>),
    Pooled(PacketBuffer),
}

impl TunWritePacket {
    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Vec(packet) => packet,
            Self::Pooled(packet) => packet,
        }
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Vec(packet) => packet,
            Self::Pooled(packet) => packet,
        }
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
    pub(crate) fn len(&self) -> usize {
        self.as_slice().len()
    }

    pub(crate) fn into_vec(self) -> Vec<u8> {
        match self {
            Self::Vec(packet) => packet,
            Self::Pooled(packet) => packet.into_vec(),
        }
    }
}

impl From<Vec<u8>> for TunWritePacket {
    fn from(packet: Vec<u8>) -> Self {
        Self::Vec(packet)
    }
}

impl From<PacketBuffer> for TunWritePacket {
    fn from(packet: PacketBuffer) -> Self {
        Self::Pooled(packet)
    }
}

impl PartialEq<Vec<u8>> for TunWritePacket {
    fn eq(&self, other: &Vec<u8>) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl PartialEq<TunWritePacket> for Vec<u8> {
    fn eq(&self, other: &TunWritePacket) -> bool {
        self.as_slice() == other.as_slice()
    }
}

/// Channel sender for packets to be written to TUN.
#[derive(Debug)]
pub struct TunTx {
    queue: Arc<TunWriteQueue>,
}

/// Channel receiver consumed by the blocking TUN writer.
#[derive(Debug)]
pub(crate) struct TunRx {
    queue: Arc<TunWriteQueue>,
}

impl Clone for TunTx {
    fn clone(&self) -> Self {
        {
            let mut state = self.queue.lock();
            state.senders = state.senders.saturating_add(1);
        }
        Self {
            queue: Arc::clone(&self.queue),
        }
    }
}

impl Drop for TunTx {
    fn drop(&mut self) {
        let should_notify = {
            let mut state = self.queue.lock();
            state.senders = state.senders.saturating_sub(1);
            state.senders == 0
        };
        if should_notify {
            self.queue.ready.notify_all();
        }
    }
}

impl TunTx {
    /// Queue a priority packet for TUN delivery.
    pub fn send(&self, packet: Vec<u8>) -> Result<(), mpsc::SendError<Vec<u8>>> {
        self.send_with_lane(packet, TunWriteLane::Priority)
            .map_err(|error| mpsc::SendError(error.into_packet()))
    }

    /// Queue a packet for TUN delivery, allowing bulk to shed under pressure.
    pub(crate) fn send_with_lane(
        &self,
        packet: impl Into<TunWritePacket>,
        lane: TunWriteLane,
    ) -> Result<(), TunWriteError> {
        let packet = packet.into();
        let mut state = self.queue.lock();
        if !state.receiver_alive {
            return Err(TunWriteError {
                packet,
                kind: TunWriteErrorKind::Closed,
            });
        }

        enqueue_tun_write_packet(&mut state, packet, lane)?;
        drop(state);
        self.queue.ready.notify_one();
        Ok(())
    }

    pub(crate) fn send_batch_with_lanes<I, P>(&self, packets: I) -> Vec<TunWriteBatchError>
    where
        I: IntoIterator<Item = (P, TunWriteLane)>,
        P: Into<TunWritePacket>,
    {
        let mut state = self.queue.lock();
        let mut failures = Vec::new();
        let mut sent = 0usize;
        for (index, (packet, lane)) in packets.into_iter().enumerate() {
            let packet = packet.into();
            if !state.receiver_alive {
                failures.push(TunWriteBatchError {
                    index,
                    kind: TunWriteErrorKind::Closed,
                });
                continue;
            }
            match enqueue_tun_write_packet(&mut state, packet, lane) {
                Ok(()) => sent = sent.saturating_add(1),
                Err(error) => failures.push(TunWriteBatchError {
                    index,
                    kind: error.kind,
                }),
            }
        }
        drop(state);
        if sent > 0 {
            self.queue.ready.notify_one();
        }
        failures
    }
}

fn enqueue_tun_write_packet(
    state: &mut TunWriteState,
    packet: TunWritePacket,
    lane: TunWriteLane,
) -> Result<(), TunWriteError> {
    match lane {
        TunWriteLane::Priority => state.priority.push_back(packet),
        TunWriteLane::Bulk => {
            if state.bulk.len() >= state.bulk_capacity {
                crate::perf_profile::record_event(crate::perf_profile::Event::TunWriteBulkDropped);
                return Err(TunWriteError {
                    packet,
                    kind: TunWriteErrorKind::BulkFull,
                });
            }
            let high_water = (state.bulk_capacity / 2).max(1);
            let previous = state.bulk.len();
            state.bulk.push_back(packet);
            if previous < high_water && state.bulk.len() >= high_water {
                crate::perf_profile::record_event(
                    crate::perf_profile::Event::TunWriteBulkBacklogHigh,
                );
            }
        }
    }
    Ok(())
}

impl TunRx {
    pub(crate) fn recv(&self) -> Option<TunWritePacket> {
        let mut state = self.queue.lock();
        loop {
            if let Some(packet) = state.priority.pop_front() {
                return Some(packet);
            }
            if let Some(packet) = state.bulk.pop_front() {
                return Some(packet);
            }
            if state.senders == 0 {
                state.receiver_alive = false;
                return None;
            }
            state = self
                .queue
                .ready
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }

    #[cfg(test)]
    pub(crate) fn try_recv(&self) -> Result<Vec<u8>, mpsc::TryRecvError> {
        self.try_recv_packet().map(TunWritePacket::into_vec)
    }

    #[cfg(test)]
    pub(crate) fn try_recv_packet(&self) -> Result<TunWritePacket, mpsc::TryRecvError> {
        let mut state = self.queue.lock();
        if let Some(packet) = state.priority.pop_front() {
            return Ok(packet);
        }
        if let Some(packet) = state.bulk.pop_front() {
            return Ok(packet);
        }
        if state.senders == 0 {
            state.receiver_alive = false;
            Err(mpsc::TryRecvError::Disconnected)
        } else {
            Err(mpsc::TryRecvError::Empty)
        }
    }
}

impl Drop for TunRx {
    fn drop(&mut self) {
        let mut state = self.queue.lock();
        state.receiver_alive = false;
        state.priority.clear();
        state.bulk.clear();
        drop(state);
        self.queue.ready.notify_all();
    }
}

impl Iterator for TunRx {
    type Item = TunWritePacket;

    fn next(&mut self) -> Option<Self::Item> {
        self.recv()
    }
}

impl TunWriteQueue {
    fn lock(&self) -> MutexGuard<'_, TunWriteState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(crate) fn write_channel() -> (TunTx, TunRx) {
    write_channel_with_bulk_capacity(tun_write_bulk_queue_cap())
}

pub(crate) fn write_channel_with_bulk_capacity(bulk_capacity: usize) -> (TunTx, TunRx) {
    let queue = Arc::new(TunWriteQueue {
        state: Mutex::new(TunWriteState {
            priority: VecDeque::new(),
            bulk: VecDeque::new(),
            senders: 1,
            receiver_alive: true,
            bulk_capacity: bulk_capacity.max(1),
        }),
        ready: Condvar::new(),
    });
    (
        TunTx {
            queue: Arc::clone(&queue),
        },
        TunRx { queue },
    )
}

fn tun_write_bulk_queue_cap() -> usize {
    std::env::var("FIPS_TUN_WRITE_BULK_QUEUE_CAP")
        .ok()
        .and_then(|raw| raw.parse::<usize>().ok())
        .map(|value| value.clamp(1, MAX_TUN_WRITE_BULK_QUEUE_CAP))
        .unwrap_or(DEFAULT_TUN_WRITE_BULK_QUEUE_CAP)
}
