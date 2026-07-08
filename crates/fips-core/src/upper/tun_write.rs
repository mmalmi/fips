use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, MutexGuard, mpsc};

use crate::transport::PacketBuffer;

#[derive(Debug)]
struct TunWriteQueue {
    state: Mutex<TunWriteState>,
    ready: Condvar,
}

#[derive(Debug)]
struct TunWriteState {
    priority: VecDeque<TunWritePacket>,
    senders: usize,
    receiver_alive: bool,
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
            Self::Pooled(packet) => packet.as_slice(),
        }
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Vec(packet) => packet,
            Self::Pooled(packet) => packet.as_mut_slice(),
        }
    }

    #[cfg(any(test, target_os = "linux", target_os = "macos", windows))]
    pub(crate) fn len(&self) -> usize {
        self.as_slice().len()
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
        let mut state = self.queue.lock();
        if !state.receiver_alive {
            return Err(mpsc::SendError(packet));
        }

        state.priority.push_back(TunWritePacket::Vec(packet));
        drop(state);
        self.queue.ready.notify_one();
        Ok(())
    }

    /// Queue a batch of packets for TUN delivery. Returns the number of
    /// packets dropped because the receiver is closed.
    pub(crate) fn send_batch<I, P>(&self, packets: I) -> usize
    where
        I: IntoIterator<Item = P>,
        P: Into<TunWritePacket>,
    {
        let packets = packets.into_iter();
        let mut state = self.queue.lock();
        if !state.receiver_alive {
            return packets.count();
        }

        let mut sent = 0;
        for packet in packets {
            state.priority.push_back(packet.into());
            sent += 1;
        }
        drop(state);
        if sent > 0 {
            self.queue.ready.notify_one();
        }
        0
    }
}

impl TunRx {
    pub(crate) fn recv(&self) -> Option<TunWritePacket> {
        let mut state = self.queue.lock();
        loop {
            if let Some(packet) = state.priority.pop_front() {
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

    #[cfg(any(test, target_os = "linux"))]
    pub(crate) fn try_recv_packet(&self) -> Result<TunWritePacket, mpsc::TryRecvError> {
        let mut state = self.queue.lock();
        if let Some(packet) = state.priority.pop_front() {
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
        drop(state);
        self.queue.ready.notify_all();
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
    let queue = Arc::new(TunWriteQueue {
        state: Mutex::new(TunWriteState {
            priority: VecDeque::new(),
            senders: 1,
            receiver_alive: true,
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
