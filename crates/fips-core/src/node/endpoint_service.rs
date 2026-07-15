use super::*;
use crate::transport::PacketBuffer;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
use tokio::sync::mpsc::error::TryRecvError;

#[derive(Debug, Clone)]
pub(crate) struct EndpointServiceDatagramDelivery {
    pub(crate) source_peer: PeerIdentity,
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
    pub(crate) payload: PacketBuffer,
    pub(crate) enqueued_at_ms: u64,
}

impl EndpointServiceDatagramDelivery {
    pub(crate) fn new(
        source_peer: PeerIdentity,
        source_port: u16,
        destination_port: u16,
        payload: PacketBuffer,
    ) -> Self {
        Self {
            source_peer,
            source_port,
            destination_port,
            payload,
            enqueued_at_ms: crate::time::now_ms(),
        }
    }
}

#[derive(Debug)]
pub(crate) struct NodeEndpointServiceEvent {
    pub(crate) messages: Vec<EndpointServiceDatagramDelivery>,
}

#[derive(Debug, Clone)]
pub(crate) struct EndpointServiceEventSender {
    tx: tokio::sync::mpsc::UnboundedSender<NodeEndpointServiceEvent>,
    queued_messages: Arc<AtomicUsize>,
    message_capacity: usize,
}

#[derive(Debug)]
pub(crate) struct EndpointServiceEventReceiver {
    rx: tokio::sync::mpsc::UnboundedReceiver<NodeEndpointServiceEvent>,
    queued_messages: Arc<AtomicUsize>,
}

impl EndpointServiceEventSender {
    pub(crate) fn channel(capacity: usize) -> (Self, EndpointServiceEventReceiver) {
        let queued_messages = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        (
            Self {
                tx,
                queued_messages: Arc::clone(&queued_messages),
                message_capacity: capacity.max(1),
            },
            EndpointServiceEventReceiver {
                rx,
                queued_messages,
            },
        )
    }

    pub(crate) fn send(&self, messages: Vec<EndpointServiceDatagramDelivery>) -> Result<(), ()> {
        if messages.is_empty() {
            return Ok(());
        }
        self.send_messages(messages)
    }

    fn send_messages(&self, mut messages: Vec<EndpointServiceDatagramDelivery>) -> Result<(), ()> {
        let count = messages.len();
        let reserved = self
            .queued_messages
            .fetch_update(Relaxed, Relaxed, |current| {
                current
                    .checked_add(count)
                    .filter(|next| *next <= self.message_capacity)
            })
            .is_ok();
        if !reserved {
            if messages.len() > 1 {
                let right = messages.split_off(messages.len() / 2);
                self.send_messages(messages)?;
                self.send_messages(right)?;
            }
            return Ok(());
        }

        if self.tx.send(NodeEndpointServiceEvent { messages }).is_err() {
            self.queued_messages.fetch_sub(count, Relaxed);
            return Err(());
        }
        Ok(())
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

impl EndpointServiceEventReceiver {
    pub(crate) async fn recv(&mut self) -> Option<NodeEndpointServiceEvent> {
        self.rx.recv().await
    }

    pub(crate) fn blocking_recv(&mut self) -> Option<NodeEndpointServiceEvent> {
        self.rx.blocking_recv()
    }

    pub(crate) fn try_recv(&mut self) -> Result<NodeEndpointServiceEvent, TryRecvError> {
        self.rx.try_recv()
    }

    pub(crate) fn release_messages(&self, count: usize) {
        if count > 0 {
            let previous = self.queued_messages.fetch_sub(count, Relaxed);
            debug_assert!(previous >= count, "service event accounting underflow");
        }
    }
}

impl Drop for EndpointServiceEventReceiver {
    fn drop(&mut self) {
        self.queued_messages.store(0, Relaxed);
    }
}

#[derive(Debug, Default)]
pub(in crate::node) struct EndpointServiceRuntime {
    senders: HashMap<u16, EndpointServiceEventSender>,
}

impl EndpointServiceRuntime {
    pub(in crate::node) fn register(
        &mut self,
        port: u16,
        sender: EndpointServiceEventSender,
    ) -> bool {
        if self.senders.contains_key(&port) {
            return false;
        }
        self.senders.insert(port, sender);
        true
    }

    pub(in crate::node) fn is_registered(&self, port: u16) -> bool {
        self.senders.contains_key(&port)
    }

    pub(in crate::node) fn remove_closed(&mut self) -> Vec<u16> {
        self.senders
            .extract_if(|_, sender| sender.is_closed())
            .map(|(port, _)| port)
            .collect()
    }

    pub(in crate::node) fn deliver(
        &self,
        messages: Vec<EndpointServiceDatagramDelivery>,
    ) -> Result<(), ()> {
        let mut by_port: HashMap<u16, Vec<EndpointServiceDatagramDelivery>> = HashMap::new();
        for message in messages {
            if self.senders.contains_key(&message.destination_port) {
                by_port
                    .entry(message.destination_port)
                    .or_default()
                    .push(message);
            }
        }
        for (port, messages) in by_port {
            if let Some(sender) = self.senders.get(&port) {
                sender.send(messages)?;
            }
        }
        Ok(())
    }
}
