use super::FipsEndpointMessage;
use crate::PeerIdentity;
use crate::node::{EndpointDataDelivery, EndpointEventReceiver, NodeEndpointEvent};
use crate::transport::PacketBuffer;
use std::collections::VecDeque;

struct EndpointQueuedMessage {
    source_peer: PeerIdentity,
    payload: PacketBuffer,
    enqueued_at_ms: u64,
}

impl EndpointQueuedMessage {
    pub(super) fn new(
        source_peer: PeerIdentity,
        payload: PacketBuffer,
        enqueued_at_ms: u64,
    ) -> Self {
        Self {
            source_peer,
            payload,
            enqueued_at_ms,
        }
    }

    fn into_public(self) -> FipsEndpointMessage {
        FipsEndpointMessage {
            source_peer: self.source_peer,
            data: self.payload,
            enqueued_at_ms: self.enqueued_at_ms,
        }
    }
}

impl From<EndpointDataDelivery> for EndpointQueuedMessage {
    fn from(message: EndpointDataDelivery) -> Self {
        Self::new(message.source_peer, message.payload, message.enqueued_at_ms)
    }
}

pub(super) struct EndpointReceiveState {
    pub(super) rx: EndpointEventReceiver,
    pending: VecDeque<EndpointQueuedMessage>,
}

impl EndpointReceiveState {
    pub(super) fn new(rx: EndpointEventReceiver) -> Self {
        Self {
            rx,
            pending: VecDeque::new(),
        }
    }

    pub(super) fn pop_pending(&mut self) -> Option<FipsEndpointMessage> {
        let message = self.pending.pop_front()?;
        self.rx.release_messages(1);
        Some(message.into_public())
    }

    pub(super) fn drain_pending_into(&mut self, out: &mut Vec<FipsEndpointMessage>, limit: usize) {
        while out.len() < limit {
            let Some(message) = self.pop_pending() else {
                break;
            };
            out.push(message);
        }
    }

    pub(super) fn drain_pending_for_each(
        &mut self,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        while *drained < limit {
            let Some(message) = self.pop_pending() else {
                break;
            };
            *drained += 1;
            if !handle_message(message) {
                return false;
            }
        }
        true
    }

    pub(super) fn push_event_into(
        &mut self,
        event: NodeEndpointEvent,
        out: &mut Vec<FipsEndpointMessage>,
        limit: usize,
    ) {
        match event {
            NodeEndpointEvent { messages, .. } => {
                for message in messages {
                    self.push_queued_into(message.into(), out, limit);
                }
            }
        }
    }

    fn push_queued_into(
        &mut self,
        message: EndpointQueuedMessage,
        out: &mut Vec<FipsEndpointMessage>,
        limit: usize,
    ) {
        if out.len() < limit {
            self.rx.release_messages(1);
            out.push(message.into_public());
        } else {
            self.pending.push_back(message);
        }
    }

    fn push_pending(&mut self, message: EndpointQueuedMessage) {
        self.pending.push_back(message);
    }

    pub(super) fn push_event_for_each(
        &mut self,
        event: NodeEndpointEvent,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        match event {
            NodeEndpointEvent { messages, .. } => {
                let mut iter = messages.into_iter();
                while let Some(message) = iter.next() {
                    let queued = EndpointQueuedMessage::from(message);
                    if !self.push_queued_for_each(queued, drained, limit, handle_message) {
                        for message in iter {
                            self.push_pending(message.into());
                        }
                        return false;
                    }
                }
                true
            }
        }
    }

    fn push_queued_for_each(
        &mut self,
        message: EndpointQueuedMessage,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        if *drained < limit {
            *drained += 1;
            let message = message.into_public();
            self.rx.release_messages(1);
            handle_message(message)
        } else {
            self.push_pending(message);
            false
        }
    }

    pub(super) fn first_from_event(
        &mut self,
        event: NodeEndpointEvent,
    ) -> Option<FipsEndpointMessage> {
        match event {
            NodeEndpointEvent { messages, .. } => {
                let mut iter = messages.into_iter();
                let first = iter.next()?;
                for message in iter {
                    self.push_pending(message.into());
                }
                self.rx.release_messages(1);
                Some(EndpointQueuedMessage::from(first).into_public())
            }
        }
    }
}
