use super::{FipsEndpointMessage, FipsEndpointPayloadMessage};
use crate::PeerIdentity;
use crate::node::{ENDPOINT_EVENT_PRIORITY_MAX_LEN, EndpointEventReceiver, NodeEndpointEvent};
use crate::transport::PacketBuffer;
use std::collections::VecDeque;

struct EndpointQueuedMessage {
    source_peer: PeerIdentity,
    payload: PacketBuffer,
}

impl EndpointQueuedMessage {
    pub(super) fn new(source_peer: PeerIdentity, payload: PacketBuffer) -> Self {
        Self {
            source_peer,
            payload,
        }
    }

    fn into_public(self) -> FipsEndpointMessage {
        FipsEndpointMessage {
            source_peer: self.source_peer,
            data: self.payload.into_vec(),
        }
    }

    fn into_payload_public(self) -> FipsEndpointPayloadMessage {
        FipsEndpointPayloadMessage {
            source_peer: self.source_peer,
            data: self.payload,
        }
    }
}

trait EndpointPublicMessage: Sized {
    fn from_queued(message: EndpointQueuedMessage) -> Self;
}

impl EndpointPublicMessage for FipsEndpointMessage {
    fn from_queued(message: EndpointQueuedMessage) -> Self {
        message.into_public()
    }
}

impl EndpointPublicMessage for FipsEndpointPayloadMessage {
    fn from_queued(message: EndpointQueuedMessage) -> Self {
        message.into_payload_public()
    }
}

pub(super) struct EndpointReceiveState {
    pub(super) rx: EndpointEventReceiver,
    pending_priority: VecDeque<EndpointQueuedMessage>,
    pending_bulk: VecDeque<EndpointQueuedMessage>,
}

impl EndpointReceiveState {
    pub(super) fn new(rx: EndpointEventReceiver) -> Self {
        Self {
            rx,
            pending_priority: VecDeque::new(),
            pending_bulk: VecDeque::new(),
        }
    }

    pub(super) fn pop_pending_priority(&mut self) -> Option<FipsEndpointMessage> {
        self.pop_pending_priority_as()
    }

    pub(super) fn pop_pending_bulk(&mut self) -> Option<FipsEndpointMessage> {
        self.pop_pending_bulk_as()
    }

    fn pop_pending_priority_as<M: EndpointPublicMessage>(&mut self) -> Option<M> {
        self.pending_priority.pop_front().map(M::from_queued)
    }

    fn pop_pending_bulk_as<M: EndpointPublicMessage>(&mut self) -> Option<M> {
        self.pending_bulk.pop_front().map(M::from_queued)
    }

    pub(super) fn drain_priority_pending_into(
        &mut self,
        out: &mut Vec<FipsEndpointMessage>,
        limit: usize,
    ) {
        while out.len() < limit {
            let Some(message) = self.pop_pending_priority() else {
                break;
            };
            out.push(message);
        }
    }

    pub(super) fn drain_bulk_pending_into(
        &mut self,
        out: &mut Vec<FipsEndpointMessage>,
        limit: usize,
    ) {
        while out.len() < limit {
            let Some(message) = self.pending_bulk.pop_front() else {
                break;
            };
            out.push(message.into_public());
        }
    }

    pub(super) fn drain_priority_pending_for_each(
        &mut self,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        self.drain_priority_pending_for_each_as(drained, limit, handle_message)
    }

    pub(super) fn drain_priority_pending_payload_for_each(
        &mut self,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointPayloadMessage) -> bool,
    ) -> bool {
        self.drain_priority_pending_for_each_as(drained, limit, handle_message)
    }

    fn drain_priority_pending_for_each_as<M: EndpointPublicMessage>(
        &mut self,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(M) -> bool,
    ) -> bool {
        while *drained < limit {
            let Some(message) = self.pop_pending_priority_as() else {
                break;
            };
            *drained += 1;
            if !handle_message(message) {
                return false;
            }
        }
        true
    }

    pub(super) fn drain_bulk_pending_for_each(
        &mut self,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        self.drain_bulk_pending_for_each_as(drained, limit, handle_message)
    }

    pub(super) fn drain_bulk_pending_payload_for_each(
        &mut self,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointPayloadMessage) -> bool,
    ) -> bool {
        self.drain_bulk_pending_for_each_as(drained, limit, handle_message)
    }

    fn drain_bulk_pending_for_each_as<M: EndpointPublicMessage>(
        &mut self,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(M) -> bool,
    ) -> bool {
        while *drained < limit {
            let Some(message) = self.pop_pending_bulk_as() else {
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
            NodeEndpointEvent::Data {
                source_peer,
                payload,
                ..
            } => {
                self.push_queued_into(EndpointQueuedMessage::new(source_peer, payload), out, limit)
            }
            NodeEndpointEvent::DataBatch { messages, .. } => {
                for message in messages {
                    self.push_queued_into(
                        EndpointQueuedMessage::new(message.source_peer, message.payload),
                        out,
                        limit,
                    );
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
            out.push(message.into_public());
        } else if message.payload.len() <= ENDPOINT_EVENT_PRIORITY_MAX_LEN {
            self.pending_priority.push_back(message);
        } else {
            self.pending_bulk.push_back(message);
        }
    }

    fn push_pending(&mut self, message: EndpointQueuedMessage) {
        if message.payload.len() <= ENDPOINT_EVENT_PRIORITY_MAX_LEN {
            self.pending_priority.push_back(message);
        } else {
            self.pending_bulk.push_back(message);
        }
    }

    pub(super) fn push_event_for_each(
        &mut self,
        event: NodeEndpointEvent,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        self.push_event_for_each_as(event, drained, limit, handle_message)
    }

    pub(super) fn push_event_payload_for_each(
        &mut self,
        event: NodeEndpointEvent,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointPayloadMessage) -> bool,
    ) -> bool {
        self.push_event_for_each_as(event, drained, limit, handle_message)
    }

    fn push_event_for_each_as<M: EndpointPublicMessage>(
        &mut self,
        event: NodeEndpointEvent,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(M) -> bool,
    ) -> bool {
        match event {
            NodeEndpointEvent::Data {
                source_peer,
                payload,
                ..
            } => self.push_queued_for_each_as(
                EndpointQueuedMessage::new(source_peer, payload),
                drained,
                limit,
                handle_message,
            ),
            NodeEndpointEvent::DataBatch { messages, .. } => {
                let mut iter = messages.into_iter();
                while let Some(message) = iter.next() {
                    let queued = EndpointQueuedMessage::new(message.source_peer, message.payload);
                    if !self.push_queued_for_each_as(queued, drained, limit, handle_message) {
                        for message in iter {
                            self.push_pending(EndpointQueuedMessage::new(
                                message.source_peer,
                                message.payload,
                            ));
                        }
                        return false;
                    }
                }
                true
            }
        }
    }

    fn push_queued_for_each_as<M: EndpointPublicMessage>(
        &mut self,
        message: EndpointQueuedMessage,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(M) -> bool,
    ) -> bool {
        if *drained < limit {
            *drained += 1;
            handle_message(M::from_queued(message))
        } else {
            self.push_pending(message);
            false
        }
    }

    pub(super) fn first_from_event(
        &mut self,
        event: NodeEndpointEvent,
    ) -> Option<FipsEndpointMessage> {
        let mut messages = Vec::with_capacity(1);
        self.push_event_into(event, &mut messages, 1);
        messages.pop()
    }
}
