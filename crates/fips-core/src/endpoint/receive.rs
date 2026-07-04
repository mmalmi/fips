use super::FipsEndpointMessage;
use crate::node::{EndpointDataDelivery, EndpointEventReceiver, NodeEndpointEvent};
use std::collections::VecDeque;

fn endpoint_delivery_into_public(message: EndpointDataDelivery) -> FipsEndpointMessage {
    FipsEndpointMessage {
        source_peer: message.source_peer,
        data: message.payload,
        enqueued_at_ms: message.enqueued_at_ms,
    }
}

pub(super) struct EndpointReceiveState {
    pub(super) rx: EndpointEventReceiver,
    pending: VecDeque<EndpointDataDelivery>,
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
        Some(endpoint_delivery_into_public(message))
    }

    pub(super) fn drain_pending_into(&mut self, out: &mut Vec<FipsEndpointMessage>, limit: usize) {
        let mut released = 0usize;
        while out.len() < limit {
            let Some(message) = self.pending.pop_front() else {
                break;
            };
            out.push(endpoint_delivery_into_public(message));
            released += 1;
        }
        self.rx.release_messages(released);
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
                let mut released = 0usize;
                for message in messages {
                    if out.len() < limit {
                        out.push(endpoint_delivery_into_public(message));
                        released += 1;
                    } else {
                        self.push_pending(message);
                    }
                }
                self.rx.release_messages(released);
            }
        }
    }

    fn push_pending(&mut self, message: EndpointDataDelivery) {
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
                    if !self.push_queued_for_each(message, drained, limit, handle_message) {
                        for message in iter {
                            self.push_pending(message);
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
        message: EndpointDataDelivery,
        drained: &mut usize,
        limit: usize,
        handle_message: &mut impl FnMut(FipsEndpointMessage) -> bool,
    ) -> bool {
        if *drained < limit {
            *drained += 1;
            let message = endpoint_delivery_into_public(message);
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
                    self.push_pending(message);
                }
                self.rx.release_messages(1);
                Some(endpoint_delivery_into_public(first))
            }
        }
    }
}
