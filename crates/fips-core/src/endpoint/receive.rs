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

    pub(super) fn push_event_into(
        &mut self,
        event: NodeEndpointEvent,
        out: &mut Vec<FipsEndpointMessage>,
        limit: usize,
    ) {
        let NodeEndpointEvent { messages, .. } = event;
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

    fn push_pending(&mut self, message: EndpointDataDelivery) {
        self.pending.push_back(message);
    }
}
