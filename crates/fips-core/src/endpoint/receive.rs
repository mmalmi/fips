use super::{FipsEndpointMessage, FipsEndpointServiceDatagram};
use crate::node::{
    EndpointDataDelivery, EndpointEventReceiver, EndpointServiceDatagramDelivery,
    EndpointServiceEventReceiver, NodeEndpointEvent, NodeEndpointServiceEvent,
};
use std::collections::VecDeque;

fn endpoint_delivery_into_public(message: EndpointDataDelivery) -> FipsEndpointMessage {
    FipsEndpointMessage {
        source_peer: message.source_peer,
        data: message.payload,
        enqueued_at_ms: message.enqueued_at_ms,
    }
}

fn service_delivery_into_public(
    message: EndpointServiceDatagramDelivery,
) -> FipsEndpointServiceDatagram {
    FipsEndpointServiceDatagram {
        source_peer: message.source_peer,
        source_port: message.source_port,
        destination_port: message.destination_port,
        data: message.payload,
        enqueued_at_ms: message.enqueued_at_ms,
    }
}

pub(super) struct EndpointReceiveState {
    pub(super) rx: EndpointEventReceiver,
    pending: VecDeque<EndpointDataDelivery>,
}

pub(super) struct ServiceReceiveState {
    pub(super) rx: EndpointServiceEventReceiver,
    pending: VecDeque<EndpointServiceDatagramDelivery>,
}

impl ServiceReceiveState {
    pub(super) fn new(rx: EndpointServiceEventReceiver) -> Self {
        Self {
            rx,
            pending: VecDeque::new(),
        }
    }

    pub(super) fn drain_pending_into(
        &mut self,
        out: &mut Vec<FipsEndpointServiceDatagram>,
        limit: usize,
    ) {
        let mut released = 0usize;
        while out.len() < limit {
            let Some(message) = self.pending.pop_front() else {
                break;
            };
            out.push(service_delivery_into_public(message));
            released += 1;
        }
        self.rx.release_messages(released);
    }

    pub(super) fn push_event_into(
        &mut self,
        event: NodeEndpointServiceEvent,
        out: &mut Vec<FipsEndpointServiceDatagram>,
        limit: usize,
    ) {
        let mut released = 0usize;
        for message in event.messages {
            if out.len() < limit {
                out.push(service_delivery_into_public(message));
                released += 1;
            } else {
                self.pending.push_back(message);
            }
        }
        self.rx.release_messages(released);
    }
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
