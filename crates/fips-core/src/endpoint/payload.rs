use crate::node::{
    EndpointCommandLane, EndpointDataPayload, EndpointPayloadClass, classify_endpoint_payload,
};

/// App-owned endpoint payload plus its queue/pressure policy.
///
/// `FipsEndpointPayload::new` classifies raw packet bytes once. Embedders that
/// already classified a packet while staging their own priority/bulk queues can
/// use `from_classified` to carry the same class into FIPS without parsing the
/// packet a second time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FipsEndpointPayload {
    bytes: Vec<u8>,
    class: EndpointPayloadClass,
}

impl FipsEndpointPayload {
    pub fn new(bytes: Vec<u8>) -> Self {
        let class = classify_endpoint_payload(&bytes);
        Self { bytes, class }
    }

    pub fn from_classified(bytes: Vec<u8>, class: EndpointPayloadClass) -> Self {
        Self { bytes, class }
    }

    pub fn class(&self) -> EndpointPayloadClass {
        self.class
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl From<FipsEndpointPayload> for EndpointDataPayload {
    fn from(payload: FipsEndpointPayload) -> Self {
        EndpointDataPayload::from_classified(payload.bytes, payload.class)
    }
}

#[derive(Debug)]
pub(super) enum EndpointPayloadLaneBatches {
    Empty,
    Single {
        lane: EndpointCommandLane,
        payloads: Vec<EndpointDataPayload>,
    },
    Split {
        priority_payloads: Vec<EndpointDataPayload>,
        bulk_payloads: Vec<EndpointDataPayload>,
    },
}

pub(super) fn endpoint_payload_lane_batches(
    payloads: Vec<FipsEndpointPayload>,
) -> EndpointPayloadLaneBatches {
    let payload_count = payloads.len();
    let mut raw_payloads = payloads.into_iter();
    let Some(first) = raw_payloads.next() else {
        return EndpointPayloadLaneBatches::Empty;
    };

    let first = EndpointDataPayload::from(first);
    let mut first_lane_payloads = Vec::with_capacity(payload_count);
    let first_lane = first.lane();
    first_lane_payloads.push(first);
    let mut batches = EndpointPayloadLaneBatches::Single {
        lane: first_lane,
        payloads: first_lane_payloads,
    };

    for payload in raw_payloads.map(EndpointDataPayload::from) {
        let payload_lane = payload.lane();
        match &mut batches {
            EndpointPayloadLaneBatches::Empty => unreachable!("first payload exists"),
            EndpointPayloadLaneBatches::Single { lane, payloads } if payload_lane == *lane => {
                payloads.push(payload);
            }
            EndpointPayloadLaneBatches::Single { lane, payloads } => {
                let first_lane_payloads = std::mem::take(payloads);
                let mut priority_payloads = Vec::new();
                let mut bulk_payloads = Vec::new();
                match *lane {
                    EndpointCommandLane::Priority => priority_payloads = first_lane_payloads,
                    EndpointCommandLane::Bulk => bulk_payloads = first_lane_payloads,
                }
                match payload_lane {
                    EndpointCommandLane::Priority => priority_payloads.push(payload),
                    EndpointCommandLane::Bulk => bulk_payloads.push(payload),
                }
                batches = EndpointPayloadLaneBatches::Split {
                    priority_payloads,
                    bulk_payloads,
                };
            }
            EndpointPayloadLaneBatches::Split {
                priority_payloads,
                bulk_payloads,
            } => match payload_lane {
                EndpointCommandLane::Priority => priority_payloads.push(payload),
                EndpointCommandLane::Bulk => bulk_payloads.push(payload),
            },
        }
    }

    batches
}
