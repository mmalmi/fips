impl PacketOutput {
    fn record_service_carrier(&self, transport: &str, bytes: usize, payload: &[u8]) {
        if let Some(counters) = &self.service_carrier {
            counters.submitted_payloads(transport, bytes, [payload]);
        }
    }
}

impl DataplaneTransportPayloadRecord {
    fn record_service_carrier_submissions(&self, sent_items: usize) {
        let Some(counters) = &self.output().service_carrier else {
            return;
        };
        // A fragmented record may fail after some fragments were submitted.
        // Account that prefix independently of the whole-record success receipt.
        match self {
            Self::Whole(output) if sent_items > 0 => {
                counters.submitted_payloads("udp", output.payload_len(), [output.payload()]);
            }
            Self::DirectFspSegments(segments) => {
                for index in 0..sent_items.min(segments.len()) {
                    let mut slices = [None; crate::transport::udp::UDP_PAYLOAD_MAX_SLICES];
                    segments.payload_slices(index, &mut slices);
                    counters.submitted_payloads(
                        "udp",
                        segments.payload_len(index),
                        slices.into_iter().flatten(),
                    );
                }
            }
            Self::Whole(_) => {}
        }
    }
}
