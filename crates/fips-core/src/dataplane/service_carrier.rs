impl PacketOutput {
    fn record_service_carrier(&self, transport: &str, bytes: usize) {
        if let Some(counters) = &self.service_carrier {
            counters.submitted(transport, bytes);
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
                counters.submitted("udp", output.payload_len());
            }
            Self::DirectFspSegments(segments) => {
                for index in 0..sent_items.min(segments.len()) {
                    counters.submitted("udp", segments.payload_len(index));
                }
            }
            Self::Whole(_) => {}
        }
    }
}
