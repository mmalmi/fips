impl PacketOutput {
    fn record_service_carrier(&self, transport: &str, bytes: usize) {
        if let Some(counters) = &self.service_carrier {
            counters.submitted(transport, bytes);
        }
    }
}

impl DataplaneTransportPayloadBatch {
    fn record_service_carrier_submissions(&self, sent_items: usize) {
        // A fragmented record may fail after some fragments were submitted.
        // Account that prefix independently of the whole-record success receipt.
        for item in self.items.iter().take(sent_items) {
            match *item {
                DataplaneTransportPayloadItem::Whole { record_index } => {
                    let output = self.records[record_index].output();
                    output.record_service_carrier("udp", output.payload_len());
                }
                DataplaneTransportPayloadItem::DirectFspSegment {
                    record_index,
                    segment_index,
                } => {
                    let DataplaneTransportPayloadRecord::DirectFspSegments(segments) =
                        &self.records[record_index]
                    else {
                        unreachable!();
                    };
                    segments
                        .output
                        .record_service_carrier("udp", segments.payload_len(segment_index));
                }
            }
        }
    }
}
