impl DataplaneLiveNodeTurn {
    pub(crate) fn extract_transport_sent_receipts(
        &mut self,
        mut take: impl FnMut(&DataplaneTransportSentReceipt) -> bool,
    ) -> Vec<DataplaneTransportSentReceipt> {
        extract_matching(&mut self.transport_sent_receipts, &mut take)
    }

    pub(crate) fn extract_output_drops(
        &mut self,
        mut take: impl FnMut(&DataplaneOutputDrop) -> bool,
    ) -> Vec<DataplaneOutputDrop> {
        extract_matching(&mut self.output_drops, &mut take)
    }

    pub(crate) fn extract_drops(
        &mut self,
        mut take: impl FnMut(&PacketDrop) -> bool,
    ) -> Vec<PacketDrop> {
        extract_matching(&mut self.drops, &mut take)
    }
}

fn extract_matching<T>(items: &mut Vec<T>, take: &mut impl FnMut(&T) -> bool) -> Vec<T> {
    let mut matched = Vec::new();
    let mut retained = Vec::with_capacity(items.len());
    for item in std::mem::take(items) {
        if take(&item) {
            matched.push(item);
        } else {
            retained.push(item);
        }
    }
    *items = retained;
    matched
}
