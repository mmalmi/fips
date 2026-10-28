impl DataplaneLiveNodeTurn {
    /// Work consumed by the node's control-ingress handler. Output statistics
    /// alone do not need that handler; deferred-forward terminal receipts are
    /// handled separately when the node has a pending or completed forward.
    pub(crate) fn has_node_control_ingress(&self) -> bool {
        !self.fmp_ingress_receipts.is_empty() || self.has_non_receipt_node_control_ingress()
    }

    pub(crate) fn has_only_fmp_ingress_receipts(&self) -> bool {
        !self.fmp_ingress_receipts.is_empty()
            && !self.has_non_receipt_node_control_ingress()
            && !self.has_failures()
    }

    fn has_non_receipt_node_control_ingress(&self) -> bool {
        !self.fmp_control_ingress.is_empty()
            || !self.fmp_link_ingress.is_empty()
            || !self.fsp_coord_warmups.is_empty()
            || !self.fsp_local_session_ingress.is_empty()
            || !self.fsp_authenticated_ingress.is_empty()
            || !self.tun_outbound_drops.is_empty()
            || !self.drops.is_empty()
    }

    pub(crate) fn consume_transport_sent_receipts(
        &mut self,
        consume: impl FnMut(&DataplaneTransportSentReceipt) -> bool,
    ) {
        consume_matching(&mut self.transport_sent_receipts, consume);
    }

    pub(crate) fn consume_output_drops(
        &mut self,
        consume: impl FnMut(&DataplaneOutputDrop) -> bool,
    ) {
        consume_matching(&mut self.output_drops, consume);
    }

    pub(crate) fn consume_drops(
        &mut self,
        consume: impl FnMut(&PacketDrop) -> bool,
    ) {
        consume_matching(&mut self.drops, consume);
    }
}

fn consume_matching<T>(items: &mut Vec<T>, mut consume: impl FnMut(&T) -> bool) {
    items.retain(|item| !consume(item));
}

#[cfg(test)]
mod turn_extract_tests {
    use super::consume_matching;

    #[test]
    fn consume_matching_preserves_unmatched_order() {
        let mut items = vec![1, 2, 3, 4];
        consume_matching(&mut items, |item| item % 2 == 0);
        assert_eq!(items, [1, 3]);
    }
}
