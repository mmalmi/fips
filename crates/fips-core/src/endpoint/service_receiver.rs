use super::*;

impl FipsEndpointServiceReceiver {
    /// Receive one datagram for this service, then drain ready follow-ons.
    pub async fn recv_batch_into(
        &self,
        datagrams: &mut Vec<FipsEndpointServiceDatagram>,
        max: usize,
    ) -> Option<usize> {
        let max = max.clamp(1, ENDPOINT_RECV_BATCH_MAX);
        datagrams.clear();

        let mut state = self.state.lock().await;
        state.drain_pending_into(datagrams, max);
        while datagrams.len() < max {
            let event = if datagrams.is_empty() {
                state.rx.recv().await?
            } else {
                match state.rx.try_recv() {
                    Ok(event) => event,
                    Err(_) => break,
                }
            };
            state.push_event_into(event, datagrams, max);
        }
        Some(datagrams.len())
    }
}
