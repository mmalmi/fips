use super::*;

impl Node {
    /// Rebind configured UDP carriers after an observed underlay change.
    ///
    /// Transport IDs, authenticated peers, and end-to-end sessions remain
    /// intact. Adopted NAT-traversal sockets are left alone; the normal direct
    /// path refresh races fresh candidates over the rebound configured carrier.
    pub(in crate::node) async fn rebind_network_transports(&mut self) -> Result<usize, NodeError> {
        let mut rebound = 0usize;

        for (transport_id, transport) in &mut self.transports {
            let crate::transport::TransportHandle::Udp(udp) = transport else {
                continue;
            };
            match udp.rebind_after_network_change().await {
                Ok(true) => {
                    rebound = rebound.saturating_add(1);
                    info!(
                        transport_id = %transport_id,
                        "Rebound configured UDP carrier for network change"
                    );
                }
                Ok(false) => {}
                Err(error) => return Err(NodeError::from_transport_error(error)),
            }
        }

        Ok(rebound)
    }
}
