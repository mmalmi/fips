use super::*;

impl Node {
    /// Rebind configured UDP carriers after an observed underlay change.
    ///
    /// Transport IDs, authenticated peers, and end-to-end sessions remain
    /// intact. Adopted NAT-traversal sockets are left alone; the normal direct
    /// path refresh races fresh candidates over the rebound configured carrier.
    pub(in crate::node) async fn rebind_network_transports(
        &mut self,
        bind_interface: Option<String>,
    ) -> Result<usize, NodeError> {
        self.config.node.discovery.nostr.bind_interface = bind_interface.clone();
        match &mut self.config.transports.udp {
            crate::config::TransportInstances::Single(config) => {
                config.bind_interface.clone_from(&bind_interface);
            }
            crate::config::TransportInstances::Named(configs) => {
                for config in configs.values_mut() {
                    config.bind_interface.clone_from(&bind_interface);
                }
            }
        }

        let mut rebound = 0usize;

        for (transport_id, transport) in &mut self.transports {
            let crate::transport::TransportHandle::Udp(udp) = transport else {
                continue;
            };
            match udp
                .rebind_after_network_change(bind_interface.clone())
                .await
            {
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

        if let Some(discovery) = self.nostr_discovery.clone()
            && let Err(error) = self.refresh_overlay_advert(&discovery).await
        {
            debug!(%error, "Failed to refresh local advert after network rebind");
        }

        Ok(rebound)
    }
}
