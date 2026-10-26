use super::*;
use crate::discovery::local_udp::{
    LOCAL_CAPABILITY_FSP_PORT, LocalCapabilityMessage, LocalCapabilityProvider,
};

impl LocalRendezvous {
    pub(super) fn self_advertisement(
        &self,
        identity: &Identity,
        epoch: [u8; 8],
    ) -> LocalInstanceAdvertisement {
        LocalInstanceAdvertisement {
            npub: identity.npub(),
            startup_epoch: epoch,
            capabilities: self.capabilities.clone(),
        }
    }
}

impl Node {
    pub(crate) fn local_capability_directory(&self) -> LocalCapabilityDirectory {
        self.local_rendezvous.directory.clone()
    }

    pub(crate) fn set_local_instance_roles(&mut self, roles: Vec<LocalInstanceCapability>) {
        self.local_rendezvous.capabilities = roles
            .into_iter()
            .filter(|capability| {
                crate::discovery::local_udp::local_capability_name_is_valid(&capability.name)
            })
            .take(crate::discovery::local_udp::LOCAL_CAPABILITY_MAX_COUNT)
            .collect();
        self.mark_local_capabilities_changed();
    }

    pub(in crate::node) fn register_local_instance_capability(
        &mut self,
        mut capability: LocalInstanceCapability,
    ) {
        capability.name = capability.name.trim().to_string();
        if !crate::discovery::local_udp::local_capability_name_is_valid(&capability.name) {
            warn!(name = %capability.name, "Ignoring invalid local capability name");
            return;
        }
        if !self
            .local_rendezvous
            .capabilities
            .iter()
            .any(|existing| existing == &capability)
        {
            if self.local_rendezvous.capabilities.len()
                >= crate::discovery::local_udp::LOCAL_CAPABILITY_MAX_COUNT
            {
                warn!(
                    max = crate::discovery::local_udp::LOCAL_CAPABILITY_MAX_COUNT,
                    "Ignoring local capability beyond protocol limit"
                );
                return;
            }
            self.local_rendezvous.capabilities.push(capability);
            self.mark_local_capabilities_changed();
        }
    }

    fn mark_local_capabilities_changed(&mut self) {
        self.local_rendezvous.capability_revision =
            self.local_rendezvous.capability_revision.saturating_add(1);
        self.local_rendezvous.last_capability_sync_ms = 0;
        if self.local_rendezvous.role == Some(LocalRendezvousRole::Anchor) {
            self.local_rendezvous.roster_revision =
                self.local_rendezvous.roster_revision.saturating_add(1);
            self.local_rendezvous.roster_dirty = true;
        }
        self.refresh_self_local_advertisement();
    }

    fn refresh_self_local_advertisement(&self) {
        if self.config.node.discovery.local.enabled {
            self.local_rendezvous.directory.upsert(
                self.local_rendezvous
                    .self_advertisement(&self.identity, self.startup_epoch),
            );
        }
    }

    pub(in crate::node) fn remove_closed_local_capabilities(&mut self) {
        let closed_ports = self.endpoint_services.remove_closed();
        let before = self.local_rendezvous.capabilities.len();
        self.local_rendezvous.capabilities.retain(|capability| {
            capability
                .fsp_port
                .is_none_or(|port| !closed_ports.contains(&port))
        });
        if self.local_rendezvous.capabilities.len() != before {
            self.mark_local_capabilities_changed();
        }
    }

    async fn send_local_capability_message(
        &mut self,
        remote: PeerIdentity,
        message: LocalCapabilityMessage,
    ) {
        let Ok(payload) = message.encode() else {
            warn!("Local capability message exceeds protocol bounds");
            return;
        };
        let Some(payload) = EndpointDataPayload::from_service_datagram(
            LOCAL_CAPABILITY_FSP_PORT,
            LOCAL_CAPABILITY_FSP_PORT,
            payload,
        ) else {
            return;
        };
        let Some(batch) = NodeEndpointDataBatch::from_payloads(remote, vec![payload], None) else {
            return;
        };
        // Capability replies can run inside authenticated handshake dispatch.
        // Keep the outbound dataplane future out of those nested poll frames.
        Box::pin(self.handle_endpoint_data_batch_no_established_flush(batch)).await;
    }

    pub(super) async fn announce_local_capabilities(&mut self, anchor: PeerIdentity) {
        let message = LocalCapabilityMessage::Announce {
            process_epoch: self.startup_epoch,
            revision: self.local_rendezvous.capability_revision,
            capabilities: self.local_rendezvous.capabilities.clone(),
        };
        self.send_local_capability_message(anchor, message).await;
        self.local_rendezvous.last_capability_sync_ms = Self::now_ms();
    }

    fn local_roster_providers(&self) -> Vec<LocalCapabilityProvider> {
        let mut providers = self
            .local_rendezvous
            .providers
            .values()
            .map(|provider| LocalCapabilityProvider {
                pubkey: provider.identity.pubkey().serialize(),
                process_epoch: provider.startup_epoch,
                capabilities: provider.capabilities.clone(),
            })
            .collect::<Vec<_>>();
        providers.sort_by_key(|provider| provider.pubkey);
        providers.truncate(
            crate::discovery::local_udp::LOCAL_CAPABILITY_MAX_PROVIDERS.saturating_sub(1),
        );
        let owner = LocalCapabilityProvider {
            pubkey: self.identity.pubkey().serialize(),
            process_epoch: self.startup_epoch,
            capabilities: self.local_rendezvous.capabilities.clone(),
        };
        let owner_at = providers
            .binary_search_by_key(&owner.pubkey, |provider| provider.pubkey)
            .unwrap_or_else(|at| at);
        providers.insert(owner_at, owner);
        providers
    }

    pub(super) fn refresh_anchor_directory(&self) {
        let mut adverts = self
            .local_rendezvous
            .providers
            .values()
            .map(|provider| LocalInstanceAdvertisement {
                npub: provider.identity.npub(),
                startup_epoch: provider.startup_epoch,
                capabilities: provider.capabilities.clone(),
            })
            .collect::<Vec<_>>();
        adverts.push(
            self.local_rendezvous
                .self_advertisement(&self.identity, self.startup_epoch),
        );
        self.local_rendezvous.directory.replace(adverts);
    }

    pub(in crate::node) async fn broadcast_local_roster(&mut self) {
        let message = LocalCapabilityMessage::Roster {
            anchor_epoch: self.startup_epoch,
            revision: self.local_rendezvous.roster_revision,
            providers: self.local_roster_providers(),
        };
        let peers = self
            .peers
            .values()
            .filter(|peer| self.authenticated_local_peer(peer.node_addr()))
            .map(|peer| *peer.identity())
            .collect::<Vec<_>>();
        for peer in peers {
            self.send_local_capability_message(peer, message.clone())
                .await;
        }
        self.local_rendezvous.last_capability_sync_ms = Self::now_ms();
        self.local_rendezvous.roster_dirty = false;
    }

    pub(in crate::node) fn handle_local_capability_message(
        &mut self,
        source_addr: &NodeAddr,
        payload: &[u8],
    ) -> bool {
        if !self.authenticated_local_peer(source_addr) {
            return false;
        }
        let Ok(message) = LocalCapabilityMessage::decode(payload) else {
            debug!(peer = %self.peer_display_name(source_addr), "Malformed local capability message");
            return false;
        };
        match message {
            LocalCapabilityMessage::Announce {
                process_epoch,
                revision,
                capabilities,
            } if self.local_rendezvous.role == Some(LocalRendezvousRole::Anchor) => {
                let Some(peer) = self.peers.get(source_addr) else {
                    return false;
                };
                if peer.remote_epoch() != Some(process_epoch) {
                    return false;
                }
                let identity = *peer.identity();
                let now = crate::time::instant_now();
                let update = if let Some(existing) =
                    self.local_rendezvous.providers.get_mut(source_addr)
                {
                    existing.apply_announcement(
                        identity,
                        process_epoch,
                        revision,
                        capabilities,
                        now,
                    )
                } else {
                    if self.local_rendezvous.providers.len()
                        >= crate::discovery::local_udp::LOCAL_CAPABILITY_MAX_PROVIDERS
                            .saturating_sub(1)
                    {
                        debug!(peer = %self.peer_display_name(source_addr), "Local capability provider limit reached");
                        return false;
                    }
                    self.local_rendezvous.providers.insert(
                        *source_addr,
                        ProviderState::new(identity, process_epoch, revision, capabilities, now),
                    );
                    ProviderAnnouncementUpdate::Changed
                };
                if update == ProviderAnnouncementUpdate::Changed {
                    self.local_rendezvous.roster_revision =
                        self.local_rendezvous.roster_revision.saturating_add(1);
                    self.local_rendezvous.roster_dirty = true;
                    self.refresh_anchor_directory();
                    true
                } else {
                    false
                }
            }
            LocalCapabilityMessage::Roster {
                anchor_epoch,
                revision,
                providers,
            } if self.local_rendezvous.role == Some(LocalRendezvousRole::Client) => {
                let Some(anchor) = self.local_rendezvous.anchor_peer else {
                    return false;
                };
                if anchor.identity.node_addr() != source_addr
                    || anchor.startup_epoch != anchor_epoch
                {
                    return false;
                }
                let fresh =
                    self.local_rendezvous
                        .accepted_roster
                        .is_none_or(|(epoch, old_revision)| {
                            epoch != anchor_epoch || revision > old_revision
                        });
                if !fresh {
                    return false;
                }
                let mut adverts = providers
                    .into_iter()
                    .filter_map(|provider| {
                        XOnlyPublicKey::from_slice(&provider.pubkey)
                            .ok()
                            .map(PeerIdentity::from_pubkey)
                            .map(|identity| LocalInstanceAdvertisement {
                                npub: identity.npub(),
                                startup_epoch: provider.process_epoch,
                                capabilities: provider.capabilities,
                            })
                    })
                    .collect::<Vec<_>>();
                adverts.push(
                    self.local_rendezvous
                        .self_advertisement(&self.identity, self.startup_epoch),
                );
                self.local_rendezvous.directory.replace(adverts);
                self.local_rendezvous.accepted_roster = Some((anchor_epoch, revision));
                false
            }
            _ => false,
        }
    }

    pub(super) fn prune_local_roster(&mut self) -> bool {
        let before = self.local_rendezvous.providers.len();
        let now = crate::time::instant_now();
        let active = self
            .local_rendezvous
            .providers
            .iter()
            .filter(|(node_addr, provider)| {
                self.authenticated_local_peer(node_addr) && provider.lease_is_current(now)
            })
            .map(|(node_addr, _)| *node_addr)
            .collect::<HashSet<_>>();
        self.local_rendezvous
            .providers
            .retain(|node_addr, _| active.contains(node_addr));
        before != self.local_rendezvous.providers.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node::endpoint_service::{
        EndpointServiceDatagramDelivery, EndpointServiceEventReceiver, EndpointServiceEventSender,
    };

    async fn register_service(
        node: &mut Node,
        port: u16,
        capability: Option<LocalInstanceCapability>,
    ) -> (bool, EndpointServiceEventReceiver) {
        let (sender, receiver) = EndpointServiceEventSender::channel(8);
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();
        assert!(
            node.handle_endpoint_control(NodeEndpointControlCommand::RegisterService {
                port,
                sender,
                capability,
                response_tx,
            })
            .await
            .is_none()
        );
        (response_rx.await.unwrap(), receiver)
    }

    fn assert_capabilities(node: &Node, expected: &[LocalInstanceCapability]) {
        assert_eq!(node.local_rendezvous.capabilities, expected);
        let adverts = node.local_capability_directory().snapshot();
        assert_eq!(adverts.len(), 1);
        assert_eq!(adverts[0].npub, node.npub());
        assert_eq!(adverts[0].capabilities, expected);
    }

    #[tokio::test]
    async fn closed_service_registration_is_reclaimed_without_maintenance() {
        const PORT: u16 = 7368;
        for replacement in [
            None,
            Some(LocalInstanceCapability::service("replacement/1", PORT)),
        ] {
            let mut config = Config::new();
            config.node.discovery.local.enabled = true;
            config.node.system_files_enabled = false;
            let mut node = Node::new(config).unwrap();
            node.local_rendezvous.role = Some(LocalRendezvousRole::Anchor);
            let role = LocalInstanceCapability::role("provider/1");
            node.set_local_instance_roles(vec![role.clone()]);
            let old = LocalInstanceCapability::service("original/1", PORT);
            let live = LocalInstanceCapability::service("other/1", PORT + 1);
            let (registered, old_receiver) =
                register_service(&mut node, PORT, Some(old.clone())).await;
            assert!(registered);
            let (registered, _live_receiver) =
                register_service(&mut node, PORT + 1, Some(live.clone())).await;
            assert!(registered);
            assert_capabilities(&node, &[role.clone(), old, live.clone()]);

            drop(old_receiver);
            let revision = node.local_rendezvous.capability_revision;
            let roster_revision = node.local_rendezvous.roster_revision;
            node.local_rendezvous.last_capability_sync_ms = 123;
            node.local_rendezvous.roster_dirty = false;
            // Dispatch directly, without starting the node or polling maintenance.
            let (registered, mut receiver) =
                register_service(&mut node, PORT, replacement.clone()).await;
            assert!(
                registered,
                "a dropped receiver must release its service port immediately"
            );
            let mut expected = vec![role, live];
            expected.extend(replacement);
            assert_capabilities(&node, &expected);
            assert!(node.local_rendezvous.capability_revision > revision);
            assert!(node.local_rendezvous.roster_revision > roster_revision);
            assert!(node.local_rendezvous.roster_dirty);
            assert_eq!(node.local_rendezvous.last_capability_sync_ms, 0);

            node.endpoint_services
                .deliver(vec![EndpointServiceDatagramDelivery::new(
                    PeerIdentity::from_pubkey_full(node.identity.pubkey_full()),
                    PORT + 1,
                    PORT,
                    crate::transport::PacketBuffer::new(b"restarted".to_vec()),
                )])
                .unwrap();
            let event = receiver.try_recv().unwrap();
            assert_eq!(event.messages.len(), 1);
            assert_eq!(event.messages[0].payload.as_slice(), b"restarted");
            receiver.release_messages(event.messages.len());
        }
    }

    #[tokio::test]
    async fn live_service_registration_keeps_its_receiver_and_capability() {
        const PORT: u16 = 7368;
        let mut config = Config::new();
        config.node.discovery.local.enabled = true;
        config.node.system_files_enabled = false;
        let mut node = Node::new(config).unwrap();
        let original = LocalInstanceCapability::service("original/1", PORT);
        let (registered, mut receiver) =
            register_service(&mut node, PORT, Some(original.clone())).await;
        assert!(registered);
        let revision = node.local_rendezvous.capability_revision;
        let (registered, mut rejected_receiver) = register_service(
            &mut node,
            PORT,
            Some(LocalInstanceCapability::service("replacement/1", PORT)),
        )
        .await;
        assert!(
            !registered,
            "a live receiver must retain its exclusive service port"
        );
        assert_capabilities(&node, &[original]);
        assert_eq!(node.local_rendezvous.capability_revision, revision);
        assert!(matches!(
            rejected_receiver.try_recv(),
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected)
        ));
        node.endpoint_services
            .deliver(vec![EndpointServiceDatagramDelivery::new(
                PeerIdentity::from_pubkey_full(node.identity.pubkey_full()),
                PORT + 1,
                PORT,
                crate::transport::PacketBuffer::new(b"original".to_vec()),
            )])
            .unwrap();
        let event = receiver.try_recv().unwrap();
        assert_eq!(event.messages[0].payload.as_slice(), b"original");
        receiver.release_messages(event.messages.len());
    }

    #[tokio::test]
    async fn closed_service_registration_is_reclaimed_with_local_discovery_disabled() {
        let mut config = Config::new();
        config.node.discovery.local.enabled = false;
        config.node.system_files_enabled = false;
        let mut node = Node::new(config).unwrap();
        let (registered, receiver) = register_service(&mut node, 7368, None).await;
        assert!(registered);
        drop(receiver);
        let (registered, _receiver) = register_service(&mut node, 7368, None).await;
        assert!(registered);
    }
}
