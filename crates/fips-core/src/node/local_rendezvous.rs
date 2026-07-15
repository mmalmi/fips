mod capabilities;

use super::*;
use crate::discovery::local::{
    LocalCapabilityDirectory, LocalInstanceAdvertisement, LocalInstanceCapability,
};
use crate::discovery::local_udp::LocalKeyHint;
use crate::transport::ReceivedPacket;
use rand::RngExt;
use secp256k1::XOnlyPublicKey;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use tracing::info;

const LOCAL_RENDEZVOUS_TRANSPORT_NAME: &str = "local-rendezvous";
const CAPABILITY_REFRESH_MS: u64 = 10_000;
const ROSTER_BROADCAST_MIN_MS: u64 = 250;
const KEY_HINT_RESPONSE_BURST: u32 = 32;
const KEY_HINT_RESPONSE_RATE: f64 = 64.0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum LocalRendezvousRole {
    Anchor,
    Client,
}

#[derive(Clone, Copy, Debug)]
struct AnchorPeer {
    identity: PeerIdentity,
    startup_epoch: [u8; 8],
}

#[derive(Clone, Debug)]
struct ProviderState {
    identity: PeerIdentity,
    startup_epoch: [u8; 8],
    revision: u64,
    capabilities: Vec<LocalInstanceCapability>,
}

pub(super) struct LocalRendezvous {
    fixed_addr: SocketAddr,
    retry_interval_ms: u64,
    transport_id: Option<TransportId>,
    role: Option<LocalRendezvousRole>,
    next_retry_ms: u64,
    pending_nonce: Option<u64>,
    key_hint_responses: rate_limit::TokenBucket,
    anchor_peer: Option<AnchorPeer>,
    capabilities: Vec<LocalInstanceCapability>,
    capability_revision: u64,
    last_capability_sync_ms: u64,
    providers: HashMap<NodeAddr, ProviderState>,
    roster_revision: u64,
    roster_dirty: bool,
    accepted_roster: Option<([u8; 8], u64)>,
    directory: LocalCapabilityDirectory,
}

impl LocalRendezvous {
    pub(super) fn new(config: &Config, identity: &Identity, startup_epoch: [u8; 8]) -> Self {
        let directory = LocalCapabilityDirectory::new();
        if config.node.discovery.local.enabled {
            directory.upsert(LocalInstanceAdvertisement {
                npub: identity.npub(),
                startup_epoch,
                capabilities: Vec::new(),
            });
        }
        Self {
            fixed_addr: SocketAddr::V4(config.node.discovery.local.rendezvous_addr),
            // Avoid a busy loop when a squatter owns the fixed port.
            retry_interval_ms: config.node.discovery.local.retry_interval_ms.max(1),
            transport_id: None,
            role: None,
            next_retry_ms: 0,
            pending_nonce: None,
            key_hint_responses: rate_limit::TokenBucket::with_params(
                KEY_HINT_RESPONSE_BURST,
                KEY_HINT_RESPONSE_RATE,
            ),
            anchor_peer: None,
            capabilities: Vec::new(),
            capability_revision: 1,
            last_capability_sync_ms: 0,
            providers: HashMap::new(),
            roster_revision: 1,
            roster_dirty: true,
            accepted_roster: None,
            directory,
        }
    }

    fn schedule_retry(&mut self, now_ms: u64) {
        let jitter_max = (self.retry_interval_ms / 4).max(1);
        let jitter = rand::rng().random_range(0..jitter_max);
        self.next_retry_ms = now_ms
            .saturating_add(self.retry_interval_ms)
            .saturating_add(jitter);
    }
}

impl Node {
    fn local_udp_config(
        bind_addr: SocketAddr,
        accept_connections: bool,
    ) -> crate::config::UdpConfig {
        crate::config::UdpConfig {
            bind_addr: Some(bind_addr.to_string()),
            advertise_on_nostr: Some(false),
            public: Some(false),
            outbound_only: Some(false),
            accept_connections: Some(accept_connections),
            ..crate::config::UdpConfig::default()
        }
    }

    async fn start_local_udp_transport(
        &mut self,
        packet_tx: &PacketTx,
        bind_addr: SocketAddr,
        exclusive: bool,
    ) -> Result<TransportId, TransportError> {
        let transport_id = self.allocate_transport_id();
        let mut udp = UdpTransport::new(
            transport_id,
            Some(LOCAL_RENDEZVOUS_TRANSPORT_NAME.to_string()),
            Self::local_udp_config(bind_addr, exclusive),
            packet_tx.clone(),
        );
        if exclusive {
            udp.start_exclusive_async().await?;
        } else {
            udp.start_async().await?;
        }
        self.transports
            .insert(transport_id, TransportHandle::Udp(udp));
        Ok(transport_id)
    }

    pub(in crate::node) async fn start_local_rendezvous(&mut self, packet_tx: &PacketTx) {
        if !self.config.node.discovery.local.enabled || self.local_rendezvous.transport_id.is_some()
        {
            return;
        }
        let fixed_addr = self.local_rendezvous.fixed_addr;
        match self
            .start_local_udp_transport(packet_tx, fixed_addr, true)
            .await
        {
            Ok(transport_id) => {
                self.install_local_rendezvous(transport_id, LocalRendezvousRole::Anchor);
                info!(addr = %fixed_addr, "Local FIPS UDP rendezvous anchor acquired");
            }
            Err(TransportError::AddressInUse { .. }) => {
                let ephemeral = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
                match self
                    .start_local_udp_transport(packet_tx, ephemeral, false)
                    .await
                {
                    Ok(transport_id) => {
                        self.install_local_rendezvous(transport_id, LocalRendezvousRole::Client);
                        self.request_local_anchor_key().await;
                    }
                    Err(error) => {
                        warn!(%error, "Failed to start local FIPS UDP client socket");
                        self.local_rendezvous.schedule_retry(Self::now_ms());
                    }
                }
            }
            Err(error) => {
                warn!(%error, "Failed to bind local FIPS UDP rendezvous anchor");
                self.local_rendezvous.schedule_retry(Self::now_ms());
            }
        }
    }

    fn install_local_rendezvous(&mut self, transport_id: TransportId, role: LocalRendezvousRole) {
        self.local_rendezvous.transport_id = Some(transport_id);
        self.local_rendezvous.role = Some(role);
        self.local_rendezvous.pending_nonce = None;
        self.local_rendezvous.anchor_peer = None;
        self.local_rendezvous.providers.clear();
        self.local_rendezvous.roster_dirty = true;
        self.local_rendezvous.accepted_roster = None;
        self.local_rendezvous.last_capability_sync_ms = 0;
        self.local_rendezvous.schedule_retry(Self::now_ms());
        self.local_rendezvous.directory.replace([self
            .local_rendezvous
            .self_advertisement(&self.identity, self.startup_epoch)]);
    }

    pub(in crate::node) fn is_local_rendezvous_path(
        &self,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) -> bool {
        self.local_rendezvous.transport_id == Some(transport_id)
            && remote_addr
                .as_str()
                .and_then(|value| value.parse::<SocketAddr>().ok())
                .is_some_and(|addr| addr.ip().is_loopback())
    }

    pub(in crate::node) fn is_local_rendezvous_transport(
        &self,
        transport_id: &TransportId,
    ) -> bool {
        self.local_rendezvous.transport_id.as_ref() == Some(transport_id)
    }

    pub(in crate::node) fn local_rendezvous_transport_id(&self) -> Option<TransportId> {
        self.local_rendezvous.transport_id
    }

    /// Retire stale fixed-address state only after its replacement completed
    /// Noise IK and the normal identity ACL.
    pub(in crate::node) fn retire_replaced_local_anchor(
        &mut self,
        authenticated_owner: &NodeAddr,
        transport_id: TransportId,
        remote_addr: &TransportAddr,
    ) {
        let fixed_addr = TransportAddr::from_socket_addr(self.local_rendezvous.fixed_addr);
        if self.local_rendezvous.role != Some(LocalRendezvousRole::Client)
            || self.local_rendezvous.transport_id != Some(transport_id)
            || remote_addr != &fixed_addr
        {
            return;
        }
        let replaced = self
            .peers
            .values()
            .filter_map(|peer| {
                (peer.node_addr() != authenticated_owner
                    && peer.transport_id() == Some(transport_id)
                    && peer.current_addr() == Some(&fixed_addr))
                .then_some(*peer.node_addr())
            })
            .collect::<Vec<_>>();
        for peer in replaced {
            self.remove_active_peer(&peer);
        }
    }

    fn authenticated_local_peer(&self, node_addr: &NodeAddr) -> bool {
        self.peers.get(node_addr).is_some_and(|peer| {
            peer.is_healthy()
                && peer.transport_id() == self.local_rendezvous.transport_id
                && peer.current_addr().is_some_and(|addr| {
                    addr.as_str()
                        .and_then(|value| value.parse::<SocketAddr>().ok())
                        .is_some_and(|addr| addr.ip().is_loopback())
                })
        })
    }

    fn connected_local_anchor(&self) -> Option<AnchorPeer> {
        if self.local_rendezvous.role != Some(LocalRendezvousRole::Client) {
            return None;
        }
        let transport_id = self.local_rendezvous.transport_id?;
        let fixed_addr = TransportAddr::from_socket_addr(self.local_rendezvous.fixed_addr);
        self.peers.values().find_map(|peer| {
            if !peer.is_healthy()
                || peer.transport_id() != Some(transport_id)
                || peer.current_addr() != Some(&fixed_addr)
            {
                return None;
            }
            Some(AnchorPeer {
                identity: *peer.identity(),
                startup_epoch: peer.remote_epoch()?,
            })
        })
    }

    async fn request_local_anchor_key(&mut self) {
        if self.local_rendezvous.role != Some(LocalRendezvousRole::Client) {
            return;
        }
        // The fixed bind proves only that an owner exists. Probe even while a
        // prior owner still looks healthy so an abrupt replacement is noticed.
        let Some(transport_id) = self.local_rendezvous.transport_id else {
            return;
        };
        let remote_addr = TransportAddr::from_socket_addr(self.local_rendezvous.fixed_addr);
        let nonce = rand::rng().random::<u64>();
        self.local_rendezvous.pending_nonce = Some(nonce);
        let request = LocalKeyHint::Request { nonce }.encode();
        if let Some(transport) = self.transports.get(&transport_id)
            && let Err(error) = transport.send(&remote_addr, &request).await
        {
            debug!(%error, "Local FIPS key-hint request failed");
        }
    }

    /// Handle the tiny unauthenticated discovery prelude on the dedicated
    /// loopback path. The returned key is only a routing hint; ordinary Noise
    /// IK and the normal ACL path prove and authorize it before any link exists.
    pub(in crate::node) async fn handle_local_key_hint(&mut self, packet: &ReceivedPacket) -> bool {
        if !self.is_local_rendezvous_path(packet.transport_id, &packet.remote_addr)
            || !LocalKeyHint::is_wire_shape(packet.data.as_slice())
        {
            return false;
        }
        let Some(message) = LocalKeyHint::decode(packet.data.as_slice()) else {
            debug!("Dropping malformed local FIPS key-hint datagram");
            return true;
        };
        match message {
            LocalKeyHint::Request { nonce }
                if self.local_rendezvous.role == Some(LocalRendezvousRole::Anchor) =>
            {
                if !self.local_rendezvous.key_hint_responses.try_acquire() {
                    debug!("Rate-limiting local FIPS key-hint response");
                    return true;
                }
                let response = LocalKeyHint::Response {
                    nonce,
                    pubkey: self.identity.pubkey().serialize(),
                }
                .encode();
                if let Some(transport) = self.transports.get(&packet.transport_id)
                    && let Err(error) = transport.send(&packet.remote_addr, &response).await
                {
                    debug!(%error, "Local FIPS key-hint response failed");
                }
            }
            LocalKeyHint::Response { nonce, pubkey }
                if self.local_rendezvous.role == Some(LocalRendezvousRole::Client)
                    && self.local_rendezvous.pending_nonce == Some(nonce)
                    && packet.remote_addr
                        == TransportAddr::from_socket_addr(self.local_rendezvous.fixed_addr) =>
            {
                self.local_rendezvous.pending_nonce = None;
                let Ok(pubkey) = XOnlyPublicKey::from_slice(&pubkey) else {
                    return true;
                };
                if pubkey == self.identity.pubkey() {
                    warn!("Local rendezvous owner uses this process's FIPS identity");
                    return true;
                }
                let identity = PeerIdentity::from_pubkey(pubkey);
                if self
                    .connected_local_anchor()
                    .is_some_and(|anchor| anchor.identity.node_addr() == identity.node_addr())
                {
                    return true;
                }
                if !self.is_connecting_to_peer_on_path(
                    identity.node_addr(),
                    packet.transport_id,
                    &packet.remote_addr,
                ) && let Err(error) = self
                    .initiate_connection(packet.transport_id, packet.remote_addr.clone(), identity)
                    .await
                {
                    debug!(%error, "Local FIPS IK authentication start failed");
                }
            }
            _ => {}
        }
        true
    }

    async fn try_promote_local_anchor(&mut self) -> bool {
        let Some(packet_tx) = self.packet_tx.clone() else {
            return false;
        };
        let candidate_id = self.allocate_transport_id();
        let mut udp = UdpTransport::new(
            candidate_id,
            Some(LOCAL_RENDEZVOUS_TRANSPORT_NAME.to_string()),
            Self::local_udp_config(self.local_rendezvous.fixed_addr, true),
            packet_tx,
        );
        match udp.start_exclusive_async().await {
            Ok(()) => {
                let old_transport_id = self.local_rendezvous.transport_id;
                self.transports
                    .insert(candidate_id, TransportHandle::Udp(udp));
                let old_peers = self
                    .peers
                    .values()
                    .filter(|peer| peer.transport_id() == old_transport_id)
                    .map(|peer| *peer.node_addr())
                    .collect::<Vec<_>>();
                for peer in old_peers {
                    self.remove_active_peer(&peer);
                }
                if let Some(old_transport_id) = old_transport_id
                    && let Some(mut old_transport) = self.transports.remove(&old_transport_id)
                {
                    let _ = old_transport.stop().await;
                }
                self.install_local_rendezvous(candidate_id, LocalRendezvousRole::Anchor);
                info!(addr = %self.local_rendezvous.fixed_addr, "Local FIPS UDP rendezvous anchor promoted");
                true
            }
            Err(TransportError::AddressInUse { .. }) => false,
            Err(error) => {
                debug!(%error, "Local FIPS UDP anchor retry failed");
                false
            }
        }
    }

    pub(in crate::node) async fn poll_local_rendezvous(&mut self) {
        self.remove_closed_local_capabilities();
        if !self.config.node.discovery.local.enabled {
            return;
        }
        let now_ms = Self::now_ms();
        if let Some(transport_id) = self.local_rendezvous.transport_id
            && self
                .transports
                .get(&transport_id)
                .is_none_or(|transport| !transport.is_operational())
        {
            self.transports.remove(&transport_id);
            let local_peers = self
                .peers
                .values()
                .filter(|peer| peer.transport_id() == Some(transport_id))
                .map(|peer| *peer.node_addr())
                .collect::<Vec<_>>();
            for peer in local_peers {
                self.remove_active_peer(&peer);
            }
            self.local_rendezvous.transport_id = None;
            self.local_rendezvous.role = None;
            self.local_rendezvous.anchor_peer = None;
            self.local_rendezvous.pending_nonce = None;
            self.local_rendezvous.providers.clear();
            self.local_rendezvous.accepted_roster = None;
            self.local_rendezvous.directory.replace([self
                .local_rendezvous
                .self_advertisement(&self.identity, self.startup_epoch)]);
        }
        if self.local_rendezvous.transport_id.is_none() {
            if now_ms >= self.local_rendezvous.next_retry_ms
                && let Some(packet_tx) = self.packet_tx.clone()
            {
                self.start_local_rendezvous(&packet_tx).await;
            }
            return;
        }
        if self.local_rendezvous.role == Some(LocalRendezvousRole::Client) {
            let anchor = self.connected_local_anchor();
            let connected = anchor.is_some();
            if self.local_rendezvous.anchor_peer.is_some() && !connected {
                self.local_rendezvous.directory.replace([self
                    .local_rendezvous
                    .self_advertisement(&self.identity, self.startup_epoch)]);
                self.local_rendezvous.accepted_roster = None;
            }
            if self
                .local_rendezvous
                .anchor_peer
                .map(|peer| (*peer.identity.node_addr(), peer.startup_epoch))
                != anchor.map(|peer| (*peer.identity.node_addr(), peer.startup_epoch))
            {
                self.local_rendezvous.accepted_roster = None;
                self.local_rendezvous.last_capability_sync_ms = 0;
            }
            self.local_rendezvous.anchor_peer = anchor;
            if connected
                && (self.local_rendezvous.last_capability_sync_ms == 0
                    || now_ms.saturating_sub(self.local_rendezvous.last_capability_sync_ms)
                        >= CAPABILITY_REFRESH_MS)
                && let Some(anchor) = self.local_rendezvous.anchor_peer
            {
                self.announce_local_capabilities(anchor.identity).await;
            }
            if now_ms >= self.local_rendezvous.next_retry_ms
                && !self.try_promote_local_anchor().await
            {
                self.request_local_anchor_key().await;
                self.local_rendezvous.schedule_retry(now_ms);
            }
        } else if self.local_rendezvous.role == Some(LocalRendezvousRole::Anchor) {
            if self.prune_local_roster() {
                self.local_rendezvous.roster_revision =
                    self.local_rendezvous.roster_revision.saturating_add(1);
                self.local_rendezvous.roster_dirty = true;
                self.refresh_anchor_directory();
            }
            let since_broadcast =
                now_ms.saturating_sub(self.local_rendezvous.last_capability_sync_ms);
            if (self.local_rendezvous.roster_dirty && since_broadcast >= ROSTER_BROADCAST_MIN_MS)
                || since_broadcast >= CAPABILITY_REFRESH_MS
            {
                self.broadcast_local_roster().await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_hint_packet(
        transport_id: TransportId,
        remote_addr: SocketAddr,
        hint: LocalKeyHint,
    ) -> ReceivedPacket {
        ReceivedPacket {
            transport_id,
            remote_addr: TransportAddr::from_socket_addr(remote_addr),
            data: crate::transport::PacketBuffer::new(hint.encode()),
            timestamp_ms: 0,
            trace_enqueued_at: None,
            trace_rx_loop_owned_at: None,
        }
    }

    #[test]
    fn key_hint_responses_have_a_bounded_global_burst() {
        let mut config = Config::new();
        config.node.discovery.local.enabled = true;
        let identity = Identity::generate();
        let mut rendezvous = LocalRendezvous::new(&config, &identity, [0; 8]);

        for _ in 0..KEY_HINT_RESPONSE_BURST {
            assert!(rendezvous.key_hint_responses.try_acquire());
        }
        assert!(!rendezvous.key_hint_responses.try_acquire());
    }

    #[test]
    fn local_rendezvous_still_enforces_the_identity_acl() {
        let dir = tempfile::tempdir().unwrap();
        let denied = Identity::generate();
        let mut config = Config::new();
        config.node.discovery.local.enabled = true;
        config.node.system_files_enabled = false;
        let mut node = Node::new(config).unwrap();
        let transport_id = TransportId::new(77);
        node.local_rendezvous.transport_id = Some(transport_id);
        node.local_rendezvous.role = Some(LocalRendezvousRole::Anchor);
        node.peer_acl = crate::node::acl::PeerAclReloader::with_paths(
            dir.path().join("peers.allow"),
            dir.path().join("peers.deny"),
        );
        std::fs::write(
            dir.path().join("peers.deny"),
            format!("{}\n", denied.npub()),
        )
        .unwrap();
        assert!(node.reload_peer_acl());

        let result = node.authorize_peer(
            &PeerIdentity::from_pubkey_full(denied.pubkey_full()),
            crate::node::acl::PeerAclContext::InboundHandshake,
            transport_id,
            &TransportAddr::from_socket_addr(node.local_rendezvous.fixed_addr),
        );

        assert!(matches!(result, Err(NodeError::AccessDenied(_))));
    }

    #[tokio::test]
    async fn client_accepts_only_matching_nonce_from_fixed_owner_address() {
        let mut config = Config::new();
        config.node.discovery.local.enabled = true;
        config.node.discovery.local.rendezvous_addr = "127.0.0.1:32111".parse().unwrap();
        let mut node = Node::new(config).unwrap();
        let transport_id = TransportId::new(77);
        node.local_rendezvous.transport_id = Some(transport_id);
        node.local_rendezvous.role = Some(LocalRendezvousRole::Client);
        node.local_rendezvous.pending_nonce = Some(9);
        let pubkey = Identity::generate().pubkey().serialize();

        let wrong_nonce = key_hint_packet(
            transport_id,
            node.local_rendezvous.fixed_addr,
            LocalKeyHint::Response { nonce: 8, pubkey },
        );
        assert!(node.handle_local_key_hint(&wrong_nonce).await);
        assert_eq!(node.local_rendezvous.pending_nonce, Some(9));

        let wrong_source = key_hint_packet(
            transport_id,
            "127.0.0.1:32112".parse().unwrap(),
            LocalKeyHint::Response { nonce: 9, pubkey },
        );
        assert!(node.handle_local_key_hint(&wrong_source).await);
        assert_eq!(node.local_rendezvous.pending_nonce, Some(9));
        assert_eq!(node.connection_count(), 0);
    }
}
