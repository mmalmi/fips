use super::*;
use crate::packet_mover2::{
    OwnerConfig, OwnerCryptoKeys, OwnerId, PacketClass, PacketMover2EndpointCommandRoute,
    PacketMover2FspWrapRoute, PacketMover2LiveEndpointRoute, PacketMover2LiveOwnerRoutes,
    PacketMover2LiveTunRoute, PacketMover2TunDestinationRoute, PacketMover2TunOutboundRoute,
    TransportPath,
};

const INITIAL_FMP_GENERATION: u64 = 1;
const INITIAL_FSP_GENERATION: u64 = 1;

struct PacketMover2FmpOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
    path: TransportPath,
}

struct PacketMover2FspOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
    session_start_ms: u64,
    routes: PacketMover2LiveOwnerRoutes,
    next_hop: Option<NodeAddr>,
}

impl Node {
    pub(in crate::node) fn sync_packet_mover2_fmp_owner(&mut self, node_addr: &NodeAddr) -> bool {
        let Some(seed) = self.packet_mover2_fmp_owner_seed(node_addr) else {
            self.remove_packet_mover2_fmp_owner(node_addr);
            return false;
        };

        self.packet_mover2
            .register_owner_if_missing(seed.owner, seed.config);
        self.packet_mover2
            .set_owner_crypto_keys(seed.owner, seed.keys)
            .is_ok()
            && self
                .packet_mover2
                .set_owner_active_path(seed.owner, seed.path)
                .is_ok()
    }

    pub(in crate::node) fn remove_packet_mover2_fmp_owner(&mut self, node_addr: &NodeAddr) {
        self.packet_mover2
            .unregister_owner(OwnerId::fmp_node(*node_addr));
    }

    pub(in crate::node) fn sync_packet_mover2_fsp_owner(&mut self, node_addr: &NodeAddr) -> bool {
        let Some(seed) = self.packet_mover2_fsp_owner_seed(node_addr) else {
            self.remove_packet_mover2_fsp_owner(node_addr);
            return false;
        };

        self.packet_mover2
            .register_owner_if_missing(seed.owner, seed.config);
        let next_hop_ready = seed
            .next_hop
            .is_none_or(|next_hop| self.sync_packet_mover2_fmp_owner(&next_hop));
        self.packet_mover2
            .set_owner_crypto_keys(seed.owner, seed.keys)
            .is_ok()
            && self
                .packet_mover2
                .set_owner_fsp_session_start_ms(seed.owner, seed.session_start_ms)
                .is_ok()
            && self
                .packet_mover2
                .replace_owner_routes(seed.owner, seed.routes)
                .is_ok()
            && next_hop_ready
    }

    pub(in crate::node) fn remove_packet_mover2_fsp_owner(&mut self, node_addr: &NodeAddr) {
        self.packet_mover2
            .unregister_owner(OwnerId::fsp_node(*node_addr));
    }

    fn packet_mover2_fmp_owner_seed(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<PacketMover2FmpOwnerSeed> {
        let peer = self.peers.get(node_addr)?;
        let session = peer.noise_session()?;
        let transport_id = peer.transport_id()?;
        let remote_addr = peer.current_addr()?.clone();
        let open = Arc::new(session.recv_cipher_clone()?);
        let seal = Arc::new(session.send_cipher_clone()?);

        Some(PacketMover2FmpOwnerSeed {
            owner: OwnerId::fmp_node(*node_addr),
            config: OwnerConfig::new(
                INITIAL_FMP_GENERATION,
                self.packet_mover2_owner_in_flight_limit(),
            )
            .with_next_send_counter(session.current_send_counter()),
            keys: OwnerCryptoKeys::new(open, seal),
            path: TransportPath::live(transport_id, remote_addr),
        })
    }

    fn packet_mover2_fsp_owner_seed(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Option<PacketMover2FspOwnerSeed> {
        let (open, seal, next_send_counter, session_start_ms, fsp_flags, inner_flags) = {
            let session = self.sessions.get(node_addr)?;
            let (open, seal) = session.fsp_crypto_keys()?;
            let mut fsp_flags = 0;
            if session.current_k_bit() {
                fsp_flags |= crate::node::session_wire::FSP_FLAG_K;
            }
            let inner_flags = crate::protocol::FspInnerFlags {
                spin_bit: session.mmp().is_some_and(|mmp| mmp.spin_bit.tx_bit()),
            }
            .to_byte();
            (
                open,
                seal,
                session.send_counter(),
                session.session_start_ms(),
                fsp_flags,
                inner_flags,
            )
        };
        let (routes, next_hop) =
            self.packet_mover2_fsp_owner_routes(node_addr, fsp_flags, inner_flags);

        Some(PacketMover2FspOwnerSeed {
            owner: OwnerId::fsp_node(*node_addr),
            config: OwnerConfig::new(
                INITIAL_FSP_GENERATION,
                self.packet_mover2_owner_in_flight_limit(),
            )
            .with_next_send_counter(next_send_counter)
            .with_fsp_session_start_ms(session_start_ms),
            keys: OwnerCryptoKeys::new(Arc::new(open), Arc::new(seal)),
            session_start_ms,
            routes,
            next_hop,
        })
    }

    fn packet_mover2_fsp_owner_routes(
        &mut self,
        node_addr: &NodeAddr,
        fsp_flags: u8,
        inner_flags: u8,
    ) -> (PacketMover2LiveOwnerRoutes, Option<NodeAddr>) {
        let owner = OwnerId::fsp_node(*node_addr);
        let Some((wrap, next_hop)) = self.packet_mover2_fsp_wrap_route(node_addr) else {
            return (PacketMover2LiveOwnerRoutes::new(), None);
        };

        let mut routes = PacketMover2LiveOwnerRoutes::new();
        let tun = PacketMover2TunOutboundRoute::fsp_ipv6_shim(
            owner,
            INITIAL_FSP_GENERATION,
            PacketClass::Bulk,
            fsp_flags,
            inner_flags,
        )
        .with_fmp_wrap(wrap);
        routes.push_tun_destination(PacketMover2LiveTunRoute::new(
            *node_addr,
            PacketMover2TunDestinationRoute::new(tun),
        ));

        let endpoint = PacketMover2EndpointCommandRoute::fsp(
            owner,
            INITIAL_FSP_GENERATION,
            fsp_flags,
            inner_flags,
        )
        .with_fmp_wrap(wrap);
        routes.push_endpoint_destination(PacketMover2LiveEndpointRoute::new(*node_addr, endpoint));

        (routes, Some(next_hop))
    }

    fn packet_mover2_fsp_wrap_route(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Option<(PacketMover2FspWrapRoute, NodeAddr)> {
        let (next_hop, receiver_idx, transport_id, remote_addr, fmp_flags) = {
            let peer = self.find_next_hop(dest_addr)?;
            let mut fmp_flags = if peer.mmp().is_some_and(|mmp| mmp.spin_bit.tx_bit()) {
                FLAG_SP
            } else {
                0
            };
            if peer.current_k_bit() {
                fmp_flags |= FLAG_KEY_EPOCH;
            }
            (
                *peer.node_addr(),
                peer.their_index()?.as_u32(),
                peer.transport_id()?,
                peer.current_addr()?.clone(),
                fmp_flags,
            )
        };
        let path_mtu = self
            .transports
            .get(&transport_id)
            .map(|transport| transport.link_mtu(&remote_addr))
            .unwrap_or_else(|| self.transport_mtu());
        let wrap = PacketMover2FspWrapRoute::new(
            OwnerId::fmp_node(next_hop),
            INITIAL_FMP_GENERATION,
            receiver_idx,
            *self.node_addr(),
            *dest_addr,
        )
        .with_fmp_flags(fmp_flags)
        .with_ttl(self.config.node.session.default_ttl)
        .with_path_mtu(path_mtu);
        Some((wrap, next_hop))
    }

    fn packet_mover2_owner_in_flight_limit(&self) -> usize {
        self.config.node.limits.max_pending_inbound.max(1)
    }
}
