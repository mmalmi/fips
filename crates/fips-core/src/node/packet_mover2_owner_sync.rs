use super::*;
use crate::packet_mover2::{
    OutputTarget, OwnerConfig, OwnerCryptoKeys, OwnerId, PacketClass,
    PacketMover2EndpointCommandRoute, PacketMover2FspWrapRoute, PacketMover2IngressRoute,
    PacketMover2LiveEndpointRoute, PacketMover2LiveFmpIngressRoute,
    PacketMover2LiveFspIngressRoute, PacketMover2LiveOwnerRoutes, PacketMover2LiveTunRoute,
    PacketMover2OutputDrop, PacketMover2OutputError, PacketMover2TunDestinationRoute,
    PacketMover2TunOutboundRoute, TransportPath,
};

const PACKET_MOVER2_DEFAULT_OWNER_BULK_IN_FLIGHT_LIMIT: usize = 16;

struct PacketMover2FmpOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
    path: TransportPath,
    routes: PacketMover2LiveOwnerRoutes,
}

struct PacketMover2FspOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
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
            .register_owner_if_missing(seed.owner, seed.config.clone());
        self.packet_mover2
            .apply_owner_live_config(seed.owner, seed.config)
            .is_ok()
            && self
                .packet_mover2
                .set_owner_crypto_keys(seed.owner, seed.keys)
                .is_ok()
            && self
                .packet_mover2
                .set_owner_active_path(seed.owner, seed.path)
                .is_ok()
            && self
                .packet_mover2
                .replace_owner_routes(seed.owner, seed.routes)
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
            .register_owner_if_missing(seed.owner, seed.config.clone());
        let next_hop_ready = seed
            .next_hop
            .is_none_or(|next_hop| self.sync_packet_mover2_fmp_owner(&next_hop));
        self.packet_mover2
            .apply_owner_live_config(seed.owner, seed.config)
            .is_ok()
            && self
                .packet_mover2
                .set_owner_crypto_keys(seed.owner, seed.keys)
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
        let receiver_idx = peer.our_index()?.as_u32();
        let generation = peer.session_generation();
        let session_start_ms = Self::now_ms().wrapping_sub(u64::from(peer.session_elapsed_ms()));
        let open = Arc::new(session.recv_cipher_clone()?);
        let seal = Arc::new(session.send_cipher_clone()?);
        let counter_authority = session.send_counter_authority();
        let mut routes = PacketMover2LiveOwnerRoutes::new();
        routes.push_fmp_ingress(PacketMover2LiveFmpIngressRoute::new(
            transport_id,
            receiver_idx,
            PacketMover2IngressRoute::new(
                OwnerId::fmp_node(*node_addr),
                generation,
                OutputTarget::SessionIngress {
                    local_addr: *self.node_addr(),
                },
            )
            .with_class(PacketClass::Bulk),
        ));

        Some(PacketMover2FmpOwnerSeed {
            owner: OwnerId::fmp_node(*node_addr),
            config: self
                .packet_mover2_owner_config(generation)
                .with_send_counter_authority(counter_authority)
                .with_fmp_session_start_ms(session_start_ms),
            keys: OwnerCryptoKeys::new(open, seal),
            path: TransportPath::live(transport_id, remote_addr),
            routes,
        })
    }

    fn packet_mover2_fsp_owner_seed(
        &mut self,
        node_addr: &NodeAddr,
    ) -> Option<PacketMover2FspOwnerSeed> {
        let (
            open,
            seal,
            counter_authority,
            session_start_ms,
            fsp_flags,
            inner_flags,
            coords_warmup_remaining,
            last_outbound_next_hop,
        ) = {
            let session = self.sessions.get(node_addr)?;
            let (open, seal) = session.fsp_crypto_keys()?;
            let counter_authority = session.send_counter_authority()?;
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
                counter_authority,
                session.session_start_ms(),
                fsp_flags,
                inner_flags,
                session.coords_warmup_remaining(),
                session.last_outbound_next_hop(),
            )
        };
        let generation = Self::packet_mover2_generation_from_session_start_ms(session_start_ms);
        let (routes, next_hop) =
            self.packet_mover2_fsp_owner_routes(node_addr, generation, fsp_flags, inner_flags);
        let route_changed_to_transit = next_hop.is_some_and(|next_hop| {
            next_hop != *node_addr && last_outbound_next_hop != Some(next_hop)
        });
        let owner_coords_warmup_remaining = if route_changed_to_transit {
            coords_warmup_remaining.max(1)
        } else {
            coords_warmup_remaining
        };
        let coords_prefix =
            self.packet_mover2_fsp_coords_prefix(node_addr, owner_coords_warmup_remaining);

        Some(PacketMover2FspOwnerSeed {
            owner: OwnerId::fsp_node(*node_addr),
            config: self
                .packet_mover2_owner_config(generation)
                .with_send_counter_authority(counter_authority)
                .with_fsp_session_start_ms(session_start_ms)
                .with_fsp_coords_warmup(owner_coords_warmup_remaining, coords_prefix),
            keys: OwnerCryptoKeys::new(Arc::new(open), Arc::new(seal)),
            routes,
            next_hop,
        })
    }

    fn packet_mover2_fsp_coords_prefix(
        &self,
        node_addr: &NodeAddr,
        coords_warmup_remaining: u8,
    ) -> Vec<u8> {
        if coords_warmup_remaining == 0 {
            return Vec::new();
        }
        self.packet_mover2_fsp_coords_prefix_for_dest(node_addr)
    }

    pub(in crate::node) fn packet_mover2_fsp_coords_prefix_for_dest(
        &self,
        node_addr: &NodeAddr,
    ) -> Vec<u8> {
        let src = self.tree_state.my_coords().clone();
        let dst = self.get_dest_coords(node_addr);
        let mut prefix = Vec::with_capacity(
            crate::protocol::coords_wire_size(&src) + crate::protocol::coords_wire_size(&dst),
        );
        crate::protocol::encode_coords(&src, &mut prefix);
        crate::protocol::encode_coords(&dst, &mut prefix);
        prefix
    }

    fn packet_mover2_fsp_owner_routes(
        &mut self,
        node_addr: &NodeAddr,
        generation: u64,
        fsp_flags: u8,
        inner_flags: u8,
    ) -> (PacketMover2LiveOwnerRoutes, Option<NodeAddr>) {
        let owner = OwnerId::fsp_node(*node_addr);
        let Some((wrap, next_hop)) = self.packet_mover2_fsp_wrap_route(node_addr) else {
            return (PacketMover2LiveOwnerRoutes::new(), None);
        };

        let mut routes = PacketMover2LiveOwnerRoutes::new();
        routes.push_fsp_ingress(PacketMover2LiveFspIngressRoute::new(
            *node_addr,
            PacketMover2IngressRoute::new(
                owner,
                generation,
                OutputTarget::SessionPayload {
                    local_addr: *self.node_addr(),
                },
            )
            .with_class(PacketClass::Bulk),
        ));
        let transit_coords_prefix = if next_hop != *node_addr {
            self.packet_mover2_fsp_coords_prefix_for_dest(node_addr)
        } else {
            Vec::new()
        };
        let route_fsp_flags = if transit_coords_prefix.is_empty() {
            fsp_flags
        } else {
            fsp_flags | crate::node::session_wire::FSP_FLAG_CP
        };
        let tun = PacketMover2TunOutboundRoute::fsp_ipv6_shim(
            owner,
            generation,
            PacketClass::Bulk,
            route_fsp_flags,
            inner_flags,
        )
        .with_fsp_cleartext_prefix(transit_coords_prefix.clone())
        .with_fmp_wrap(wrap);
        routes.push_tun_destination(PacketMover2LiveTunRoute::new(
            *node_addr,
            PacketMover2TunDestinationRoute::new(tun),
        ));

        let endpoint =
            PacketMover2EndpointCommandRoute::fsp(owner, generation, route_fsp_flags, inner_flags)
                .with_fsp_cleartext_prefix(transit_coords_prefix)
                .with_fmp_wrap(wrap);
        routes.push_endpoint_destination(PacketMover2LiveEndpointRoute::new(*node_addr, endpoint));

        (routes, Some(next_hop))
    }

    pub(in crate::node) fn packet_mover2_fsp_wrap_route(
        &mut self,
        dest_addr: &NodeAddr,
    ) -> Option<(PacketMover2FspWrapRoute, NodeAddr)> {
        let (next_hop, generation, receiver_idx, transport_id, remote_addr, fmp_flags) = {
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
                peer.session_generation(),
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
            generation,
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

    fn packet_mover2_owner_config(&self, generation: u64) -> OwnerConfig {
        let in_flight_limit = self.packet_mover2_owner_in_flight_limit();
        let bulk_in_flight_limit = packet_mover2_owner_bulk_in_flight_limit(in_flight_limit);
        OwnerConfig::new(generation, in_flight_limit)
            .with_bulk_in_flight_limit(bulk_in_flight_limit)
    }

    pub(in crate::node) fn packet_mover2_fsp_generation(
        &self,
        node_addr: &NodeAddr,
    ) -> Option<u64> {
        self.sessions.get(node_addr).map(|session| {
            Self::packet_mover2_generation_from_session_start_ms(session.session_start_ms())
        })
    }

    fn packet_mover2_generation_from_session_start_ms(session_start_ms: u64) -> u64 {
        session_start_ms.max(1)
    }

    pub(in crate::node) fn packet_mover2_fmp_output_drop_error(
        &self,
        node_addr: NodeAddr,
        drop: &PacketMover2OutputDrop,
    ) -> NodeError {
        match drop.reason() {
            PacketMover2OutputError::MtuExceeded => NodeError::MtuExceeded {
                node_addr,
                packet_size: drop.payload_len(),
                mtu: self.packet_mover2_drop_path_mtu(drop),
            },
            PacketMover2OutputError::NoRoute => {
                NodeError::LocalRouteUnavailable("packet_mover2 transport route unavailable".into())
            }
            reason => NodeError::SendFailed {
                node_addr,
                reason: format!("packet_mover2 transport output failed: {:?}", reason),
            },
        }
    }

    fn packet_mover2_drop_path_mtu(&self, drop: &PacketMover2OutputDrop) -> u16 {
        let Some(TransportPath::Live {
            transport_id,
            remote_addr,
        }) = drop.path()
        else {
            return self.transport_mtu();
        };
        self.transports
            .get(&transport_id)
            .map(|transport| transport.link_mtu(&remote_addr))
            .unwrap_or_else(|| self.transport_mtu())
    }
}

fn packet_mover2_owner_bulk_in_flight_limit(in_flight_limit: usize) -> usize {
    let in_flight_limit = in_flight_limit.max(1);
    let priority_reserve = usize::from(in_flight_limit > 1);
    PACKET_MOVER2_DEFAULT_OWNER_BULK_IN_FLIGHT_LIMIT
        .min(in_flight_limit.saturating_sub(priority_reserve))
        .max(1)
}

#[cfg(test)]
mod packet_mover2_owner_sync_tests {
    use super::*;

    #[test]
    fn owner_bulk_in_flight_limit_reserves_priority_slot() {
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(0), 1);
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(1), 1);
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(2), 1);
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(16), 15);
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(17), 16);
        assert_eq!(packet_mover2_owner_bulk_in_flight_limit(128), 16);
    }
}
