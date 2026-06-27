use super::*;
use crate::packet_mover2::{OwnerConfig, OwnerCryptoKeys, OwnerId, TransportPath};

const INITIAL_FMP_GENERATION: u64 = 1;

struct PacketMover2FmpOwnerSeed {
    owner: OwnerId,
    config: OwnerConfig,
    keys: OwnerCryptoKeys,
    path: TransportPath,
}

impl Node {
    pub(in crate::node) fn sync_packet_mover2_fmp_owner(&mut self, node_addr: &NodeAddr) -> bool {
        let Some(seed) = self.packet_mover2_fmp_owner_seed(node_addr) else {
            self.remove_packet_mover2_fmp_owner(node_addr);
            return false;
        };

        self.packet_mover2.register_owner(seed.owner, seed.config);
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

    fn packet_mover2_owner_in_flight_limit(&self) -> usize {
        self.config.node.limits.max_pending_inbound.max(1)
    }
}
