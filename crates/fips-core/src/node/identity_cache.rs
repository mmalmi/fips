use super::*;

/// Source-attributed packet delivered by a node running without a system TUN.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeDeliveredPacket {
    /// FIPS node address that originated the packet.
    pub source_node_addr: NodeAddr,
    /// Source Nostr public key when the node has learned it.
    pub source_npub: Option<String>,
    /// Destination FIPS address from the IPv6 packet.
    pub destination: FipsAddress,
    /// Full IPv6 packet after FIPS session decapsulation.
    pub packet: Vec<u8>,
}

#[derive(Debug, Clone)]
struct IdentityCacheEntry {
    node_addr: NodeAddr,
    pubkey: secp256k1::PublicKey,
    npub: String,
    last_seen_ms: u64,
    dns_resolved: bool,
}

impl IdentityCacheEntry {
    fn new(
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
        npub: String,
        last_seen_ms: u64,
        dns_resolved: bool,
    ) -> Self {
        Self {
            node_addr,
            pubkey,
            npub,
            last_seen_ms,
            dns_resolved,
        }
    }
}

/// Prefix-indexed identity cache for FipsAddress/NodeAddr lookup.
#[derive(Debug, Default)]
pub(in crate::node) struct IdentityCache {
    entries: HashMap<[u8; 15], IdentityCacheEntry>,
}

impl IdentityCache {
    pub(in crate::node) fn prefix_for(node_addr: &NodeAddr) -> [u8; 15] {
        let mut prefix = [0u8; 15];
        prefix.copy_from_slice(&node_addr.as_bytes()[0..15]);
        prefix
    }

    pub(in crate::node) fn register(
        &mut self,
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
        now_ms: u64,
        max_entries: usize,
    ) -> bool {
        self.register_inner(node_addr, pubkey, now_ms, max_entries, false)
    }

    pub(in crate::node) fn register_dns_resolved(
        &mut self,
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
        now_ms: u64,
        max_entries: usize,
    ) -> bool {
        self.register_inner(node_addr, pubkey, now_ms, max_entries, true)
    }

    fn register_inner(
        &mut self,
        node_addr: NodeAddr,
        pubkey: secp256k1::PublicKey,
        now_ms: u64,
        max_entries: usize,
        dns_resolved: bool,
    ) -> bool {
        let prefix = Self::prefix_for(&node_addr);
        if let Some(entry) = self.entries.get_mut(&prefix)
            && entry.node_addr == node_addr
            && entry.pubkey == pubkey
        {
            entry.last_seen_ms = now_ms;
            entry.dns_resolved |= dns_resolved;
            return true;
        }

        let (xonly, _) = pubkey.x_only_public_key();
        let derived_node_addr = NodeAddr::from_pubkey(&xonly);
        if derived_node_addr != node_addr {
            debug!(
                claimed_node_addr = %node_addr,
                derived_node_addr = %derived_node_addr,
                "Rejected identity cache entry with mismatched public key"
            );
            return false;
        }

        if let Some(entry) = self.entries.get_mut(&prefix)
            && entry.node_addr == node_addr
        {
            entry.pubkey = pubkey;
            entry.last_seen_ms = now_ms;
            entry.dns_resolved |= dns_resolved;
            return true;
        }

        let npub = encode_npub(&xonly);
        self.entries.insert(
            prefix,
            IdentityCacheEntry::new(node_addr, pubkey, npub, now_ms, dns_resolved),
        );
        self.evict_lru(max_entries);
        true
    }

    pub(in crate::node) fn lookup_by_prefix(
        &mut self,
        prefix: &[u8; 15],
        now_ms: u64,
    ) -> Option<(NodeAddr, secp256k1::PublicKey)> {
        let entry = self.entries.get_mut(prefix)?;
        entry.last_seen_ms = now_ms;
        Some((entry.node_addr, entry.pubkey))
    }

    pub(in crate::node) fn has_prefix_for(&self, node_addr: &NodeAddr) -> bool {
        self.entries.contains_key(&Self::prefix_for(node_addr))
    }

    pub(in crate::node) fn is_dns_resolved(&self, node_addr: &NodeAddr) -> bool {
        self.entries
            .get(&Self::prefix_for(node_addr))
            .is_some_and(|entry| entry.node_addr == *node_addr && entry.dns_resolved)
    }

    pub(in crate::node) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(in crate::node) fn iter(
        &self,
    ) -> impl Iterator<Item = (&NodeAddr, &secp256k1::PublicKey, u64)> {
        self.entries
            .values()
            .map(|entry| (&entry.node_addr, &entry.pubkey, entry.last_seen_ms))
    }

    pub(in crate::node) fn pubkey_for_node_addr(
        &self,
        addr: &NodeAddr,
    ) -> Option<secp256k1::PublicKey> {
        self.entries
            .get(&Self::prefix_for(addr))
            .filter(|entry| &entry.node_addr == addr)
            .map(|entry| entry.pubkey)
    }

    pub(in crate::node) fn npub_for_node_addr(&self, addr: &NodeAddr) -> Option<String> {
        self.entries
            .get(&Self::prefix_for(addr))
            .filter(|entry| &entry.node_addr == addr)
            .map(|entry| entry.npub.clone())
    }

    fn evict_lru(&mut self, max_entries: usize) {
        if self.entries.len() > max_entries
            && let Some(oldest_key) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_seen_ms)
                .map(|(key, _)| *key)
        {
            self.entries.remove(&oldest_key);
        }
    }
}
