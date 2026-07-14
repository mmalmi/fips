//! Low-priority FIPS datagrams carried by targeted ephemeral Nostr events.
//!
//! This transport never selects or connects to relays. It signs outbound
//! events and accepts verified inbound events; an embedding adapter owns the
//! configured relay connections and route affinity.

use std::collections::VecDeque;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use nostr::prelude::{Event, EventBuilder, Kind, PublicKey, Tag, Timestamp};

use crate::config::NostrRelayConfig;
use crate::{Identity, Transport};

use super::{
    DiscoveredPeer, PacketBuffer, PacketTx, ReceivedPacket, TransportAddr, TransportError,
    TransportId, TransportState, TransportType,
};

/// Custom ephemeral event carrying one encrypted FIPS wire datagram.
pub const NOSTR_RELAY_DATAGRAM_KIND: u16 = 21_060;

/// Old relay delivery is useless to a live datagram transport and can replay
/// handshake work. This is deliberately independent of relay storage policy.
const MAX_EVENT_AGE_SECS: u64 = 60;
const MAX_FUTURE_SKEW_SECS: u64 = 30;

pub struct NostrRelayTransport {
    id: TransportId,
    name: Option<String>,
    config: NostrRelayConfig,
    state: TransportState,
    packet_tx: PacketTx,
    keys: nostr::Keys,
    local_pubkey: PublicKey,
    outbound: Mutex<VecDeque<Event>>,
}

impl NostrRelayTransport {
    pub fn new(
        id: TransportId,
        name: Option<String>,
        config: NostrRelayConfig,
        packet_tx: PacketTx,
        identity: &Identity,
    ) -> Result<Self, TransportError> {
        let keys = nostr::Keys::parse(&hex::encode(identity.keypair().secret_bytes()))
            .map_err(|error| TransportError::StartFailed(error.to_string()))?;
        let local_pubkey = keys.public_key();
        Ok(Self {
            id,
            name,
            config,
            state: TransportState::Configured,
            packet_tx,
            keys,
            local_pubkey,
            outbound: Mutex::new(VecDeque::new()),
        })
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn drain_outbound_events(&self, limit: usize) -> Vec<Event> {
        let mut outbound = self
            .outbound
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let count = limit.min(outbound.len());
        outbound.drain(..count).collect()
    }

    pub fn ingest_event(&self, event: Event) -> Result<bool, TransportError> {
        if event.kind != Kind::Custom(NOSTR_RELAY_DATAGRAM_KIND) {
            return Ok(false);
        }
        event
            .verify()
            .map_err(|error| TransportError::RecvFailed(error.to_string()))?;
        let mut recipients = event.tags.public_keys();
        if recipients.next() != Some(&self.local_pubkey) || recipients.next().is_some() {
            return Ok(false);
        }
        let now = Timestamp::now().as_secs();
        let created_at = event.created_at.as_secs();
        if created_at > now.saturating_add(MAX_FUTURE_SKEW_SECS)
            || now.saturating_sub(created_at) > MAX_EVENT_AGE_SECS
        {
            return Ok(false);
        }
        let max_encoded_len = usize::from(self.config.mtu()).div_ceil(3) * 4;
        if event.content.len() > max_encoded_len {
            return Ok(false);
        }
        let data = URL_SAFE_NO_PAD
            .decode(&event.content)
            .map_err(|error| TransportError::RecvFailed(error.to_string()))?;
        if data.is_empty() || data.len() > usize::from(self.config.mtu()) {
            return Ok(false);
        }
        let packet = ReceivedPacket::with_timestamp(
            self.id,
            TransportAddr::from(event.pubkey.to_hex()),
            PacketBuffer::new(data),
            crate::time::now_ms(),
        );
        self.packet_tx
            .send(packet)
            .map_err(|_| TransportError::RecvFailed("FIPS packet receiver closed".to_string()))?;
        Ok(true)
    }

    fn destination(addr: &TransportAddr) -> Result<PublicKey, TransportError> {
        let value = addr
            .as_str()
            .ok_or_else(|| TransportError::InvalidAddress(addr.to_string()))?;
        PublicKey::parse(value).map_err(|error| TransportError::InvalidAddress(error.to_string()))
    }
}

impl Transport for NostrRelayTransport {
    fn transport_id(&self) -> TransportId {
        self.id
    }

    fn transport_type(&self) -> &TransportType {
        &TransportType::NOSTR_RELAY
    }

    fn state(&self) -> TransportState {
        self.state
    }

    fn mtu(&self) -> u16 {
        self.config.mtu()
    }

    fn start(&mut self) -> Result<(), TransportError> {
        if !self.state.can_start() {
            return Err(TransportError::AlreadyStarted);
        }
        self.state = TransportState::Up;
        Ok(())
    }

    fn stop(&mut self) -> Result<(), TransportError> {
        self.state = TransportState::Down;
        Ok(())
    }

    fn send(&self, addr: &TransportAddr, data: &[u8]) -> Result<(), TransportError> {
        if self.state != TransportState::Up {
            return Err(TransportError::NotStarted);
        }
        if data.len() > usize::from(self.config.mtu()) {
            return Err(TransportError::MtuExceeded {
                packet_size: data.len(),
                mtu: self.config.mtu(),
            });
        }
        let destination = Self::destination(addr)?;
        let event = EventBuilder::new(
            Kind::Custom(NOSTR_RELAY_DATAGRAM_KIND),
            URL_SAFE_NO_PAD.encode(data),
        )
        .tag(Tag::public_key(destination))
        .sign_with_keys(&self.keys)
        .map_err(|error| TransportError::SendFailed(error.to_string()))?;
        let mut outbound = self
            .outbound
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if outbound.len() >= self.config.max_pending_events() {
            return Err(TransportError::SendFailed(
                "Nostr relay event queue is full".to_string(),
            ));
        }
        outbound.push_back(event);
        Ok(())
    }

    fn discover(&self) -> Result<Vec<DiscoveredPeer>, TransportError> {
        Ok(Vec::new())
    }

    fn auto_connect(&self) -> bool {
        self.config.auto_connect()
    }

    fn accept_connections(&self) -> bool {
        self.config.accept_connections()
    }
}
