//! One readiness heartbeat, using the pending connection's eventual FMP session.

use super::{HandshakeState, NoiseError, PeerConnection};
use crate::dataplane::build_fmp_established_header;
use crate::mmp::SenderState;
use crate::protocol::LinkMessageType;
use std::time::Instant;

pub(super) struct PendingReadyHeartbeat {
    wire: Vec<u8>,
    origin: Instant,
    counter: u64,
    timestamp_ms: u32,
    sender: SenderState,
    recorded: bool,
}

impl PeerConnection {
    /// Prepare once with the actual Noise nonce authority; retries reuse exact wire.
    /// This grants no active-peer or forwarding authority and renews no deadline.
    pub(crate) fn prepare_ready_heartbeat(&mut self) -> Result<&[u8], NoiseError> {
        if !self.is_outbound() || self.handshake_state != HandshakeState::Complete {
            return Err(NoiseError::WrongState {
                expected: "complete outbound connection".to_string(),
                got: format!("{:?} {}", self.direction, self.handshake_state),
            });
        }
        let their_index = self.their_index.ok_or_else(|| NoiseError::WrongState {
            expected: "remote receiver index".to_string(),
            got: "missing index".to_string(),
        })?;
        let session = self
            .noise_session
            .as_mut()
            .ok_or(NoiseError::HandshakeNotComplete)?;
        if self.ready_heartbeat.is_none() {
            let origin = Instant::now();
            let timestamp_ms = origin.elapsed().as_millis() as u32;
            let mut plaintext = [0u8; 5];
            plaintext[..4].copy_from_slice(&timestamp_ms.to_le_bytes());
            plaintext[4] = LinkMessageType::Heartbeat.to_byte();
            let counter = session.current_send_counter();
            let header = build_fmp_established_header(their_index.as_u32(), counter, 0, 5);
            let ciphertext = session.encrypt_with_aad(&plaintext, &header)?;
            let mut wire = Vec::with_capacity(header.len() + ciphertext.len());
            wire.extend_from_slice(&header);
            wire.extend_from_slice(&ciphertext);
            self.ready_heartbeat = Some(PendingReadyHeartbeat {
                wire,
                origin,
                counter,
                timestamp_ms,
                sender: SenderState::new(),
                recorded: false,
            });
        }
        Ok(&self.ready_heartbeat.as_ref().expect("prepared above").wire)
    }

    /// Record a complete successful transport write of the cached frame.
    /// Retries consume link bytes, but replayed nonces are not new MMP frames.
    pub(crate) fn record_ready_heartbeat_sent(&mut self, bytes: usize) -> bool {
        let Some(ready) = self.ready_heartbeat.as_mut() else {
            return false;
        };
        if bytes != ready.wire.len() {
            return false;
        }
        self.link_stats.record_sent(bytes);
        if !ready.recorded {
            ready
                .sender
                .record_sent(ready.counter, ready.timestamp_ms, bytes);
            ready.recorded = true;
        }
        true
    }

    /// Move accounting only when this exact session wins promotion. Install it
    /// synchronously before bootstrap, together with the retained wire origin.
    pub(crate) fn take_ready_heartbeat_accounting(&mut self) -> Option<(Instant, SenderState)> {
        self.ready_heartbeat
            .take()
            .map(|ready| (ready.origin, ready.sender))
    }
}

#[cfg(test)]
mod tests;
