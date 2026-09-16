//! Strict structural classification for a bounded session-bootstrap allowance.
//! This does not verify Noise or authenticate either end-to-end address.
use super::{SessionAck, SessionMsg3, SessionSetup};
use crate::{
    NodeAddr,
    noise::{XK_HANDSHAKE_MSG1_SIZE, XK_HANDSHAKE_MSG2_SIZE, XK_HANDSHAKE_MSG3_SIZE},
    proto::fsp_wire::{FSP_COMMON_PREFIX_SIZE, FSP_PHASE_MSG1, FSP_PHASE_MSG2, FSP_PHASE_MSG3},
};

/// A local bootstrap classification ceiling, not a general FSP wire size limit.
pub const MAX_BOOTSTRAP_HANDSHAKE_BYTES: usize = 2_048;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SessionHandshake {
    Setup,
    Ack,
    Finish,
}

impl SessionHandshake {
    /// Recognize only current canonical handshake envelopes with fixed Noise
    /// payload sizes and matching cleartext addresses. Established data, errors,
    /// unknown flags/versions, padding and oversized handshakes return None.
    /// Callers must separately bound authenticated-neighbor and aggregate work:
    /// a structurally valid envelope can still contain an invalid Noise message.
    pub fn classify(payload: &[u8], source: NodeAddr, destination: NodeAddr) -> Option<Self> {
        if !(FSP_COMMON_PREFIX_SIZE..=MAX_BOOTSTRAP_HANDSHAKE_BYTES).contains(&payload.len()) {
            return None;
        }
        let body = &payload[FSP_COMMON_PREFIX_SIZE..];
        match payload[0] {
            FSP_PHASE_MSG1 => {
                let message = SessionSetup::decode(body).ok()?;
                (message.handshake_payload.len() == XK_HANDSHAKE_MSG1_SIZE
                    && message.src_coords.node_addr() == &source
                    && message.dest_coords.node_addr() == &destination
                    && message.encode() == payload)
                    .then_some(Self::Setup)
            }
            FSP_PHASE_MSG2 => {
                let message = SessionAck::decode(body).ok()?;
                (message.handshake_payload.len() == XK_HANDSHAKE_MSG2_SIZE
                    && message.flags & !0x04 == 0
                    && message.src_coords.node_addr() == &source
                    && message.dest_coords.node_addr() == &destination
                    && message.encode() == payload)
                    .then_some(Self::Ack)
            }
            FSP_PHASE_MSG3 => {
                let message = SessionMsg3::decode(body).ok()?;
                (message.handshake_payload.len() == XK_HANDSHAKE_MSG3_SIZE
                    && message.flags == 0
                    && message.encode() == payload)
                    .then_some(Self::Finish)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::TreeCoordinate;

    #[test]
    fn only_exact_bounded_handshake_shapes_are_classified() {
        let source = NodeAddr::from_bytes([1; 16]);
        let destination = NodeAddr::from_bytes([2; 16]);
        let setup = SessionSetup::new(
            TreeCoordinate::root(source),
            TreeCoordinate::root(destination),
        )
        .with_handshake(vec![0; XK_HANDSHAKE_MSG1_SIZE])
        .encode();
        let ack = SessionAck::new(
            TreeCoordinate::root(source),
            TreeCoordinate::root(destination),
        )
        .with_handshake(vec![0; XK_HANDSHAKE_MSG2_SIZE])
        .with_direct_fsp_transport()
        .encode();
        let finish = SessionMsg3::new(vec![0; XK_HANDSHAKE_MSG3_SIZE]).encode();
        for (packet, phase) in [
            (setup, SessionHandshake::Setup),
            (ack, SessionHandshake::Ack),
            (finish, SessionHandshake::Finish),
        ] {
            assert_eq!(
                SessionHandshake::classify(&packet, source, destination),
                Some(phase)
            );
            for index in [0, 1, 2, 3, 4] {
                let mut changed = packet.clone();
                changed[index] ^= 0x80;
                assert_eq!(
                    SessionHandshake::classify(&changed, source, destination),
                    None
                );
            }
            for end in 0..packet.len() {
                assert_eq!(
                    SessionHandshake::classify(&packet[..end], source, destination),
                    None
                );
            }
            let mut padded = packet.clone();
            padded.push(0);
            assert_eq!(
                SessionHandshake::classify(&padded, source, destination),
                None
            );
            // Adjusting the declared length must not make a trailing body free.
            let body_len = (padded.len() - 4) as u16;
            padded[2..4].copy_from_slice(&body_len.to_le_bytes());
            assert_eq!(
                SessionHandshake::classify(&padded, source, destination),
                None
            );
            if phase != SessionHandshake::Finish {
                assert_eq!(
                    SessionHandshake::classify(&packet, destination, source),
                    None
                );
            }
        }
        for len in [
            XK_HANDSHAKE_MSG3_SIZE - 1,
            XK_HANDSHAKE_MSG3_SIZE + 1,
            4_096,
        ] {
            assert_eq!(
                SessionHandshake::classify(
                    &SessionMsg3::new(vec![0; len]).encode(),
                    source,
                    destination
                ),
                None
            );
        }
    }
}
