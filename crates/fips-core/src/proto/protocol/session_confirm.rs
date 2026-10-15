//! Fixed, payload-free proof that the responder installed a rekey epoch.
use crate::{
    noise::{self, NoiseSession},
    proto::fsp_wire::{FSP_HEADER_SIZE, FSP_PHASE_CONFIRM},
};

const CONFIRM_BYTES: usize = FSP_HEADER_SIZE + noise::TAG_SIZE;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SessionConfirm([u8; CONFIRM_BYTES]);

impl SessionConfirm {
    /// Reserve the first nonce before exposing the fresh epoch to the dataplane.
    /// Retries reuse these exact bytes, leaving no holes in MMP's counter stream.
    pub(crate) fn for_fresh_session(session: &NoiseSession) -> Option<Self> {
        let counter = session.take_send_counter().ok()?;
        if counter != 0 {
            return None;
        }
        let mut bytes = [0; CONFIRM_BYTES];
        bytes[0] = FSP_PHASE_CONFIRM;
        let tag = noise::seal(
            session.send_cipher_clone().as_ref(),
            counter,
            &bytes[..FSP_HEADER_SIZE],
            &[],
        )
        .ok()?;
        bytes[FSP_HEADER_SIZE..].copy_from_slice(&tag);
        Some(Self(bytes))
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let bytes: [u8; CONFIRM_BYTES] = bytes.try_into().ok()?;
        (bytes[0] == FSP_PHASE_CONFIRM && bytes[1..FSP_HEADER_SIZE] == [0; FSP_HEADER_SIZE - 1])
            .then_some(Self(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
