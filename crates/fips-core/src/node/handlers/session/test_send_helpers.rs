use crate::node::FspSendBookkeepingInput;
use crate::node::session_wire::{FSP_HEADER_SIZE, build_fsp_header, fsp_prepend_inner_header};
use crate::protocol::{coords_wire_size, encode_coords};
use crate::upper::icmp::FIPS_OVERHEAD;
use std::borrow::Cow;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionFspSendBookkeeping {
    Data { payload_len: usize, now_ms: u64 },
    Control,
}

struct SessionFspSendPlan<'a> {
    dest_addr: NodeAddr,
    timestamp: u32,
    fsp_flags: u8,
    inner_plaintext: Cow<'a, [u8]>,
    coords: Option<(
        &'a crate::tree::TreeCoordinate,
        &'a crate::tree::TreeCoordinate,
    )>,
    bookkeeping: SessionFspSendBookkeeping,
}

struct SealedSessionFspSend {
    dest_addr: NodeAddr,
    timestamp: u32,
    counter: u64,
    ciphertext_len: usize,
    fsp_payload: Vec<u8>,
    bookkeeping: SessionFspSendBookkeeping,
}

impl<'a> SessionFspSendPlan<'a> {
    fn new(
        dest_addr: NodeAddr,
        timestamp: u32,
        fsp_flags: u8,
        inner_plaintext: &'a [u8],
        coords: Option<(
            &'a crate::tree::TreeCoordinate,
            &'a crate::tree::TreeCoordinate,
        )>,
        bookkeeping: SessionFspSendBookkeeping,
    ) -> Self {
        Self::from_inner_plaintext(
            dest_addr,
            timestamp,
            fsp_flags,
            Cow::Borrowed(inner_plaintext),
            coords,
            bookkeeping,
        )
    }

    fn from_inner_plaintext(
        dest_addr: NodeAddr,
        timestamp: u32,
        fsp_flags: u8,
        inner_plaintext: Cow<'a, [u8]>,
        coords: Option<(
            &'a crate::tree::TreeCoordinate,
            &'a crate::tree::TreeCoordinate,
        )>,
        bookkeeping: SessionFspSendBookkeeping,
    ) -> Self {
        let fsp_flags = if coords.is_some() {
            fsp_flags | FSP_FLAG_CP
        } else {
            fsp_flags & !FSP_FLAG_CP
        };
        Self {
            dest_addr,
            timestamp,
            fsp_flags,
            inner_plaintext,
            coords,
            bookkeeping,
        }
    }

    fn dest_addr(&self) -> NodeAddr {
        self.dest_addr
    }

    fn seal(self, session: &mut NoiseSession) -> Result<SealedSessionFspSend, NodeError> {
        let payload_len =
            u16::try_from(self.inner_plaintext.len()).map_err(|_| NodeError::SendFailed {
                node_addr: self.dest_addr,
                reason: "session FSP payload too large".into(),
            })?;
        let counter = session.current_send_counter();
        let header = build_fsp_header(counter, self.fsp_flags, payload_len);
        let ciphertext = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::FspEncrypt);
            session
                .encrypt_with_aad(self.inner_plaintext.as_ref(), &header)
                .map_err(|e| NodeError::SendFailed {
                    node_addr: self.dest_addr,
                    reason: format!("session encrypt failed: {}", e),
                })?
        };

        let coords_size = self
            .coords
            .as_ref()
            .map(|(src, dst)| coords_wire_size(src) + coords_wire_size(dst))
            .unwrap_or(0);
        let mut fsp_payload = Vec::with_capacity(FSP_HEADER_SIZE + coords_size + ciphertext.len());
        fsp_payload.extend_from_slice(&header);
        if let Some((src, dst)) = self.coords {
            encode_coords(src, &mut fsp_payload);
            encode_coords(dst, &mut fsp_payload);
        }
        fsp_payload.extend_from_slice(&ciphertext);

        Ok(SealedSessionFspSend {
            dest_addr: self.dest_addr,
            timestamp: self.timestamp,
            counter,
            ciphertext_len: ciphertext.len(),
            fsp_payload,
            bookkeeping: self.bookkeeping,
        })
    }
}
