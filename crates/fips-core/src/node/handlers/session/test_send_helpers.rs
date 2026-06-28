use crate::node::FspSendBookkeepingInput;
#[cfg(unix)]
use crate::node::endpoint_flow_dispatch_key;
use crate::node::session_wire::{build_fsp_header, fsp_prepend_inner_header};
#[cfg(unix)]
use crate::protocol::{LinkMessageType, SESSION_DATAGRAM_HEADER_SIZE};
use crate::protocol::{coords_wire_size, encode_coords};
use crate::upper::icmp::FIPS_OVERHEAD;
use std::borrow::Cow;

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Clone, Copy)]
struct PipelinedEndpointSend<'a> {
    dest_addr: &'a NodeAddr,
    payload: &'a EndpointDataPayload,
    now_ms: u64,
    timestamp: u32,
    fsp_flags: u8,
    body: PipelinedEndpointWireBody<'a>,
    my_coords: Option<&'a crate::tree::TreeCoordinate>,
    dest_coords: Option<&'a crate::tree::TreeCoordinate>,
}

struct PreparedEndpointSessionMeta {
    dest_addr: NodeAddr,
    now_ms: u64,
    timestamp: u32,
    msg_type: u8,
    inner_flags: u8,
    fsp_flags: u8,
    my_coords: Option<crate::tree::TreeCoordinate>,
    dest_coords: Option<crate::tree::TreeCoordinate>,
}

struct PreparedEndpointSessionData<'a> {
    meta: PreparedEndpointSessionMeta,
    payload: &'a EndpointDataPayload,
}

#[derive(Clone, Copy)]
enum PipelinedEndpointWireBody<'a> {
    #[cfg_attr(not(test), allow(dead_code))]
    InnerPlaintext(&'a [u8]),
    EndpointPayload {
        timestamp: u32,
        msg_type: u8,
        inner_flags: u8,
        payload: &'a [u8],
    },
}

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

impl PreparedEndpointSessionMeta {
    fn pipelined<'a>(&'a self, payload: &'a EndpointDataPayload) -> PipelinedEndpointSend<'a> {
        PipelinedEndpointSend {
            dest_addr: &self.dest_addr,
            payload,
            now_ms: self.now_ms,
            timestamp: self.timestamp,
            fsp_flags: self.fsp_flags,
            body: PipelinedEndpointWireBody::EndpointPayload {
                timestamp: self.timestamp,
                msg_type: self.msg_type,
                inner_flags: self.inner_flags,
                payload: payload.as_slice(),
            },
            my_coords: self.my_coords.as_ref(),
            dest_coords: self.dest_coords.as_ref(),
        }
    }

    fn fallback_plan<'a>(&'a self, payload: &'a EndpointDataPayload) -> SessionFspSendPlan<'a> {
        let inner_plaintext = fsp_prepend_inner_header(
            self.timestamp,
            self.msg_type,
            self.inner_flags,
            payload.as_slice(),
        );
        SessionFspSendPlan::new_owned(
            self.dest_addr,
            self.timestamp,
            self.fsp_flags,
            inner_plaintext,
            self.my_coords.as_ref().zip(self.dest_coords.as_ref()),
            SessionFspSendBookkeeping::Data {
                payload_len: payload.len(),
                now_ms: self.now_ms,
            },
        )
    }
}

impl<'a> PreparedEndpointSessionData<'a> {
    fn pipelined(&self) -> PipelinedEndpointSend<'_> {
        self.meta.pipelined(self.payload)
    }

    fn fallback_plan(&self) -> SessionFspSendPlan<'_> {
        self.meta.fallback_plan(self.payload)
    }
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

    fn new_owned(
        dest_addr: NodeAddr,
        timestamp: u32,
        fsp_flags: u8,
        inner_plaintext: Vec<u8>,
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
            Cow::Owned(inner_plaintext),
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
