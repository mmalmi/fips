//! FSP wire compatibility exports for node call sites.
//!
//! Runtime-agnostic FSP parsing lives under `proto::fsp_wire`; this module
//! keeps existing `crate::node::session_wire` paths stable during the split.

pub(crate) use crate::proto::fsp_wire::*;
