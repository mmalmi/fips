//! Protocol compatibility exports.
//!
//! Runtime-agnostic wire codecs live under `proto::protocol`; this module keeps
//! the existing public `crate::protocol` path stable.

pub use crate::proto::protocol::*;

pub(crate) use crate::proto::protocol::{coords_wire_size, encode_coords};
