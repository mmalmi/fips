//! Spanning-tree compatibility exports.
//!
//! Runtime-agnostic spanning-tree state lives under `proto::stp`; this module
//! keeps the existing public `crate::tree` path stable.

pub use crate::proto::stp::*;
