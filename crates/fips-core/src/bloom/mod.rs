//! Bloom filter compatibility exports.
//!
//! Runtime-agnostic bloom logic lives under `proto::bloom`; this module keeps
//! the existing public `crate::bloom` path stable.

pub use crate::proto::bloom::*;
