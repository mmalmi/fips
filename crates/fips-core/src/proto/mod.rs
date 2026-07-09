//! Runtime-agnostic protocol cores.
//!
//! The async node handlers own I/O, logging, metrics, and clocks. Modules here
//! keep deterministic protocol decisions small enough to test without a Tokio
//! runtime or live transports.

pub(crate) mod bloom;
pub(crate) mod fsp_wire;
pub(crate) mod lookup;
pub(crate) mod lookup_limits;
pub(crate) mod lookup_state;
pub(crate) mod mmp;
pub(crate) mod protocol;
pub(crate) mod rate_limit;
pub(crate) mod routing;
pub(crate) mod stp;
