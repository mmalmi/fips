//! Runtime-agnostic protocol decision cores.
//!
//! The async node handlers own I/O, logging, metrics, and clocks. Modules here
//! keep deterministic protocol decisions small enough to test without a Tokio
//! runtime or live transports.

pub(crate) mod lookup;
