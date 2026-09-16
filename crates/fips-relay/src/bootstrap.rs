//! Strict handshake classification and its public diagnostics.
pub use crate::unpaid_budget::UnpaidStats as BootstrapStats;
use fips_core::{NodeAddr, protocol::SessionHandshake};

pub(crate) fn is_handshake(payload: &[u8], source: NodeAddr, destination: NodeAddr) -> bool {
    SessionHandshake::classify(payload, source, destination).is_some()
}
