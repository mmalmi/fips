//! Experimental service accounting for native FIPS forwarding.
//!
//! No delivery receipt is required. Payment verification and durable allowance
//! publication must happen outside the node's synchronous admission loop.

pub mod ledger;
pub mod payment;
