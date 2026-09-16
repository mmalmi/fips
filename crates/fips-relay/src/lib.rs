//! Experimental service accounting for native FIPS forwarding.
//!
//! No delivery receipt is required. Payment verification and durable allowance
//! publication must happen outside the node's synchronous admission loop.

pub mod bootstrap;
pub mod buyer;
pub mod control_transport;
pub mod controller;
#[cfg(unix)]
pub mod customer;
pub mod destination_pricing;
pub mod durable;
pub mod free_routes;
pub mod ledger;
pub mod measurements;
pub mod payment;
pub mod payment_control;
#[cfg(unix)]
pub mod probe;
pub mod return_allowance;
pub mod route_quotes;
#[cfg(unix)]
pub mod service;
#[cfg(all(unix, feature = "testbench"))]
pub mod testbench;
mod unpaid_budget;
#[cfg(unix)]
pub mod wallet_tools;
