//! Compatibility facade for the FIPS daemon package.
//!
//! Reusable library code lives in `fips-core`. This crate keeps the historic
//! `fips::...` import path working for binaries and downstream users.

pub use fips_core::*;
