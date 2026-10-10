//! Integration tests for end-to-end Noise IK handshake scenarios.

use super::*;

mod admission;
mod candidates;
mod cleanup_and_resend;
mod cleanup_rekey;
#[cfg(feature = "sim-transport")]
mod control_progress;
mod delayed_startup;
mod early_rekey;
mod epoch_restart;
mod maintenance_progress;
mod rx_loop;
mod same_path_refresh;
mod static_and_cross;
mod udp_two_node;
