//! Integration tests for end-to-end Noise IK handshake scenarios.

use super::*;

mod admission;
mod cleanup_and_resend;
mod cleanup_rekey;
mod early_rekey;
mod epoch_restart;
mod maintenance_progress;
mod rx_loop;
mod static_and_cross;
mod udp_two_node;
