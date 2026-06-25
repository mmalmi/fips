//! RX event loop and message handlers.

mod connected_udp;
pub(crate) mod discovery;
mod dispatch;
mod encrypted;
mod forwarding;
mod handshake;
mod mmp;
mod rekey;
mod rx_loop;
pub(in crate::node) mod session;
mod timeout;

#[cfg(test)]
pub(in crate::node) use encrypted::EncryptedFrameFastPath;
#[cfg(test)]
pub(in crate::node) use mmp::traversal_path_liveness_timeout;
#[cfg(test)]
pub(in crate::node) use mmp::traversal_path_quiet_refresh_timeout;
