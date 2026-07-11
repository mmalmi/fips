//! UDP socket wrapper with platform-specific receive implementations.
//!
//! On Linux, provides `SO_RXQ_OVFL` kernel drop counter support and
//! `UDP_GRO` receive segment-size metadata via `recvmsg()` ancillary
//! data parsing. The async wrapper uses
//! `tokio::io::unix::AsyncFd` for integration with the tokio runtime.
//!
//! On macOS, uses the same `recvmsg()` path but without `SO_RXQ_OVFL`
//! (kernel drop counting is not available; the drops field returns 0).
//!
//! On Windows, uses `tokio::net::UdpSocket` directly (kernel drop
//! counting is not available; the drops field always returns 0).
//!
//! Follows the pattern established by `transport/ethernet/socket.rs`.

use crate::transport::TransportError;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
#[cfg(unix)]
use tracing::warn;

/// Maximum number of datagrams a single `recvmmsg` syscall pulls from the
/// kernel queue. Shared with the higher-level UDP receive loops so all Linux
/// packet ingress paths use the same batch width.
#[cfg(any(target_os = "linux", target_os = "macos"))]
const RECV_BATCH_SIZE: usize = super::UDP_RECV_BATCH_SIZE;

// ============================================================================
// Unix implementation
// ============================================================================

#[cfg(unix)]
mod platform {
    include!("socket_unix_types.rs");
    include!("socket_unix_raw.rs");
    include!("socket_unix_io.rs");
}

include!("socket_windows.rs");
