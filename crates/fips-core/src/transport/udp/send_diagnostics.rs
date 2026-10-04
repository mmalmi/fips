use super::{SocketAddr, TransportError};
use crate::dataplane::FmpWireHeader;

/// Opt-in kernel submission evidence, not a delivery receipt. Both scalar
/// send paths use the same public header fields; ciphertext is never logged.
pub(super) fn record(
    data: &[u8],
    local_addr: SocketAddr,
    remote_addr: SocketAddr,
    result: &Result<usize, TransportError>,
) {
    // Direct FSP shares FMP's version/phase but has a different header.
    if tracing::enabled!(target: "fips_udp_send", tracing::Level::TRACE)
        && let Ok(header) = FmpWireHeader::parse_encrypted(data)
        && header.flags() & crate::node::session_wire::FSP_FLAG_DIRECT_TRANSPORT == 0
    {
        let outcome = if result.is_ok() {
            "kernel_accepted"
        } else {
            "failed"
        };
        let accepted_bytes = result.as_ref().copied().unwrap_or(0);
        tracing::trace!(target: "fips_udp_send", event = "send_result",
            receiver_idx = header.receiver_idx(), flags = header.flags(),
            counter = header.counter(), wire_bytes = data.len(),
            %local_addr, %remote_addr, outcome, accepted_bytes,
            error = ?result.as_ref().err(), "UDP established FMP send result");
    }
}
