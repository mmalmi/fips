/// Keep the post-cutover stale-epoch FMP drain window open for this long.
pub(in crate::node) const FMP_DRAIN_WINDOW_SECS: u64 = 10;

/// Keep the post-cutover stale-epoch FSP drain window open long enough for
/// delayed direct-lane packet bursts to clear after explicit rekey tests.
pub(in crate::node) const FSP_DRAIN_WINDOW_SECS: u64 = 45;

/// Suppress local rekey initiation for this long after receiving a peer's
/// rekey msg1.
pub(in crate::node) const REKEY_DAMPENING_SECS: u64 = 30;

/// Delay FMP initiator cutover after receiving msg2. The responder keeps the
/// pending session until it authenticates the peer's K-bit flip.
pub(in crate::node) const FMP_CUTOVER_DELAY_MS: u64 = 250;

/// Give the initial FSP msg3 and its first retry time to reach the responder
/// before probing the pending epoch. Application traffic stays on the proven
/// epoch until authenticated pending-epoch traffic comes back.
pub(in crate::node) const FSP_PENDING_EPOCH_PROBE_DELAY_MS: u64 = 2_000;
pub(in crate::node) const FSP_PENDING_EPOCH_PROBE_INTERVAL_MS: u64 = 1_000;
