use crate::NodeAddr;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct SessionRekeyTickPlan {
    pub(super) probe: Vec<NodeAddr>,
    pub(super) drain: Vec<NodeAddr>,
    pub(super) initiate: Vec<NodeAddr>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SessionRekeyTickConfig {
    pub(super) initiate_enabled: bool,
    pub(super) now_ms: u64,
    pub(super) rekey_after_secs: u64,
    pub(super) rekey_after_messages: u64,
    pub(super) drain_ms: u64,
    pub(super) dampening_ms: u64,
    pub(super) probe_delay_ms: u64,
    pub(super) probe_interval_ms: u64,
}
