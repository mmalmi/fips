use super::{MAX_WEBRTC_CANDIDATE_LENGTH, TransportError, debug};
use crate::config::{
    MAX_WEBRTC_HOST_CANDIDATE_SOCKETS, MAX_WEBRTC_LOCAL_CANDIDATE_LINES,
    MAX_WEBRTC_LOCAL_CANDIDATE_ROUTES, MAX_WEBRTC_REMOTE_CANDIDATE_LINES,
    MAX_WEBRTC_REMOTE_CANDIDATE_ROUTES,
};
use ::webrtc::api::APIBuilder;
use ::webrtc::api::media_engine::MediaEngine;
use ::webrtc::api::setting_engine::SettingEngine;
use ::webrtc::ice::candidate::Candidate;
use ::webrtc::ice::candidate::candidate_base::unmarshal_candidate;
use ::webrtc::ice::mdns::MulticastDnsMode;
use ::webrtc::ice::network_type::NetworkType;
use if_addrs::IfOperStatus;
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

#[derive(Clone)]
pub(super) struct CandidateAddressPolicy {
    source: CandidateAddressSource,
    profile: CandidateNetworkProfile,
}

#[derive(Clone)]
enum CandidateAddressSource {
    System,
    #[cfg(test)]
    Snapshot(Vec<LocalCandidateAddress>),
    #[cfg(test)]
    Fixed(Vec<IpAddr>),
}

#[derive(Clone, Copy)]
enum CandidateNetworkProfile {
    Production,
    #[cfg(test)]
    LoopbackUdp4,
}

#[derive(Clone, Debug)]
struct LocalCandidateAddress {
    interface: String,
    index: Option<u32>,
    ip: IpAddr,
    is_p2p: bool,
    oper_status: IfOperStatus,
}

impl CandidateAddressPolicy {
    pub(super) fn system() -> Self {
        Self {
            source: CandidateAddressSource::System,
            profile: CandidateNetworkProfile::Production,
        }
    }

    #[cfg(test)]
    pub(super) fn loopback_udp4() -> Self {
        Self {
            source: CandidateAddressSource::Fixed(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
            profile: CandidateNetworkProfile::LoopbackUdp4,
        }
    }

    #[cfg(test)]
    pub(super) fn from_test_snapshot(
        addresses: impl IntoIterator<Item = (String, IpAddr, bool, u32)>,
    ) -> Self {
        Self {
            source: CandidateAddressSource::Snapshot(
                addresses
                    .into_iter()
                    .map(|(interface, ip, is_p2p, index)| LocalCandidateAddress {
                        interface,
                        index: Some(index),
                        ip,
                        is_p2p,
                        oper_status: IfOperStatus::Up,
                    })
                    .collect(),
            ),
            profile: CandidateNetworkProfile::Production,
        }
    }

    #[cfg(test)]
    pub(super) fn from_test_status_snapshot(
        addresses: impl IntoIterator<Item = (String, IpAddr, bool, u32, IfOperStatus)>,
    ) -> Self {
        Self {
            source: CandidateAddressSource::Snapshot(
                addresses
                    .into_iter()
                    .map(
                        |(interface, ip, is_p2p, index, oper_status)| LocalCandidateAddress {
                            interface,
                            index: Some(index),
                            ip,
                            is_p2p,
                            oper_status,
                        },
                    )
                    .collect(),
            ),
            profile: CandidateNetworkProfile::Production,
        }
    }

    pub(super) fn build_api(&self) -> Result<Arc<::webrtc::api::API>, TransportError> {
        self.build_api_inner(None)
    }

    #[cfg(test)]
    pub(super) fn build_api_with_vnet(
        &self,
        vnet: Arc<::webrtc::util::vnet::net::Net>,
    ) -> Result<Arc<::webrtc::api::API>, TransportError> {
        self.build_api_inner(Some(vnet))
    }

    #[cfg(test)]
    pub(super) fn selected_ips_for_test(&self) -> Result<Vec<IpAddr>, TransportError> {
        self.selected_ips()
    }

    fn build_api_inner(
        &self,
        vnet: Option<Arc<::webrtc::util::vnet::net::Net>>,
    ) -> Result<Arc<::webrtc::api::API>, TransportError> {
        let selected = self.selected_ips()?;
        debug!(
            selected_candidate_addresses = selected.len(),
            max_candidate_addresses = MAX_WEBRTC_HOST_CANDIDATE_SOCKETS,
            "built immutable WebRTC candidate-address generation"
        );
        let allowed: HashSet<_> = selected.into_iter().collect();
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|error| TransportError::StartFailed(error.to_string()))?;
        let mut setting_engine = SettingEngine::default();
        setting_engine.set_ice_multicast_dns_mode(MulticastDnsMode::Disabled);
        setting_engine.set_ip_filter(Box::new(move |ip| allowed.contains(&ip)));
        match self.profile {
            CandidateNetworkProfile::Production => {
                setting_engine.set_network_types(vec![NetworkType::Udp4, NetworkType::Udp6]);
            }
            #[cfg(test)]
            CandidateNetworkProfile::LoopbackUdp4 => {
                setting_engine.set_include_loopback_candidate(true);
                setting_engine.set_network_types(vec![NetworkType::Udp4]);
            }
        }
        if let Some(vnet) = vnet {
            setting_engine.set_vnet(Some(vnet));
        }
        Ok(Arc::new(
            APIBuilder::new()
                .with_media_engine(media_engine)
                .with_setting_engine(setting_engine)
                .build(),
        ))
    }

    fn selected_ips(&self) -> Result<Vec<IpAddr>, TransportError> {
        match &self.source {
            CandidateAddressSource::System => {
                let addresses = if_addrs::get_if_addrs()
                    .map_err(|error| TransportError::StartFailed(error.to_string()))?
                    .into_iter()
                    .map(|interface| LocalCandidateAddress {
                        ip: interface.ip(),
                        is_p2p: interface.is_p2p(),
                        oper_status: interface.oper_status,
                        interface: interface.name,
                        index: interface.index,
                    })
                    .collect();
                Ok(select_candidate_addresses(addresses))
            }
            #[cfg(test)]
            CandidateAddressSource::Snapshot(addresses) => {
                Ok(select_candidate_addresses(addresses.clone()))
            }
            #[cfg(test)]
            CandidateAddressSource::Fixed(addresses) => Ok(addresses.clone()),
        }
    }
}

fn select_candidate_addresses(addresses: Vec<LocalCandidateAddress>) -> Vec<IpAddr> {
    let mut per_interface_family: HashMap<(String, bool), LocalCandidateAddress> = HashMap::new();
    for candidate in addresses.into_iter().filter(is_usable_candidate) {
        let key = (candidate.interface.clone(), candidate.ip.is_ipv6());
        match per_interface_family.get_mut(&key) {
            Some(existing) if local_address_cmp(&candidate, existing) == Ordering::Less => {
                *existing = candidate;
            }
            None => {
                per_interface_family.insert(key, candidate);
            }
            _ => {}
        }
    }
    let mut representatives: Vec<_> = per_interface_family.into_values().collect();
    representatives.sort_by(local_address_cmp);

    let mut selected = Vec::with_capacity(MAX_WEBRTC_HOST_CANDIDATE_SOCKETS);
    let mut selected_ips = HashSet::new();
    take_matching(
        &representatives,
        &mut selected,
        &mut selected_ips,
        1,
        |item| !item.is_p2p && item.ip.is_ipv4(),
    );
    take_matching(
        &representatives,
        &mut selected,
        &mut selected_ips,
        1,
        |item| !item.is_p2p && item.ip.is_ipv6(),
    );
    take_matching(
        &representatives,
        &mut selected,
        &mut selected_ips,
        1,
        |item| item.is_p2p && item.ip.is_ipv4(),
    );
    take_matching(
        &representatives,
        &mut selected,
        &mut selected_ips,
        1,
        |item| item.is_p2p && item.ip.is_ipv6(),
    );
    let remaining = MAX_WEBRTC_HOST_CANDIDATE_SOCKETS.saturating_sub(selected.len());
    take_matching(
        &representatives,
        &mut selected,
        &mut selected_ips,
        remaining,
        |_| true,
    );
    debug_assert!(selected.len() <= MAX_WEBRTC_HOST_CANDIDATE_SOCKETS);
    selected
}

fn take_matching(
    candidates: &[LocalCandidateAddress],
    selected: &mut Vec<IpAddr>,
    selected_ips: &mut HashSet<IpAddr>,
    limit: usize,
    predicate: impl Fn(&LocalCandidateAddress) -> bool,
) {
    let mut taken = 0usize;
    for candidate in candidates {
        if selected.len() >= MAX_WEBRTC_HOST_CANDIDATE_SOCKETS || taken >= limit {
            return;
        }
        if predicate(candidate) && selected_ips.insert(candidate.ip) {
            selected.push(candidate.ip);
            taken += 1;
        }
    }
}

fn is_usable_candidate(candidate: &LocalCandidateAddress) -> bool {
    if matches!(
        candidate.oper_status,
        IfOperStatus::Down | IfOperStatus::NotPresent | IfOperStatus::LowerLayerDown
    ) {
        return false;
    }
    match candidate.ip {
        IpAddr::V4(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_multicast()
                && ip != Ipv4Addr::BROADCAST
        }
        IpAddr::V6(ip) => {
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_unicast_link_local()
                && !ip.is_multicast()
        }
    }
}

fn local_address_cmp(left: &LocalCandidateAddress, right: &LocalCandidateAddress) -> Ordering {
    oper_status_rank(&left.oper_status)
        .cmp(&oper_status_rank(&right.oper_status))
        .then_with(|| address_scope_rank(left.ip).cmp(&address_scope_rank(right.ip)))
        .then_with(|| {
            left.index
                .unwrap_or(u32::MAX)
                .cmp(&right.index.unwrap_or(u32::MAX))
        })
        .then_with(|| left.interface.cmp(&right.interface))
        .then_with(|| left.ip.cmp(&right.ip))
}

fn oper_status_rank(status: &IfOperStatus) -> u8 {
    match status {
        IfOperStatus::Up => 0,
        IfOperStatus::Unknown => 1,
        IfOperStatus::Dormant => 2,
        IfOperStatus::Testing => 3,
        IfOperStatus::Down | IfOperStatus::NotPresent | IfOperStatus::LowerLayerDown => 4,
    }
}

fn address_scope_rank(ip: IpAddr) -> u8 {
    match ip {
        IpAddr::V4(ip) if ip.is_private() => 1,
        IpAddr::V6(ip) if ip.segments()[0] & 0xfe00 == 0xfc00 => 1,
        _ => 0,
    }
}

#[cfg(test)]
pub(super) fn build_webrtc_api() -> Result<Arc<::webrtc::api::API>, TransportError> {
    CandidateAddressPolicy::system().build_api()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct EmbeddedCandidateCount {
    pub(super) raw_lines: usize,
    pub(super) unique_routes: usize,
}

#[derive(Clone, Copy)]
pub(super) enum EmbeddedCandidateScope {
    Local,
    Remote,
}

impl EmbeddedCandidateScope {
    fn limits(self) -> (usize, usize) {
        match self {
            Self::Local => (
                MAX_WEBRTC_LOCAL_CANDIDATE_ROUTES,
                MAX_WEBRTC_LOCAL_CANDIDATE_LINES,
            ),
            Self::Remote => (
                MAX_WEBRTC_REMOTE_CANDIDATE_ROUTES,
                MAX_WEBRTC_REMOTE_CANDIDATE_LINES,
            ),
        }
    }
}

pub(super) fn validate_embedded_ice_candidates(
    sdp: &str,
    scope: EmbeddedCandidateScope,
) -> Result<EmbeddedCandidateCount, TransportError> {
    let (max_routes, max_lines) = scope.limits();
    let mut raw_lines = 0usize;
    let mut unique = HashSet::new();
    for line in sdp.lines() {
        let Some(raw_candidate) = line.trim_start().strip_prefix("a=candidate:") else {
            continue;
        };
        raw_lines += 1;
        if raw_lines > max_lines || raw_candidate.len() > MAX_WEBRTC_CANDIDATE_LENGTH {
            return Err(TransportError::InvalidAddress(
                "WebRTC embedded candidate lines exceed limits".into(),
            ));
        }
        let candidate = unmarshal_candidate(raw_candidate).map_err(|error| {
            TransportError::InvalidAddress(format!("invalid WebRTC ICE candidate: {error}"))
        })?;
        let related = candidate
            .related_address()
            .map(|address| format!("{}:{}", address.address.to_ascii_lowercase(), address.port))
            .unwrap_or_default();
        unique.insert(format!(
            "{}|{}|{}|{}|{}|{}",
            candidate.network_type(),
            candidate.candidate_type(),
            candidate.address().to_ascii_lowercase(),
            candidate.port(),
            candidate.tcp_type(),
            related,
        ));
        if unique.len() > max_routes {
            return Err(TransportError::InvalidAddress(format!(
                "WebRTC embedded SDP exceeds {max_routes} unique ICE routes"
            )));
        }
    }
    Ok(EmbeddedCandidateCount {
        raw_lines,
        unique_routes: unique.len(),
    })
}
