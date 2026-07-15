// Ephemeral webrtc-ice binds one host socket for every selected local IP.
pub(crate) const MAX_WEBRTC_HOST_CANDIDATE_SOCKETS: usize = 6;
// Bound configured STUN URL fanout independently of the connection cap.
pub(crate) const MAX_WEBRTC_STUN_SERVERS: usize = 3;
// Each STUN URL can bind one UDP4 and one UDP6 server-reflexive socket.
pub(crate) const MAX_WEBRTC_SOCKETS_PER_STUN_SERVER: usize = 2;
// Keep all WebRTC transports in one validated configuration below this cap.
pub(crate) const MAX_WEBRTC_CONFIG_CANDIDATE_SOCKETS: usize = 96;
#[cfg(any(feature = "webrtc-transport", test))]
pub(crate) const MAX_WEBRTC_LOCAL_CANDIDATE_ROUTES: usize = MAX_WEBRTC_HOST_CANDIDATE_SOCKETS
    + MAX_WEBRTC_STUN_SERVERS * MAX_WEBRTC_SOCKETS_PER_STUN_SERVER;
#[cfg(any(feature = "webrtc-transport", test))]
pub(crate) const MAX_WEBRTC_LOCAL_CANDIDATE_LINES: usize = MAX_WEBRTC_LOCAL_CANDIDATE_ROUTES * 2;
#[cfg(any(feature = "webrtc-transport", test))]
pub(crate) const MAX_WEBRTC_REMOTE_CANDIDATE_ROUTES: usize = 32;
#[cfg(any(feature = "webrtc-transport", test))]
pub(crate) const MAX_WEBRTC_REMOTE_CANDIDATE_LINES: usize = MAX_WEBRTC_REMOTE_CANDIDATE_ROUTES * 2;

pub(crate) fn validate_webrtc_candidate_socket_budget(
    max_connections: usize,
    stun_servers: &[String],
) -> Result<usize, String> {
    if max_connections == 0 {
        return Err("max_connections must be at least 1".into());
    }
    if stun_servers.len() > MAX_WEBRTC_STUN_SERVERS {
        return Err(format!(
            "{} STUN URLs exceed the supported maximum {MAX_WEBRTC_STUN_SERVERS}",
            stun_servers.len()
        ));
    }
    if stun_servers.iter().any(|url| {
        url.strip_prefix("stun:")
            .is_none_or(|endpoint| endpoint.is_empty() || endpoint.starts_with("//"))
    }) {
        return Err("only non-empty `stun:` server URLs are supported".into());
    }
    #[cfg(feature = "webrtc-transport")]
    for url in stun_servers {
        ::webrtc::ice::url::Url::parse_url(url)
            .map_err(|error| format!("invalid WebRTC STUN URL `{url}`: {error}"))?;
    }
    let per_connection =
        MAX_WEBRTC_HOST_CANDIDATE_SOCKETS + stun_servers.len() * MAX_WEBRTC_SOCKETS_PER_STUN_SERVER;
    let reservation = max_connections
        .checked_mul(per_connection)
        .ok_or_else(|| "candidate socket reservation overflowed".to_string())?;
    let safe_connections = MAX_WEBRTC_CONFIG_CANDIDATE_SOCKETS / per_connection;
    if reservation > MAX_WEBRTC_CONFIG_CANDIDATE_SOCKETS {
        return Err(format!(
            "max_connections {max_connections} with {} STUN URLs can allocate more than {MAX_WEBRTC_CONFIG_CANDIDATE_SOCKETS} candidate sockets; maximum is {safe_connections}",
            stun_servers.len()
        ));
    }
    Ok(reservation)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reviewed_socket_arithmetic_covers_host_and_stun_fanout() {
        let three_stun = vec!["stun:test.invalid".to_string(); 3];
        assert_eq!(MAX_WEBRTC_LOCAL_CANDIDATE_ROUTES, 12);
        assert_eq!(
            validate_webrtc_candidate_socket_budget(6, &three_stun),
            Ok(72)
        );
        assert!(validate_webrtc_candidate_socket_budget(8, &three_stun).is_ok());
        assert!(validate_webrtc_candidate_socket_budget(9, &three_stun).is_err());
        assert!(validate_webrtc_candidate_socket_budget(16, &[]).is_ok());
        assert!(validate_webrtc_candidate_socket_budget(17, &[]).is_err());
        assert!(validate_webrtc_candidate_socket_budget(0, &[]).is_err());
        assert!(validate_webrtc_candidate_socket_budget(1, &["turn:test.invalid".into()]).is_err());
    }
}
