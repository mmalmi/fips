use super::*;

#[test]
fn parse_external_addr_accepts_bare_ipv4_with_appended_bind_port() {
    let sa = parse_external_advert_addr("198.51.100.1", 2121).unwrap();
    assert_eq!(sa.to_string(), "198.51.100.1:2121");
}

#[test]
fn parse_external_addr_accepts_full_ipv4_socket_addr() {
    let sa = parse_external_advert_addr("198.51.100.1:443", 2121).unwrap();
    assert_eq!(sa.to_string(), "198.51.100.1:443");
    // Explicit port wins over the bind port we passed in.
}

#[test]
fn parse_external_addr_accepts_bare_ipv6_with_appended_bind_port() {
    let sa = parse_external_advert_addr("2001:db8::1", 443).unwrap();
    assert_eq!(sa.to_string(), "[2001:db8::1]:443");
}

#[test]
fn parse_external_addr_accepts_bracketed_ipv6_with_explicit_port() {
    let sa = parse_external_advert_addr("[2001:db8::1]:8443", 443).unwrap();
    assert_eq!(sa.to_string(), "[2001:db8::1]:8443");
}

#[test]
fn parse_external_addr_rejects_garbage() {
    assert!(parse_external_advert_addr("not-an-ip", 443).is_none());
    assert!(parse_external_advert_addr("", 443).is_none());
}

#[test]
fn udp_external_advert_addr_combines_with_bind_port_default() {
    let cfg = UdpConfig {
        external_addr: Some("198.51.100.1".to_string()),
        ..UdpConfig::default()
    };
    // bind_addr unset, so default DEFAULT_UDP_BIND_ADDR (0.0.0.0:2121) applies.
    let sa = cfg.external_advert_addr().unwrap();
    assert_eq!(sa.to_string(), "198.51.100.1:2121");
}

#[test]
fn udp_external_advert_addr_with_explicit_full_socket_addr_overrides_bind_port() {
    let cfg = UdpConfig {
        bind_addr: Some("0.0.0.0:2121".to_string()),
        external_addr: Some("198.51.100.1:9999".to_string()),
        ..UdpConfig::default()
    };
    let sa = cfg.external_advert_addr().unwrap();
    assert_eq!(sa.to_string(), "198.51.100.1:9999");
}

#[test]
fn udp_external_advert_addr_returns_none_when_unset() {
    let cfg = UdpConfig::default();
    assert!(cfg.external_advert_addr().is_none());
}

#[test]
fn tcp_external_advert_addr_requires_bind_port() {
    let cfg = TcpConfig {
        external_addr: Some("198.51.100.1".to_string()),
        ..TcpConfig::default()
    };
    // bind_addr unset → no port to combine with → None.
    assert!(cfg.external_advert_addr().is_none());

    let cfg = TcpConfig {
        bind_addr: Some("0.0.0.0:443".to_string()),
        external_addr: Some("198.51.100.1".to_string()),
        ..TcpConfig::default()
    };
    let sa = cfg.external_advert_addr().unwrap();
    assert_eq!(sa.to_string(), "198.51.100.1:443");
}

#[test]
fn tcp_external_advert_addr_with_full_socket_addr_independent_of_bind() {
    let cfg = TcpConfig {
        bind_addr: Some("0.0.0.0:443".to_string()),
        external_addr: Some("198.51.100.1:8443".to_string()),
        ..TcpConfig::default()
    };
    let sa = cfg.external_advert_addr().unwrap();
    assert_eq!(sa.to_string(), "198.51.100.1:8443");
}

#[test]
fn parse_bind_port_extracts_from_socket_addr_strings() {
    assert_eq!(parse_bind_port("0.0.0.0:2121"), Some(2121));
    assert_eq!(parse_bind_port("[::]:443"), Some(443));
    assert_eq!(parse_bind_port("not-a-socket-addr"), None);
}
