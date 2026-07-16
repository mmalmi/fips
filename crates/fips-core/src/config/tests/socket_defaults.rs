use super::*;
use tempfile::TempDir;

#[cfg(unix)]
static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn test_is_loopback_addr_str() {
    assert!(is_loopback_addr_str("127.0.0.1:2121"));
    assert!(is_loopback_addr_str("127.0.0.5:9999"));
    assert!(is_loopback_addr_str("[::1]:2121"));
    assert!(is_loopback_addr_str("::1:2121"));
    assert!(is_loopback_addr_str("localhost:80"));
    assert!(!is_loopback_addr_str("0.0.0.0:2121"));
    assert!(!is_loopback_addr_str("192.168.1.1:2121"));
    assert!(!is_loopback_addr_str("[fd00::1]:2121"));
    assert!(!is_loopback_addr_str("core-vm.tail65015.ts.net:2121"));
    assert!(!is_loopback_addr_str("example.com:443"));
}

#[cfg(unix)]
#[test]
fn test_resolve_default_socket_call_sites_agree() {
    let _guard = ENV_MUTEX.lock().unwrap();

    let control_client = default_control_path().to_string_lossy().into_owned();
    let gateway_client = default_gateway_path().to_string_lossy().into_owned();
    let control_daemon = ControlConfig::default().socket_path;

    assert_eq!(control_daemon, control_client);

    let control_dir = Path::new(&control_client)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    let gateway_dir = Path::new(&gateway_client)
        .parent()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default();
    assert_eq!(control_dir, gateway_dir);
}

#[cfg(unix)]
#[test]
fn test_resolve_default_socket_xdg_when_no_run_fips() {
    let _guard = ENV_MUTEX.lock().unwrap();

    let temp_dir = TempDir::new().unwrap();
    let prev_xdg = std::env::var("XDG_RUNTIME_DIR").ok();

    // SAFETY: serialized by ENV_MUTEX, so no other test in this module
    // observes the transient process environment.
    unsafe {
        std::env::set_var("XDG_RUNTIME_DIR", temp_dir.path());
    }

    let path = resolve_default_socket("control.sock");

    // SAFETY: serialized by ENV_MUTEX.
    unsafe {
        match prev_xdg {
            Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    assert!(
        path.starts_with("/run/fips/")
            || path.starts_with(&format!("{}/fips/", temp_dir.path().display())),
        "expected /run/fips or XDG path, got: {path}"
    );
}

#[cfg(unix)]
#[test]
fn test_resolve_default_socket_tmp_when_xdg_invalid() {
    let _guard = ENV_MUTEX.lock().unwrap();

    let prev_xdg = std::env::var("XDG_RUNTIME_DIR").ok();
    let bogus = "/nonexistent-xdg-runtime-dir-for-fips-test-zzz";

    // SAFETY: serialized by ENV_MUTEX.
    unsafe {
        std::env::set_var("XDG_RUNTIME_DIR", bogus);
    }

    let path = resolve_default_socket("gateway.sock");

    // SAFETY: serialized by ENV_MUTEX.
    unsafe {
        match prev_xdg {
            Some(value) => std::env::set_var("XDG_RUNTIME_DIR", value),
            None => std::env::remove_var("XDG_RUNTIME_DIR"),
        }
    }

    assert!(
        path.starts_with("/run/fips/") || path == "/tmp/fips-gateway.sock",
        "expected /run/fips or /tmp fallback, got: {path}"
    );
    assert!(
        !path.starts_with(bogus),
        "stale XDG_RUNTIME_DIR leaked into resolver: {path}"
    );
}

#[test]
fn test_validate_loopback_bind_with_external_peer_rejected() {
    use crate::config::PeerAddress;
    let mut config = Config::default();
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:2121".to_string()),
        ..Default::default()
    });
    config.peers = vec![PeerConfig {
        npub: "npub1peer".to_string(),
        addresses: vec![PeerAddress::new("udp", "core-vm.tail65015.ts.net:2121")],
        ..Default::default()
    }];

    let err = config.validate().expect_err("validation should fail");
    let msg = err.to_string();
    assert!(msg.contains("loopback"), "got: {msg}");
    assert!(msg.contains("non-loopback"), "got: {msg}");
}

#[test]
fn test_validate_loopback_bind_with_loopback_peer_ok() {
    use crate::config::PeerAddress;
    let mut config = Config::default();
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:2121".to_string()),
        ..Default::default()
    });
    config.peers = vec![PeerConfig {
        npub: "npub1peer".to_string(),
        addresses: vec![PeerAddress::new("udp", "127.0.0.2:2121")],
        ..Default::default()
    }];

    config
        .validate()
        .expect("loopback peer with loopback bind should validate");
}

#[test]
fn test_validate_outbound_only_exempt_from_loopback_check() {
    use crate::config::PeerAddress;
    let mut config = Config::default();
    // outbound_only overrides bind_addr → 0.0.0.0:0; the loopback
    // check must skip this transport entirely.
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("127.0.0.1:2121".to_string()),
        outbound_only: Some(true),
        ..Default::default()
    });
    config.peers = vec![PeerConfig {
        npub: "npub1peer".to_string(),
        addresses: vec![PeerAddress::new("udp", "core-vm.tail65015.ts.net:2121")],
        ..Default::default()
    }];

    config
        .validate()
        .expect("outbound_only should be exempt from the loopback check");
}

#[test]
fn test_outbound_only_forces_ephemeral_bind() {
    let cfg = UdpConfig {
        bind_addr: Some("127.0.0.1:2121".to_string()),
        outbound_only: Some(true),
        ..Default::default()
    };
    assert_eq!(cfg.bind_addr(), "0.0.0.0:0");
    assert!(cfg.outbound_only());
}

#[test]
fn test_outbound_only_forces_advertise_off() {
    let cfg = UdpConfig {
        advertise_on_nostr: Some(true),
        outbound_only: Some(true),
        ..Default::default()
    };
    assert!(!cfg.advertise_on_nostr());
}

#[test]
fn test_udp_accept_connections_default_true() {
    let cfg = UdpConfig::default();
    assert!(cfg.accept_connections());
}

#[test]
fn local_rendezvous_rejects_colliding_application_udp_bind() {
    let mut config = Config::new();
    config.node.discovery.local.enabled = true;
    config.transports.udp = TransportInstances::Single(UdpConfig {
        bind_addr: Some("0.0.0.0:21211".to_string()),
        ..UdpConfig::default()
    });

    let error = config
        .validate()
        .expect_err("application bind must not steal the rendezvous port");
    assert!(
        error
            .to_string()
            .contains("collides with the local rendezvous")
    );

    let TransportInstances::Single(udp) = &mut config.transports.udp else {
        unreachable!()
    };
    udp.outbound_only = Some(true);
    config
        .validate()
        .expect("outbound-only transport ignores its configured bind");
}
