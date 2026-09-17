use super::*;
use crate::control_transport::NeighborAdmission;
use fips_core::{
    Config,
    config::{PeerConfig, TransportInstances},
};

fn configured(transports: Value) -> ServiceConfig {
    let mut config: ServiceConfig =
        serde_json::from_str(include_str!("../../service.example.json")).unwrap();
    config.transports = serde_json::from_value(transports).unwrap();
    config.neighbors.clear();
    config
}

fn assert_discovery_disabled(config: &Config) {
    assert!(!config.node.discovery.nostr.enabled);
    assert!(!config.node.discovery.lan.enabled);
    assert!(!config.node.discovery.local.enabled);
}

#[test]
fn tcp_only_configuration_keeps_its_native_settings_without_adding_udp() {
    let mut config = configured(json!({
        "tcp": { "bind_addr": "127.0.0.1:0", "keepalive_secs": 0 }
    }));
    config.neighbors.push(PeerConfig::new(
        Identity::generate().npub(),
        "tcp",
        "127.0.0.1:2121",
    ));
    config.validate().unwrap();
    let native = config.network(&Identity::generate(), false);
    assert_eq!(
        serde_json::to_value(&native.transports).unwrap(),
        serde_json::to_value(&config.transports).unwrap()
    );
    assert!(native.transports.udp.is_empty());
    assert!(native.transports.ethernet.is_empty());
    assert_eq!(native.peers.len(), 1);
    assert_eq!(native.peers[0].addresses[0].transport, "tcp");
    assert_discovery_disabled(&native);
}

#[test]
fn named_transport_instances_share_one_total_bound_and_preserve_configuration() {
    let transports = json!({
        "udp": {
            "v4": { "bind_addr": "127.0.0.1:0", "accept_connections": false },
            "v6": { "bind_addr": "[::1]:0" }
        },
        "tcp": {
            "listener": { "bind_addr": "127.0.0.1:0" },
            "outbound": {}
        }
    });
    let config = configured(transports.clone());
    config.validate().unwrap();
    let native = config.network(&Identity::generate(), false);
    assert_eq!(serde_json::to_value(native.transports).unwrap(), transports);
    let mut too_many = transports;
    too_many["tcp"]["extra"] = json!({});
    assert!(configured(too_many).validate().is_err());
}

#[test]
fn initialization_uses_only_loopback_even_with_multiple_runtime_transports() {
    let mut config = configured(json!({
        "udp": { "bind_addr": "0.0.0.0:2121" },
        "tcp": { "bind_addr": "0.0.0.0:2122" }
    }));
    config.neighbor_admission = NeighborAdmission::AuthenticatedAdjacent;
    config.neighbors.push(PeerConfig::new(
        Identity::generate().npub(),
        "tcp",
        "192.0.2.1:2122",
    ));
    config.validate().unwrap();
    let native = config.network(&Identity::generate(), true);
    assert_eq!(
        native.transports.instance_counts().collect::<Vec<_>>(),
        [("udp", 1)]
    );
    let TransportInstances::Single(udp) = native.transports.udp.clone() else {
        panic!("initialization uses one loopback socket");
    };
    assert_eq!(udp.bind_addr.as_deref(), Some("127.0.0.1:0"));
    assert!(native.peers.is_empty());
    assert!(!native.node.control.enabled);
    assert_discovery_disabled(&native);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn explicit_link_discovery_is_independent_of_control_and_purchase_authority() {
    let original = configured(json!({"udp": {"bind_addr": "127.0.0.1:0"}}));
    assert_eq!(
        original.neighbor_admission,
        NeighborAdmission::ConfiguredOnly
    );
    for mode in [
        NeighborAdmission::ConfiguredOnly,
        NeighborAdmission::AuthenticatedAdjacent,
    ] {
        for enabled in [false, true] {
            let mut config = configured(json!({ "ethernet": {
                "mesh": {
                    "interface": "mesh0",
                    "discovery": enabled,
                    "announce": enabled,
                    "auto_connect": enabled,
                    "accept_connections": true
                }
            }}));
            config.neighbor_admission = mode;
            config.validate().unwrap();
            let native = config.network(&Identity::generate(), false);
            assert_eq!(
                serde_json::to_value(&native.transports).unwrap(),
                serde_json::to_value(&config.transports).unwrap()
            );
            assert!(native.transports.udp.is_empty());
            assert!(native.peers.is_empty());
            assert_eq!(config.terms, original.terms);
            assert_discovery_disabled(&native);
            if mode == NeighborAdmission::AuthenticatedAdjacent {
                assert_eq!(native.node.limits.max_peers, 16);
                assert_eq!(native.node.limits.max_connections, 32);
                assert_eq!(native.node.limits.max_links, 32);
                assert_eq!(native.node.limits.max_pending_inbound, 16);
                assert_eq!(native.node.limits.max_sessions, 128);
            }
            let initializing = config.network(&Identity::generate(), true);
            assert!(initializing.transports.ethernet.is_empty());
        }
    }
}

#[test]
fn empty_unsupported_and_misspelled_transport_configuration_is_rejected() {
    assert!(configured(json!({})).validate().is_err());
    for adapter in ["websocket", "tor", "webrtc", "ble"] {
        let mut transports = json!({"udp": {"bind_addr": "127.0.0.1:0"}});
        transports[adapter] = json!({});
        assert!(configured(transports).validate().is_err(), "{adapter}");
    }
    let mut value = serde_json::to_value(configured(json!({"tcp": {}}))).unwrap();
    value["transports"]["udpp"] = json!({});
    assert!(serde_json::from_value::<ServiceConfig>(value).is_err());
}

#[test]
fn binds_are_numeric_and_unicast_even_when_outbound_mode_overrides_them() {
    for adapter in ["udp", "tcp"] {
        for bind in [
            "not-an-address",
            "localhost:2121",
            "127.0.0.1",
            "239.1.2.3:2121",
            "255.255.255.255:2121",
            "[ff02::1]:2121",
        ] {
            let mut transports = json!({});
            transports[adapter] = json!({"bind_addr": bind});
            assert!(
                configured(transports).validate().is_err(),
                "{adapter} {bind}"
            );
        }
    }
    assert!(
        configured(json!({"udp": {
            "bind_addr": "malformed",
            "outbound_only": true
        }}))
        .validate()
        .is_err()
    );
}

#[test]
fn neighbor_addresses_require_an_enabled_type_and_valid_numeric_target() {
    for adapter in ["udp", "tcp"] {
        let mut transports = json!({});
        transports[adapter] = json!({"bind_addr": "0.0.0.0:0"});
        let mut config = configured(transports);
        for address in [
            "localhost:2121",
            "192.0.2.1:0",
            "0.0.0.0:2121",
            "239.1.2.3:2121",
            "255.255.255.255:2121",
            "[ff02::1]:2121",
        ] {
            config.neighbors = vec![PeerConfig::new(
                Identity::generate().npub(),
                adapter,
                address,
            )];
            assert!(config.validate().is_err(), "{adapter} {address}");
        }
        config.neighbors[0].addresses[0].addr = "192.0.2.1:2121".into();
        config.validate().unwrap();
        config.neighbors[0].addresses[0].transport = format!("{adapter}/default");
        assert!(config.validate().is_err());
    }
    let mut config = configured(json!({"tcp": {}}));
    config.neighbors = vec![PeerConfig::new(
        Identity::generate().npub(),
        "udp",
        "127.0.0.1:2121",
    )];
    assert!(config.validate().is_err());
}

#[test]
fn udp_requires_a_matching_socket_family_but_tcp_uses_independent_outbound_sockets() {
    for adapter in ["udp", "tcp"] {
        let mut transports = json!({});
        transports[adapter] = json!({"bind_addr": "0.0.0.0:0"});
        let mut config = configured(transports);
        config.neighbors.push(PeerConfig::new(
            Identity::generate().npub(),
            adapter,
            "[::1]:2121",
        ));
        assert_eq!(config.validate().is_ok(), adapter == "tcp");
    }
}

#[test]
fn native_cross_field_validation_rejects_adverts_without_enabling_discovery() {
    for adapter in ["udp", "tcp"] {
        let mut transports = json!({});
        transports[adapter] = json!({
            "bind_addr": "127.0.0.1:2121",
            "advertise_on_nostr": true
        });
        let config = configured(transports);
        assert!(config.validate().is_err(), "{adapter}");
        let native = config.network(&Identity::generate(), false);
        assert_discovery_disabled(&native);
        assert_eq!(
            serde_json::to_value(&native.transports).unwrap(),
            serde_json::to_value(&config.transports).unwrap()
        );
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn ethernet_requires_unique_valid_interfaces_and_unicast_neighbor_macs() {
    for interface in ["", "too-long-interface", "mesh/0", "mèsh0", "mesh 0"] {
        assert!(
            configured(json!({"ethernet": {"interface": interface}}))
                .validate()
                .is_err(),
            "{interface}"
        );
    }
    assert!(
        configured(json!({"ethernet": {
            "first": {"interface": "mesh0"},
            "second": {"interface": "mesh0"}
        }}))
        .validate()
        .is_err()
    );
    let mut config = configured(json!({"ethernet": {"interface": "mesh0"}}));
    for address in [
        "mesh1/02:11:22:33:44:55",
        "mesh0/not-a-mac",
        "mesh0/00:00:00:00:00:00",
        "mesh0/ff:ff:ff:ff:ff:ff",
        "mesh0/01:00:5e:00:00:01",
    ] {
        config.neighbors = vec![PeerConfig::new(
            Identity::generate().npub(),
            "ethernet",
            address,
        )];
        assert!(config.validate().is_err(), "{address}");
    }
    config.neighbors[0].addresses[0].addr = "mesh0/02:11:22:33:44:55".into();
    config.validate().unwrap();
}

#[test]
fn configured_peer_identity_and_address_state_stays_bounded() {
    let mut config = configured(json!({"tcp": {}}));
    config.neighbors = (0..8)
        .map(|_| PeerConfig::new(Identity::generate().npub(), "tcp", "127.0.0.1:2121"))
        .collect();
    config.validate().unwrap();
    config.neighbors.push(PeerConfig::new(
        Identity::generate().npub(),
        "tcp",
        "127.0.0.1:2121",
    ));
    assert!(config.validate().is_err());
    config.neighbors.truncate(1);
    let original = config.neighbors[0].clone();
    config.neighbors.push(original.clone());
    assert!(config.validate().is_err());
    config.neighbors.truncate(1);
    config.neighbors[0].npub = "invalid".into();
    assert!(config.validate().is_err());
    config.neighbors[0] = original;
    config.neighbors[0].addresses.clear();
    assert!(config.validate().is_err());
    config.neighbors[0].addresses = (0..4)
        .map(|i| fips_core::config::PeerAddress::new("tcp", format!("127.0.0.1:{}", 2121 + i)))
        .collect();
    config.validate().unwrap();
    config.neighbors[0]
        .addresses
        .push(fips_core::config::PeerAddress::new("tcp", "127.0.0.1:2125"));
    assert!(config.validate().is_err());
}

#[test]
fn customer_entry_requires_a_specific_inbound_udp_listener_inside_its_network() {
    let mut config = configured(json!({"udp": {"bind_addr": "192.0.2.1:2121"}}));
    assert!(config.customer_network.is_none());
    config.customer_network = Some("192.0.2.0/24".parse().unwrap());
    config.validate().unwrap();
    let native = config.network(&Identity::generate(), false);
    assert_eq!(native.node.limits.max_peers, config.neighbors.len() + 16);
    assert_eq!(native.node.limits.max_pending_inbound, 16);
    assert_eq!(native.node.limits.max_sessions, 128);
    for transports in [
        json!({"tcp": {"bind_addr": "192.0.2.1:2121"}}),
        json!({"udp": {"bind_addr": "0.0.0.0:2121"}}),
        json!({"udp": {"bind_addr": "198.51.100.1:2121"}}),
        json!({"udp": {"bind_addr": "[::1]:2121"}}),
        json!({"udp": {"bind_addr": "192.0.2.1:2121", "outbound_only": true}}),
        json!({"udp": {"bind_addr": "192.0.2.1:2121", "accept_connections": false}}),
    ] {
        config.transports = serde_json::from_value(transports.clone()).unwrap();
        assert!(config.validate().is_err(), "{transports}");
    }
    config.transports = serde_json::from_value(json!({
        "udp": {
            "customers": {"bind_addr": "192.0.2.1:2121"},
            "other": {"bind_addr": "198.51.100.1:2121"}
        },
        "tcp": {"bind_addr": "0.0.0.0:2122"}
    }))
    .unwrap();
    config.validate().unwrap();
    for network in ["0.0.0.0/0", "224.0.0.0/4", "::/0", "ff00::/8"] {
        config.customer_network = Some(network.parse().unwrap());
        assert!(config.validate().is_err(), "{network}");
    }
    config.customer_network = Some("fd00::/64".parse().unwrap());
    config.transports =
        serde_json::from_value(json!({"udp": {"bind_addr": "[fd00::1]:2121"}})).unwrap();
    config.validate().unwrap();
}
