use super::super::*;

fn peer_without_addresses() -> Config {
    Config {
        peers: vec![PeerConfig {
            npub: "npub1peer".to_string(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

#[test]
fn peer_addresses_are_optional_with_ble_discovery() {
    let mut config = peer_without_addresses();
    config.node.discovery.nostr.enabled = false;
    config.transports.ble = TransportInstances::Single(BleConfig {
        auto_connect: Some(true),
        ..BleConfig::default()
    });

    config
        .validate()
        .expect("BLE discovery should allow peers without static addresses");
}

#[test]
fn addressless_overlay_peers_remain_valid_when_ble_auto_connect_is_off() {
    let mut config = peer_without_addresses();
    config.node.discovery.nostr.enabled = false;
    config.transports.ble = TransportInstances::Single(BleConfig::default());

    config
        .validate()
        .expect("a later authenticated adjacency can still resolve the overlay peer");
}
