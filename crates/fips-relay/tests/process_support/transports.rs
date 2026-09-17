use fips_core::config::{TransportInstances, TransportsConfig, UdpConfig};
use fips_relay::service::ServiceConfig;
use std::net::SocketAddr;

pub fn udp_transports(bind: SocketAddr) -> TransportsConfig {
    TransportsConfig {
        udp: TransportInstances::Single(UdpConfig {
            bind_addr: Some(bind.to_string()),
            advertise_on_nostr: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub fn udp_bind(config: &ServiceConfig) -> SocketAddr {
    let TransportInstances::Single(udp) = &config.transports.udp else {
        panic!("fixture requires one UDP transport");
    };
    udp.bind_addr.as_ref().unwrap().parse().unwrap()
}
