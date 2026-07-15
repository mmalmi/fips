use super::*;

impl Node {
    pub(super) async fn build_overlay_advert(
        &self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) -> Option<OverlayAdvert> {
        if !self.config.node.discovery.nostr.enabled {
            return None;
        }

        let mut endpoints = Vec::new();
        let mut has_udp_nat = false;

        for (transport_id, handle) in &self.transports {
            if self.is_local_rendezvous_transport(transport_id) || !handle.is_operational() {
                continue;
            }

            match handle.transport_type().name {
                "udp" => {
                    let Some(cfg) = self.lookup_udp_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    if cfg.is_public() {
                        // Precedence:
                        // 1. operator-supplied `external_addr` (skips STUN)
                        // 2. non-wildcard *public* `local_addr` (operator
                        //    bound to a specific public IP directly)
                        // 3. STUN auto-discovery against ephemeral socket
                        //    (also taken when bind is wildcard *or* private —
                        //    a private bind is not peer-reachable, so we
                        //    must publish the public reflexive instead)
                        // 4. loud warn + omit endpoint
                        if let Some(explicit) = cfg.external_advert_addr() {
                            endpoints.push(OverlayEndpointAdvert {
                                transport: OverlayTransportKind::Udp,
                                addr: explicit.to_string(),
                            });
                        } else {
                            match handle.local_addr() {
                                Some(addr)
                                    if !addr.ip().is_unspecified()
                                        && !is_unroutable_advert_ip(addr.ip()) =>
                                {
                                    endpoints.push(OverlayEndpointAdvert {
                                        transport: OverlayTransportKind::Udp,
                                        addr: addr.to_string(),
                                    });
                                }
                                Some(addr) => {
                                    let key = handle.transport_id().as_u32();
                                    let port = addr.port();
                                    if let Some(public) =
                                        bootstrap.learn_public_udp_addr(key, port).await
                                    {
                                        endpoints.push(OverlayEndpointAdvert {
                                            transport: OverlayTransportKind::Udp,
                                            addr: public.to_string(),
                                        });
                                    } else {
                                        warn!(
                                            transport_id = key,
                                            bind_addr = %addr,
                                            "advert: udp public=true but bind is wildcard \
                                            or private and STUN observation failed; \
                                            advertising no UDP endpoint. Either set \
                                            transports.udp.external_addr, bind to a \
                                            specific *public* IP, or ensure \
                                            node.discovery.nostr.stun_servers is reachable"
                                        );
                                    }
                                }
                                None => {}
                            }
                        }
                    } else {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Udp,
                            addr: "nat".to_string(),
                        });
                        has_udp_nat = true;
                    }
                }
                "webrtc" => {
                    let Some(cfg) = self.lookup_webrtc_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    endpoints.push(OverlayEndpointAdvert {
                        transport: OverlayTransportKind::WebRtc,
                        addr: hex::encode(self.identity.pubkey_full().serialize()),
                    });
                }
                "tcp" => {
                    let Some(cfg) = self.lookup_tcp_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    // Precedence:
                    // 1. operator-supplied `external_addr` (only path that
                    //    works on cloud-NAT setups where the public IP is
                    //    not on a host interface).
                    // 2. non-wildcard *public* `local_addr` (operator bound
                    //    to a specific public IP directly).
                    // 3. loud warn + omit endpoint (no TCP STUN equivalent).
                    //
                    // A wildcard *or* private bind is never advertised as-is
                    // — peers off-LAN can't reach a private bind, and there
                    // is no TCP STUN to discover a public reflexive.
                    if let Some(explicit) = cfg.external_advert_addr() {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Tcp,
                            addr: explicit.to_string(),
                        });
                    } else {
                        match handle.local_addr() {
                            Some(addr)
                                if !addr.ip().is_unspecified()
                                    && !is_unroutable_advert_ip(addr.ip()) =>
                            {
                                endpoints.push(OverlayEndpointAdvert {
                                    transport: OverlayTransportKind::Tcp,
                                    addr: addr.to_string(),
                                });
                            }
                            Some(addr) => {
                                warn!(
                                    bind_addr = %addr,
                                    "advert: tcp advertise_on_nostr=true bound to wildcard \
                                    or private IP and no transports.tcp.external_addr set; \
                                    advertising no TCP endpoint. Either set external_addr \
                                    to the public IP (recommended for cloud 1:1-NAT setups) \
                                    or bind explicitly to the public IP"
                                );
                            }
                            None => {}
                        }
                    }
                }
                "tor" => {
                    let Some(cfg) = self.lookup_tor_config(handle.name()) else {
                        continue;
                    };
                    if !cfg.advertise_on_nostr() {
                        continue;
                    }
                    if let Some(addr) = handle.onion_address() {
                        endpoints.push(OverlayEndpointAdvert {
                            transport: OverlayTransportKind::Tor,
                            addr: format!("{}:{}", addr, cfg.advertised_port()),
                        });
                    }
                }
                "nostr_relay" => {
                    endpoints.push(OverlayEndpointAdvert {
                        transport: OverlayTransportKind::NostrRelay,
                        addr: crate::encode_npub(&self.identity.pubkey()),
                    });
                }
                _ => {}
            }
        }

        if endpoints.is_empty() {
            return None;
        }

        Some(OverlayAdvert {
            identifier: ADVERT_IDENTIFIER.to_string(),
            version: ADVERT_VERSION,
            endpoints,
            stun_servers: has_udp_nat
                .then(|| self.config.node.discovery.nostr.stun_servers.clone()),
        })
    }

    pub(super) async fn refresh_overlay_advert(
        &self,
        bootstrap: &std::sync::Arc<NostrDiscovery>,
    ) -> Result<(), crate::discovery::nostr::BootstrapError> {
        let advert = self.build_overlay_advert(bootstrap).await;
        bootstrap.update_local_advert(advert).await
    }

    pub(super) fn lookup_udp_config(
        &self,
        transport_name: Option<&str>,
    ) -> Option<&crate::config::UdpConfig> {
        match (&self.config.transports.udp, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    pub(super) fn lookup_tcp_config(
        &self,
        transport_name: Option<&str>,
    ) -> Option<&crate::config::TcpConfig> {
        match (&self.config.transports.tcp, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    pub(super) fn lookup_tor_config(
        &self,
        transport_name: Option<&str>,
    ) -> Option<&crate::config::TorConfig> {
        match (&self.config.transports.tor, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }

    pub(super) fn lookup_webrtc_config(
        &self,
        transport_name: Option<&str>,
    ) -> Option<&crate::config::WebRtcConfig> {
        match (&self.config.transports.webrtc, transport_name) {
            (crate::config::TransportInstances::Single(cfg), None) => Some(cfg),
            (crate::config::TransportInstances::Named(configs), Some(name)) => configs.get(name),
            _ => None,
        }
    }
}
