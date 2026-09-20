//! Carry a withdrawn paid trial's durable remainder without reviving its grant.
use super::*;

impl Destination {
    pub(super) fn paid_trial_admission(
        &self,
        denied: Option<bool>,
        retained: impl FnOnce() -> Result<Option<(bool, u64)>, String>,
    ) -> Result<Option<bool>, String> {
        if !self.active.as_ref().is_some_and(|active| active.trial) {
            return Ok(denied);
        }
        Ok(Some(
            denied == Some(true) || retained()?.is_none_or(|(_, remaining)| remaining == 0),
        ))
    }

    pub(super) fn interrupted_trial_step(
        &self,
        selected: &RouteOffer,
        policy: &PriceSelectionPolicy,
        retained: impl FnOnce(&RouteOffer) -> Result<Option<(bool, u64)>, String>,
    ) -> Result<Option<SelectionStep>, String> {
        let Some(active) = self.active.as_ref().filter(|active| {
            active.trial
                && active.price.msat != 0
                && same_path(active, selected)
                && self
                    .working_loss(selected, policy, Instant::now())
                    .is_none()
        }) else {
            return Ok(None);
        };
        let (usable, remaining) = retained(active)?.ok_or("paid trial accounting unavailable")?;
        if usable && active.expires_unix > unix_now()? {
            return Ok(None);
        }
        if remaining == 0 || remaining > active.max_units {
            return Err("closed paid trial has no retained quota".into());
        }
        // Closing an old grant or settling its channel never replenishes its
        // allowance. A fresh offer must still pass the Watch and funding gates.
        Ok(Some(SelectionStep::Request {
            max_units: Some(remaining),
            reuse_unchanged: false,
        }))
    }
}

impl RouteQuotes {
    /// Restore only the selection hint. Retired grants stay closed; the next
    /// accepted replacement must bind its carrier through the normal path.
    pub(crate) async fn restore_trial_hint(
        &self,
        destination: PeerIdentity,
        hint: Result<Option<RouteOffer>, String>,
    ) -> Result<(), String> {
        let Some(selection) = &self.selection else {
            return Ok(());
        };
        let _work = selection.work.lock().await;
        let mut states = selection
            .destinations
            .lock()
            .map_err(|_| "price selection poisoned")?;
        let dest = *destination.node_addr();
        if states
            .get(&dest)
            .is_some_and(|state| state.active.is_some())
        {
            return Ok(());
        }
        let Some(offer) = hint? else {
            return Ok(());
        };
        if offer.destination.node_addr() != &dest
            || offer.buyer != *self.endpoint.node_addr()
            || !offer.trial
            || offer.price.msat == 0
        {
            return Err("invalid interrupted trial hint".into());
        }
        if states.len() >= MAX_DESTINATIONS && !states.contains_key(&dest) {
            return Err("source selection capacity".into());
        }
        let state = states.entry(dest).or_default();
        state.active = Some(offer);
        state.restored = true;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{offer, working};
    use super::*;

    fn fixture() -> (Destination, RouteOffer, PriceSelectionPolicy) {
        let full = offer(2, 1_024);
        let policy = PriceSelectionPolicy::default();
        let mut active = full.clone();
        active.id = "partly-used-trial".into();
        active.trial = true;
        active.max_units = policy.trial_max_units;
        active.expires_unix = unix_now().unwrap() + 60;
        (
            Destination {
                active: Some(active),
                ..Default::default()
            },
            full,
            policy,
        )
    }

    #[test]
    fn closed_unknown_trial_requests_only_durable_remainder_even_after_cooldown() {
        let (mut state, full, policy) = fixture();
        for failed in [false, true] {
            if failed {
                state.failed.insert(full.provider, Instant::now());
            }
            let step = state
                .interrupted_trial_step(&full, &policy, |active| {
                    assert_eq!(Some(active), state.active.as_ref());
                    Ok(Some((false, 29_672)))
                })
                .unwrap();
            assert!(matches!(
                step,
                Some(SelectionStep::Request {
                    max_units: Some(29_672),
                    reuse_unchanged: false,
                })
            ));
        }
        assert_eq!(state.active.as_ref().unwrap().max_units, 32_768);
    }

    #[test]
    fn closed_unknown_trial_cannot_refill_missing_or_exhausted_accounting() {
        let (state, full, policy) = fixture();
        for retained in [None, Some((false, 0)), Some((false, 32_769))] {
            assert!(
                state
                    .interrupted_trial_step(&full, &policy, |_| Ok(retained))
                    .is_err()
            );
        }
        assert!(
            state
                .interrupted_trial_step(&full, &policy, |_| Err("poisoned".into()))
                .is_err()
        );
    }

    #[test]
    fn unavailable_unknown_trial_is_excluded_before_choosing_an_alternative() {
        let alternative = offer(3, 2_048);
        for retained in [Some((false, 0)), None] {
            let (mut state, full, policy) = fixture();
            let now = Instant::now();
            let blocked = state
                .paid_trial_admission(Some(false), || Ok(retained))
                .unwrap()
                .unwrap();
            state.observe_admission(blocked, &policy, now).unwrap();
            for at in [now, now + Duration::from_millis(policy.retry_after_ms + 1)] {
                assert!(!state.provider_eligible(full.provider, at));
                assert_eq!(
                    state
                        .choose(vec![full.clone(), alternative.clone()], &policy, at)
                        .unwrap(),
                    alternative
                );
            }
        }
    }

    #[test]
    fn full_route_admission_never_reads_interrupted_trial_history() {
        let (mut state, full, _) = fixture();
        state.active = Some(full);
        for denied in [None, Some(false), Some(true)] {
            assert_eq!(
                state.paid_trial_admission(denied, || {
                    panic!("full route must not consult potentially ambiguous trial history")
                }),
                Ok(denied)
            );
        }
    }

    #[test]
    fn restored_hint_ignores_quality_until_an_accepted_carrier_is_bound() {
        let (mut state, full, policy) = fixture();
        let active = state.active.as_ref().unwrap().clone();
        state.restored = true;
        for mut quality in [working(&active, 0.0), SourceRouteQuality::default()] {
            quality.delivery_feedback_timed_out = true;
            state.observe(&quality, &policy, Instant::now()).unwrap();
            assert!(state.failed.is_empty());
            assert!(state.observations.is_empty());
        }
        assert!(matches!(
            state
                .interrupted_trial_step(&full, &policy, |_| Ok(Some((false, 123))))
                .unwrap(),
            Some(SelectionStep::Request {
                max_units: Some(123),
                reuse_unchanged: false
            })
        ));
    }

    #[tokio::test]
    async fn restored_accounting_hint_needs_real_native_binding_even_on_the_same_path() {
        use fips_core::{
            Config,
            config::{PeerConfig, TransportInstances, UdpConfig},
        };
        let root = tempfile::tempdir().unwrap();
        let mut nodes = Vec::new();
        for _ in 0..2 {
            let mut config = Config::new();
            config.node.control.enabled = false;
            config.node.discovery.nostr.enabled = false;
            config.node.discovery.lan.enabled = false;
            config.node.discovery.local.enabled = false;
            config.transports.udp = TransportInstances::Single(UdpConfig {
                bind_addr: Some("127.0.0.1:0".into()),
                advertise_on_nostr: Some(false),
                ..Default::default()
            });
            nodes.push(Arc::new(
                FipsEndpoint::builder()
                    .config(config)
                    .without_system_tun()
                    .bind()
                    .await
                    .unwrap(),
            ));
        }
        let peers: Vec<_> = nodes
            .iter()
            .map(|node| PeerIdentity::from_npub(node.npub()).unwrap())
            .collect();
        let buyer = Arc::new(
            crate::buyer::BuyerAuthorizer::create(
                &root.path().join("buyer"),
                *peers[0].node_addr(),
                64,
                Default::default(),
            )
            .unwrap(),
        );
        let (transport, _incoming) =
            ControlTransport::start(nodes[0].clone(), 44_731, vec![peers[1]], 77)
                .await
                .unwrap();
        let quotes = RouteQuotes::new(
            nodes[0].clone(),
            Arc::new(transport),
            QuotePolicy {
                destination_fees: Default::default(),
                billing: BillingBasis::ForwardingData,
                mint_url: "http://test.invalid".into(),
                receiver_pubkey_hex: "02".to_owned() + &"11".repeat(32),
                fee_msat_per_kib: 1,
                max_rate_msat_per_kib: 8192,
                lifetime_secs: 300,
                max_units: 65_536,
                capacity_sat: 64,
                grace_msat: 8_000,
            },
        )
        .unwrap()
        .with_price_selection(PriceSelectionPolicy::default(), buyer)
        .unwrap();
        let (state, _, _) = fixture();
        let mut hint = state.active.unwrap();
        hint.buyer = *peers[0].node_addr();
        hint.provider = *peers[1].node_addr();
        hint.path[0] = hint.provider;
        let destination = hint.destination;
        let before = nodes[0]
            .source_route_quality(destination, Duration::from_secs(15))
            .await
            .unwrap();
        quotes
            .restore_trial_hint(destination, Ok(Some(hint.clone())))
            .await
            .unwrap();
        let after = nodes[0]
            .source_route_quality(destination, Duration::from_secs(15))
            .await
            .unwrap();
        assert_eq!(
            before.next_hop, after.next_hop,
            "hint must not bind a native carrier"
        );
        assert!(
            quotes.activate_source_route(&hint).await.is_err(),
            "same-path hint cannot skip native connected-neighbor validation"
        );
        assert!(
            quotes
                .selection
                .as_ref()
                .unwrap()
                .destinations
                .lock()
                .unwrap()[destination.node_addr()]
            .restored
        );
        let addresses = [
            nodes[0].bound_udp_listen_addrs().await.unwrap()[0],
            nodes[1].bound_udp_listen_addrs().await.unwrap()[0],
        ];
        for (i, node) in nodes.iter().enumerate() {
            let j = 1 - i;
            node.update_peers(vec![PeerConfig::new(
                peers[j].npub(),
                "udp",
                addresses[j].to_string(),
            )])
            .await
            .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(10), async {
            while quotes.connected_provider(hint.provider).await.is_err() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        quotes.activate_source_route(&hint).await.unwrap();
        assert!(
            !quotes
                .selection
                .as_ref()
                .unwrap()
                .destinations
                .lock()
                .unwrap()[destination.node_addr()]
            .restored
        );
        assert_eq!(
            nodes[0]
                .resolve_next_hop(destination, None)
                .await
                .unwrap()
                .map(|peer| *peer.node_addr()),
            Some(hint.provider)
        );
        for node in nodes {
            node.shutdown().await.unwrap();
        }
    }

    #[test]
    fn live_trial_retention_and_qualified_promotion_keep_existing_rules() {
        let (mut state, full, policy) = fixture();
        assert!(
            state
                .interrupted_trial_step(&full, &policy, |_| Ok(Some((true, 29_672))))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            state
                .selection_step(&full, &policy, true, |_| None)
                .unwrap(),
            SelectionStep::Retain(_)
        ));
        let active = state.active.as_ref().unwrap().clone();
        state
            .observe(&working(&active, 0.0), &policy, Instant::now())
            .unwrap();
        assert!(
            state
                .interrupted_trial_step(&full, &policy, |_| panic!("qualified promotion"))
                .unwrap()
                .is_none()
        );
        assert!(matches!(
            state
                .selection_step(&full, &policy, true, |_| None)
                .unwrap(),
            SelectionStep::Request {
                max_units: None,
                reuse_unchanged: false
            }
        ));
        state.observations.clear();
        state.active.as_mut().unwrap().expires_unix = 1;
        assert!(matches!(
            state
                .interrupted_trial_step(&full, &policy, |_| Ok(Some((true, 123))))
                .unwrap(),
            Some(SelectionStep::Request {
                max_units: Some(123),
                reuse_unchanged: false
            })
        ));
    }

    #[test]
    fn recovery_does_not_apply_old_quota_to_other_paths_or_free_routes() {
        let (mut state, full, policy) = fixture();
        let mut other = full.clone();
        other.path.insert(1, offer(3, 1).provider);
        assert!(
            state
                .interrupted_trial_step(&other, &policy, |_| panic!("different path"))
                .unwrap()
                .is_none()
        );
        state.active.as_mut().unwrap().price.msat = 0;
        assert!(
            state
                .interrupted_trial_step(&full, &policy, |_| panic!("free quota"))
                .unwrap()
                .is_none()
        );
    }
}
