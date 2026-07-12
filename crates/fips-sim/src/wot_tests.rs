#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn wot_admission_prioritizes_good_probes_newcomer_and_penalizes_degraded() {
        let report = Box::pin(run_default_wot_admission_sim()).await;
        assert_eq!(report.trusted_rating_author_count, 1);
        assert!(report.peer_discovery.node_count >= 100);
        assert!((1..=3).contains(&report.peer_discovery.known_entry_nodes));
        assert_eq!(
            report.peer_discovery.tracked_candidates_cached,
            report.peer_discovery.tracked_peer_count
        );
        assert!(
            report.peer_discovery.cached_open_discovery_candidates
                >= report.peer_discovery.tracked_peer_count
        );
        assert_eq!(
            report.peer_discovery.advert_events_published,
            report.config.rating_pubsub.peer_count.saturating_sub(1)
        );
        assert_eq!(
            report.peer_discovery.advert_events_cached,
            report.peer_discovery.advert_events_published
        );
        assert!(report.peer_discovery.virtual_ticks > 0);

        assert_eq!(
            selected_profiles(&report, "cold_start"),
            vec![
                WotPeerProfile::Bad,
                WotPeerProfile::Newcomer,
                WotPeerProfile::Degrading,
            ]
        );
        let newcomer = peer_id(&report, WotPeerProfile::Newcomer);
        let bad = peer_id(&report, WotPeerProfile::Bad);
        assert_decision(
            phase(&report, "cold_start"),
            &newcomer,
            true,
            None,
            WotAdmissionReason::NewcomerProbe,
        );
        assert_decision(
            phase(&report, "cold_start"),
            &bad,
            true,
            None,
            WotAdmissionReason::NewcomerProbe,
        );

        let after_probe = phase(&report, "after_initial_probe");
        let reliable = peer_id(&report, WotPeerProfile::Reliable);
        let degrading = peer_id(&report, WotPeerProfile::Degrading);
        assert_decision(
            after_probe,
            &degrading,
            true,
            Some(100),
            WotAdmissionReason::TrustedRating,
        );
        assert_decision(
            after_probe,
            &newcomer,
            true,
            Some(68),
            WotAdmissionReason::TrustedRating,
        );
        assert_decision(
            after_probe,
            &reliable,
            true,
            None,
            WotAdmissionReason::NewcomerProbe,
        );
        assert_decision(
            after_probe,
            &bad,
            false,
            Some(-100),
            WotAdmissionReason::DeferredNegative,
        );

        assert_eq!(
            selected_profiles(&report, "after_degradation"),
            vec![
                WotPeerProfile::Reliable,
                WotPeerProfile::Newcomer,
                WotPeerProfile::BackupReliable,
            ]
        );
        let backup = peer_id(&report, WotPeerProfile::BackupReliable);
        assert_decision(
            phase(&report, "after_degradation"),
            &degrading,
            false,
            Some(-100),
            WotAdmissionReason::DeferredNegative,
        );
        assert_decision(
            phase(&report, "after_degradation"),
            &backup,
            true,
            None,
            WotAdmissionReason::NewcomerProbe,
        );

        assert_eq!(report.exchange.historic_seed_events, 0);
        assert_eq!(report.exchange.local_published_events, 5);
        assert_eq!(report.exchange.indexed_events, 5);
        assert_eq!(report.exchange.history_queries, 3);
        assert_eq!(report.exchange.probe_requests, 6);
        assert_eq!(report.exchange.probe_valid_payloads, 4);
        assert_eq!(report.exchange.probe_invalid_payloads, 2);
        assert_eq!(report.exchange.probe_timeouts, 0);
        assert_eq!(report.exchange.probe_useful_bytes, 4 * 1024);
        assert_eq!(report.exchange.probe_junk_bytes, 2 * 1024);
        assert_eq!(report.exchange.probe_low_throughput_valid_payloads, 2);
        assert!(report.exchange.probe_network_packets_sent > 0);
        assert!(report.exchange.probe_network_packets_delivered > 0);
        assert!(report.exchange.probe_network_bytes_sent > 0);
        assert!(
            report.exchange.probe_network_bytes_delivered
                >= (report.exchange.probe_useful_bytes + report.exchange.probe_junk_bytes) as u64
        );
        assert_eq!(report.rating_events.len(), 5);
        assert!(
            report
                .rating_events
                .iter()
                .all(|event| event.event.verify().is_ok())
        );
        assert!(
            report
                .rating_events
                .iter()
                .all(|event| event.signer() == trusted_rating_signer_npub())
        );
        assert!(
            report
                .rating_events
                .iter()
                .all(|event| event.source != WotRatingEventSource::HistoricIndex)
        );
    }

    #[tokio::test]
    async fn local_rating_publish_uses_inv_want_pubsub_before_history_lookup() {
        let report = Box::pin(run_default_wot_admission_sim()).await;
        let spam_publish_count = report.exchange.local_published_events
            * report.config.rating_pubsub.spam_events_per_publish;
        let expected_pubsub_published = report.peer_discovery.advert_events_published
            + report.exchange.local_published_events
            + spam_publish_count;

        assert_eq!(
            report.exchange.pubsub_published_events,
            expected_pubsub_published
        );
        assert!(report.exchange.pubsub_delivered_events > expected_pubsub_published);
        assert!(
            report.exchange.pubsub_inventory_messages > report.exchange.pubsub_delivered_events
        );
        assert_eq!(
            report.exchange.pubsub_want_messages,
            report.exchange.pubsub_delivered_events
        );
        assert_eq!(
            report.exchange.pubsub_payload_events_decoded,
            report.exchange.pubsub_local_delivered_events
        );
        assert_eq!(report.exchange.pubsub_payload_decode_failures, 0);
        assert!(report.exchange.pubsub_payload_bytes > 0);
        assert!(report.exchange.pubsub_duplicate_inventories > 0);
        assert!(report.exchange.pubsub_virtual_ticks > 0);
        assert!(
            report.exchange.pubsub_inv_want_bytes < report.exchange.pubsub_flood_bytes,
            "inv/want publish accounting should be cheaper than full-payload flooding"
        );

        assert_eq!(phase(&report, "cold_start").rating_events_seen, 0);
        assert_eq!(phase(&report, "after_initial_probe").rating_events_seen, 3);
        assert_eq!(phase(&report, "after_degradation").rating_events_seen, 5);
    }

    #[tokio::test]
    async fn untrusted_rating_spam_is_not_indexed_into_history() {
        let report = Box::pin(run_default_wot_admission_sim()).await;
        let spam_per_publish = report.config.rating_pubsub.spam_events_per_publish;

        assert_eq!(
            report.exchange.pubsub_spam_events_seen,
            report.exchange.local_published_events * spam_per_publish
        );
        assert_eq!(
            report.exchange.pubsub_spam_events_dropped,
            report.exchange.pubsub_spam_events_seen
        );
        assert_eq!(
            report.exchange.indexed_events,
            report.exchange.historic_seed_events + report.exchange.local_published_events
        );
        assert_eq!(report.rating_events.len(), report.exchange.indexed_events);
        assert_eq!(
            phase(&report, "after_degradation").rating_events_seen,
            report.exchange.indexed_events
        );
        assert!(
            report
                .rating_events
                .iter()
                .all(|event| event.source != WotRatingEventSource::UntrustedSpam)
        );
    }

    #[tokio::test]
    async fn low_throughput_valid_probe_is_not_downvoted() {
        let peer = peer(
            peer_npub(WotPeerProfile::Newcomer),
            WotPeerProfile::Newcomer,
            100,
        );
        let mut probe_runtime = WotProbeRuntime::start(std::slice::from_ref(&peer))
            .await
            .expect("start probe runtime");
        let observation = probe_runtime
            .observed_rating_for_probe(&peer, false, 123)
            .await;
        probe_runtime
            .shutdown()
            .await
            .expect("shutdown probe runtime");

        assert!(observation.valid_payload);
        assert!(!observation.timed_out);
        assert!(observation.low_throughput_valid_payload);
        assert!(observation.network_delta.packets_sent > 0);
        assert!(observation.network_delta.packets_delivered > 0);
        assert_eq!(observation.rating, Some(84));
        assert_eq!(normalize_rating_score(84, 0, 100), Some(68));
    }

    #[tokio::test]
    async fn trusted_rating_signer_can_differ_from_rater_fact() {
        let mut exchange = WotRatingExchange::default();
        let signer = trusted_rating_signer_keys();
        let external_rater = sim_npub(30);
        let subject = sim_npub(31);
        let spam_subject = sim_npub(32);
        let trusted = WotRatingFactEvent::signed_by(
            &signer,
            &external_rater,
            &subject,
            "fips.peer",
            90,
            10,
            WotRatingEventSource::HistoricIndex,
        );
        let spam = WotRatingFactEvent::signed_by(
            &sim_keys(90),
            &trusted_rating_signer_npub(),
            &spam_subject,
            "fips.peer",
            100,
            11,
            WotRatingEventSource::HistoricIndex,
        );

        for event in [spam, trusted] {
            exchange.stats.historic_seed_events += 1;
            exchange.ingest(event).await;
        }

        let events = exchange.query_events(&WotNostrFilter::rating_scope("fips.peer", 64));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].signer(), trusted_rating_signer_npub());
        assert_eq!(events[0].rater().as_deref(), Some(external_rater.as_str()));
        assert_eq!(events[0].subject().as_deref(), Some(subject.as_str()));
        assert_eq!(events[0].normalized_score(), Some(80));
        assert_eq!(
            exchange
                .trust_scores_for_npubs(std::slice::from_ref(&subject))
                .await
                .get(&subject),
            Some(&80)
        );
        assert_eq!(exchange.stats.pubsub_spam_events_seen, 1);
        assert_eq!(exchange.stats.pubsub_spam_events_dropped, 1);
        assert_eq!(exchange.stats.indexed_events, 1);
    }

    #[test]
    fn rating_fact_tags_use_scope_for_pubsub_and_history_lookup() {
        let subject = sim_npub(40);
        let event = WotRatingFactEvent::signed_by(
            &trusted_rating_signer_keys(),
            &local_rater_npub(),
            &subject,
            "fips.peer",
            80,
            42,
            WotRatingEventSource::LocalProbe,
        );
        let tags = event.nostr_fact_tags();

        assert!(event.event.verify().is_ok());
        assert_eq!(event.kind(), RATING_FACT_KIND);
        assert_eq!(event.signer(), trusted_rating_signer_npub());
        assert!(tags.contains(&tag("i", "fips.peer")));
        assert!(tags.contains(&tag("scope", "fips.peer")));
        assert!(tags.contains(&tag("type", "rating")));
        assert!(
            !tags
                .iter()
                .any(|tag| tag.first().is_some_and(|key| key == "context"))
        );

        let filter = WotNostrFilter::rating_scope("fips.peer", 64);
        assert_eq!(filter.kinds, vec![RATING_FACT_KIND]);
        assert_eq!(filter.i_tags, vec!["fips.peer"]);
        assert_eq!(
            serde_json::to_value(&filter).unwrap(),
            serde_json::json!({
                "kinds": [7368],
                "#i": ["fips.peer"],
                "limit": 64,
            })
        );
        let nostr_filter = serde_json::to_value(filter.to_nostr_filter()).unwrap();
        assert_eq!(nostr_filter["kinds"], serde_json::json!([7368]));
        assert_eq!(nostr_filter["#i"], serde_json::json!(["fips.peer"]));
        assert_eq!(nostr_filter["limit"], 64);
    }

    #[test]
    fn history_lookup_uses_normal_nostr_filter_kind_and_i_tag() {
        let signer = trusted_rating_signer_keys();
        let mut exchange = WotRatingExchange::default();
        let good_subject = sim_npub(50);
        let other_scope_subject = sim_npub(51);
        let wrong_kind_subject = sim_npub(52);
        exchange.events.push(WotRatingFactEvent::signed_by(
            &signer,
            &local_rater_npub(),
            &good_subject,
            "fips.peer",
            90,
            100,
            WotRatingEventSource::HistoricIndex,
        ));
        exchange.events.push(WotRatingFactEvent::signed_by(
            &signer,
            &local_rater_npub(),
            &other_scope_subject,
            "other.scope",
            90,
            101,
            WotRatingEventSource::HistoricIndex,
        ));
        exchange.events.push(signed_rating_fact_event(
            &signer,
            &local_rater_npub(),
            &wrong_kind_subject,
            "fips.peer",
            90,
            102,
            WotRatingEventSource::HistoricIndex,
            Kind::Custom(1),
        ));

        let events = exchange.query_events(&WotNostrFilter::rating_scope("fips.peer", 64));

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].subject().as_deref(), Some(good_subject.as_str()));
    }

    fn phase<'a>(report: &'a WotAdmissionSimReport, label: &str) -> &'a WotAdmissionPhaseReport {
        report
            .phases
            .iter()
            .find(|phase| phase.label == label)
            .expect("phase exists")
    }

    fn selected_profiles(report: &WotAdmissionSimReport, label: &str) -> Vec<WotPeerProfile> {
        phase(report, label)
            .selected_peers
            .iter()
            .map(|peer_id| profile(report, peer_id))
            .collect()
    }

    fn profile(report: &WotAdmissionSimReport, peer_id: &str) -> WotPeerProfile {
        report
            .peers
            .iter()
            .find(|peer| peer.id == peer_id)
            .map(|peer| peer.profile)
            .expect("peer exists")
    }

    fn peer_id(report: &WotAdmissionSimReport, profile: WotPeerProfile) -> String {
        report
            .peers
            .iter()
            .find(|peer| peer.profile == profile)
            .map(|peer| peer.id.clone())
            .expect("peer exists")
    }

    fn assert_decision(
        phase: &WotAdmissionPhaseReport,
        peer_id: &str,
        selected: bool,
        trust_score: Option<i64>,
        reason: WotAdmissionReason,
    ) {
        let decision = phase
            .decisions
            .iter()
            .find(|decision| decision.peer_id == peer_id)
            .expect("peer decision exists");
        assert_eq!(decision.selected, selected);
        assert_eq!(decision.trust_score, trust_score);
        assert_eq!(decision.reason, reason);
        assert_eq!(decision.admission_order.is_some(), selected);
    }

    fn tag(key: &str, value: &str) -> Vec<String> {
        vec![key.to_string(), value.to_string()]
    }
}
