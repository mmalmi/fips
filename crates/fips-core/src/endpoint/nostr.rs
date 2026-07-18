use super::*;

impl FipsEndpoint {
    /// Snapshot signed machine-rating events for peers with enough local
    /// health evidence. Event signing remains inside the FIPS node identity.
    pub async fn peer_rating_events(
        &self,
        scope: impl Into<String>,
    ) -> Result<Vec<nostr::Event>, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.control(
            "peer rating snapshot",
            NodeEndpointControlCommand::PeerRatingEvents {
                scope: scope.into(),
                response_tx,
            },
            response_rx,
        )
        .await?
        .map_err(FipsEndpointError::Node)
    }

    /// Feed a signed Nostr discovery or rating event into FIPS.
    /// Unsupported, invalid, stale, or incorrectly addressed events return
    /// `false`.
    pub async fn ingest_nostr_event(&self, event: nostr::Event) -> Result<bool, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.control(
            "Nostr event ingest",
            NodeEndpointControlCommand::IngestNostrEvent { event, response_tx },
            response_rx,
        )
        .await
    }

    /// Compatibility name for callers that only feed discovery events.
    pub async fn ingest_nostr_discovery_event(
        &self,
        event: nostr::Event,
    ) -> Result<bool, FipsEndpointError> {
        self.ingest_nostr_event(event).await
    }

    #[deprecated(since = "0.3.98", note = "use ingest_nostr_discovery_event")]
    pub async fn ingest_nostr_pubsub_event(
        &self,
        event: nostr::Event,
    ) -> Result<bool, FipsEndpointError> {
        self.ingest_nostr_event(event).await
    }

    /// Snapshot the endpoint addresses this node is currently advertising via
    /// Nostr discovery.
    pub async fn local_advertised_endpoints(
        &self,
    ) -> Result<Vec<crate::discovery::nostr::OverlayEndpointAdvert>, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.control(
            "local advert snapshot",
            NodeEndpointControlCommand::LocalAdvertSnapshot { response_tx },
            response_rx,
        )
        .await
    }

    /// Return the signed local peer advert for an external peerfinding provider.
    ///
    /// This only creates the ordinary kind 37195 event; it does not select or
    /// contact relays. `None` means advertising is disabled or no local
    /// transport currently has an advert-eligible endpoint.
    pub async fn local_nostr_discovery_advert_event(
        &self,
    ) -> Result<Option<nostr::Event>, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        match self
            .control(
                "local Nostr discovery advert",
                NodeEndpointControlCommand::LocalNostrDiscoveryAdvertEvent { response_tx },
                response_rx,
            )
            .await?
        {
            Ok(event) => Ok(event),
            Err(error) => Err(FipsEndpointError::Node(error)),
        }
    }

    /// Snapshot live Nostr relay states used by the embedded endpoint.
    pub async fn relay_statuses(&self) -> Result<Vec<FipsEndpointRelayStatus>, FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.control(
            "relay snapshot",
            NodeEndpointControlCommand::RelaySnapshot { response_tx },
            response_rx,
        )
        .await
        .map(|relays| {
            relays
                .into_iter()
                .map(FipsEndpointRelayStatus::from)
                .collect()
        })
    }

    /// Replace Nostr discovery relays without rebuilding the endpoint.
    pub async fn update_relays(&self, advert_relays: Vec<String>) -> Result<(), FipsEndpointError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.control(
            "relay update",
            NodeEndpointControlCommand::UpdateRelays {
                advert_relays,
                response_tx,
            },
            response_rx,
        )
        .await?
        .map_err(FipsEndpointError::Node)
    }
}
