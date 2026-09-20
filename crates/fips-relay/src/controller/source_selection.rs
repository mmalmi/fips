//! Distinguish explicitly opened local routes from purchases made for transit.
use super::*;

mod recovery;

impl Controller {
    pub(super) async fn authorize_source_selection(
        &self,
        destination: PeerIdentity,
    ) -> Result<(), String> {
        if !self.services.quotes.price_selection_enabled() {
            return Ok(());
        }
        let id = destination.npub();
        let billing = self.services.quotes.billing_basis();
        let max_rate_msat_per_kib = self.services.quotes.max_rate_msat_per_kib();
        self.change(move |j| {
            if !j.watched_routes.contains_key(&id) {
                if j.watched_routes.len() >= MAX_ROUTES {
                    return Err("source route capacity".into());
                }
                // Retain source ownership for restart, but a one-shot purchase
                // does not implicitly authorize ongoing alternative purchases.
                j.watched_routes.insert(
                    id.clone(),
                    WatchedRoute {
                        billing,
                        destination: id,
                        max_rate_msat_per_kib,
                        paused: true,
                        pending: None,
                        selected_trial: None,
                    },
                );
            }
            Ok(())
        })
        .await
    }

    pub(super) async fn activate_source_route(&self, offer: &RouteOffer) -> Result<(), String> {
        if !self.services.quotes.price_selection_enabled() {
            return Ok(());
        }
        // Recovery may have taken its snapshot before a replacement retired
        // this offer. Serialize with local retirement and check current state
        // before binding, so old recovery work cannot restore an obsolete path.
        let _work = self.route_work.lock().await;
        let snapshot = self.snapshot().await?;
        if !snapshot
            .watched_routes
            .contains_key(&offer.destination.npub())
        {
            return Ok(());
        }
        let timestamp = now()?;
        if offer.price.msat != 0
            && !snapshot.outgoing.values().any(|o| {
                o.offer == *offer
                    && o.accepted
                    && Self::routing_eligible(&snapshot, o)
                    && o.purchase.contract.expires_unix > timestamp
                    && !snapshot
                        .buyer_settlements
                        .contains_key(&o.purchase.channel.id)
            })
        {
            return Ok(());
        }
        self.services.quotes.activate_source_route(offer).await?;
        Ok(())
    }
}
