//! Retain the exact trial allowance across interrupted replacement and restart.
use super::*;

impl Controller {
    pub(in crate::controller) fn validate_selected_trial(
        j: &Journal,
        watch: &WatchedRoute,
    ) -> Result<(), String> {
        let Some(id) = &watch.selected_trial else {
            return Ok(());
        };
        let old = j
            .outgoing
            .get(id)
            .ok_or("selected trial accounting missing")?;
        if j.version & journal::SELECTED_TRIAL_VERSION == 0
            || !old.accepted
            || !old.offer.trial
            || old.offer.price.msat == 0
            || old.purchase.contract.id != *id
            || old.offer.destination.npub() != watch.destination
            || old.offer.billing != watch.billing
            || old.offer.buyer != j.local
        {
            return Err("invalid selected trial accounting".into());
        }
        Ok(())
    }

    pub(in crate::controller) fn complete_watched_purchase(
        j: &mut Journal,
        id: &str,
        mut expected: WatchedRoute,
        completed: &Purchase,
    ) -> Result<(), String> {
        let outgoing = j
            .outgoing
            .get(&completed.contract.id)
            .ok_or("purchase intent missing")?;
        if outgoing.purchase != *completed
            || !outgoing.accepted
            || !Self::routing_eligible(j, outgoing)
            || j.buyer_settlements.contains_key(&completed.channel.id)
        {
            return Err("watched purchase changed".into());
        }
        if expected.pending.is_some() {
            // A concurrent transit purchase may retain an equivalent offer.
            // Completion must compare the identity actually bound by reservation.
            expected.pending = Some(outgoing.offer.clone());
        }
        let watch = j
            .watched_routes
            .get_mut(id)
            .ok_or("source authorization missing")?;
        if *watch != expected || watch.paused || !watch.accepts(&outgoing.offer) {
            return Err("watched purchase changed".into());
        }
        watch.pending = None;
        // A failed/withdrawn promotion never reaches this transaction, leaving
        // the predecessor's remaining allowance pinned instead of replenished.
        watch.selected_trial = outgoing.offer.trial.then(|| completed.contract.id.clone());
        if watch.selected_trial.is_some() {
            j.version |= journal::SELECTED_TRIAL_VERSION;
        }
        Ok(())
    }

    pub(in crate::controller) async fn restore_interrupted_trial(
        &self,
        watch: &WatchedRoute,
    ) -> Result<(), String> {
        if !self.services.quotes.price_selection_enabled() {
            return Ok(());
        }
        let current = self.snapshot().await?;
        let destination = PeerIdentity::from_npub(&watch.destination)
            .map_err(|_| "invalid watched destination")?;
        self.services
            .quotes
            .restore_trial_hint(destination, Self::interrupted_trial_hint(&current, watch))
            .await
    }

    fn interrupted_trial_hint(
        j: &Journal,
        watch: &WatchedRoute,
    ) -> Result<Option<RouteOffer>, String> {
        if watch.paused
            || watch.pending.is_some()
            || j.watched_routes.get(&watch.destination) != Some(watch)
        {
            return Ok(None);
        }
        Self::validate_selected_trial(j, watch)?;
        Ok(watch
            .selected_trial
            .as_ref()
            .map(|id| j.outgoing[id].offer.clone()))
    }
}

#[cfg(test)]
mod tests;
