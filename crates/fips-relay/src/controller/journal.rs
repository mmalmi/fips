//! Validate retained financial intent before resuming service.
use super::*;

// Authorization-format fence independent of the existing accounting checkpoints.
pub(super) const RECOVERY_ONLY_VERSION: u16 = 0x100;
pub(super) const EXPIRY_RECOVERY_VERSION: u16 = 0x200;
const FORMAT_FLAGS: u16 = RECOVERY_ONLY_VERSION | EXPIRY_RECOVERY_VERSION;

impl Journal {
    pub(super) fn history_version(&self) -> u16 {
        self.version & !FORMAT_FLAGS
    }

    pub(super) fn advance_history_version(&mut self, version: u16) {
        self.version = (self.version & FORMAT_FLAGS) | self.history_version().max(version);
    }
}

impl Controller {
    pub(super) fn validate_journal(
        j: &Journal,
        policy: &ControllerPolicy,
        local: NodeAddr,
    ) -> Result<(), String> {
        if !matches!(j.history_version(), 2..=6)
            || &j.policy != policy
            || j.local != local
            || j.epoch.is_empty()
            || j.epoch.len() > 64
            || j.next_funding == 0
            || j.funding.len() > MAX_CHANNELS
            || j.requested.len() > MAX_ROUTES
            || j.outgoing.len() > MAX_ROUTES
            || j.incoming.len() > MAX_ROUTES
        {
            return Err("invalid controller journal bindings".into());
        }
        Self::validate_recovery_only(j)?;
        Self::validate_history(j)?;
        Self::validate_channel_history(j)?;
        Self::validate_seller_history(j)?;
        Self::validate_renewals(j)?;
        let mut providers = HashSet::new();
        let mut sequences = HashSet::new();
        Self::validate_capital(j)?;
        for (id, f) in &j.funding {
            let sequence = channel_history::sequence(j, id)
                .or_else(|| {
                    id.strip_prefix(&format!("{}-", j.epoch))
                        .and_then(|s| s.parse::<u64>().ok())
                        .filter(|n| id == &format!("{}-{n}", j.epoch))
                })
                .filter(|n| *n > 0 && *n < j.next_funding);
            if id != &f.id
                || sequence.is_none_or(|n| !sequences.insert(n))
                || (j.history_version() < 4 && channel_history::sequence(j, id).is_some())
                || id.len() > 128
                || f.provider == local
                || (!Self::funding_released(j, f) && !providers.insert(f.provider))
                || f.capacity_sat == 0
                || f.capacity_sat > policy.channel_capacity_sat
                || f.expires_unix <= f.created_unix
                || f.expires_unix - f.created_unix != policy.channel_lifetime_secs
                || f.receiver_pubkey_hex.len() != 66
                || f.grace_msat > f.capacity_sat * 1_000
            {
                return Err("invalid funding intent".into());
            }
            if let Some(funded) = &f.funded {
                validate_channel(&funded.terms).map_err(|e| e.to_string())?;
                if funded.terms.buyer != local
                    || funded.terms.mint_url != policy.mint_url
                    || funded.terms.expires_unix != f.expires_unix
                    || funded.terms.capacity_sat != f.capacity_sat
                    || funded.terms.grace_msat != f.grace_msat
                    || funded.opening.channel_id != funded.terms.id
                    || funded.opening.balance != 0
                {
                    return Err("funded channel mismatches durable intent".into());
                }
            }
        }
        Self::validate_route_changes(j)?;
        Self::validate_watched_routes(j)?;
        let mut requested = HashSet::new();
        for (id, offer) in &j.requested {
            if id != &offer.id
                || id.is_empty()
                || id.len() > 128
                || offer.buyer != local
                || offer.provider == local
                || offer.mint_url != policy.mint_url
                || (!j.recovery_only.contains(id)
                    && !requested.insert((offer.provider, *offer.destination.node_addr())))
            {
                return Err("invalid requested route".into());
            }
        }
        let mut outgoing = HashSet::new();
        for (id, o) in &j.outgoing {
            let intent = j
                .funding
                .get(&o.funding_id)
                .ok_or("outgoing funding missing")?;
            let f = intent
                .funded
                .as_ref()
                .ok_or("outgoing channel not funded")?;
            if id != &o.purchase.contract.id
                || o.purchase.provider != o.offer.provider
                || intent.provider != o.purchase.provider
                || o.offer.buyer != local
                || o.purchase.channel != f.terms
                || (!o.retired && j.requested.get(&o.offer.id) != Some(&o.offer))
                || (o.retired
                    && !Self::changed_route_retires(j, &o.purchase)
                    && !j
                        .buyer_settlements
                        .get(&o.purchase.channel.id)
                        .is_some_and(|s| s.refunded))
                || (Self::routing_eligible(j, o)
                    && !outgoing.insert((o.purchase.provider, o.purchase.contract.destination)))
            {
                return Err("invalid outgoing agreement".into());
            }
            validate_contract(&o.purchase.contract, &o.purchase.channel)
                .map_err(|e| e.to_string())?;
            if o.purchase.contract.price != o.offer.price
                || o.purchase.contract.billing != o.offer.billing
                || o.purchase.contract.destination != *o.offer.destination.node_addr()
                || o.purchase.contract.next_hop != o.offer.next_hop
            {
                return Err("outgoing price or route changed".into());
            }
        }
        for (id, i) in &j.incoming {
            validate_channel(&i.channel).map_err(|e| e.to_string())?;
            validate_contract(&i.contract, &i.channel).map_err(|e| e.to_string())?;
            if (j.selling_stopped && i.phase != Phase::Stopped)
                || id != &i.contract.id
                || i.offer.provider != local
                || i.channel.buyer != i.offer.buyer
                || i.channel.mint_url != policy.mint_url
                || i.verified_paid_msat > i.channel.capacity_sat * 1_000
                || i.contract.price != i.offer.price
                || i.contract.billing != i.offer.billing
                || i.contract.destination != *i.offer.destination.node_addr()
                || i.contract.next_hop != i.offer.next_hop
                || (i.replacement_retired
                    && (i.replaces.is_none()
                        || i.phase == Phase::Prepared
                        || j.history.as_ref().is_none_or(|h| h.through_unix == 0)))
                || i.replaces.as_ref().is_some_and(|previous| {
                    previous == id
                        || j.incoming
                            .get(previous)
                            .map_or(!i.replacement_retired, |old| {
                                old.channel.buyer != i.channel.buyer
                                    || old.contract.destination != i.contract.destination
                                    || old.phase != Phase::Stopped
                            })
                })
            {
                return Err("invalid accepted upstream agreement".into());
            }
            if let Some(d) = &i.downstream {
                if d.buyer != local
                    || d.provider != i.offer.next_hop
                    || d.destination.node_addr() != i.offer.destination.node_addr()
                    || d.price.per_bytes != i.offer.price.per_bytes
                    || d.price.msat > i.offer.price.msat
                    || (d.price.msat == 0 && !d.billing.has_free_handshakes())
                    || d.billing != i.offer.billing
                    || (d.price.msat != 0 && d.mint_url != policy.mint_url)
                {
                    return Err("invalid onward quote".into());
                }
            } else if i.offer.next_hop != *i.offer.destination.node_addr() {
                return Err("missing onward quote".into());
            }
        }
        Ok(())
    }
}
