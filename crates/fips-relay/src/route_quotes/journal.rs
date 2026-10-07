//! Retain issued quotes before replying, without granting forwarding authority.
use super::*;
use crate::durable::{acquire_owner, write_private_journal};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

const MAX_BYTES: u64 = 1024 * 1024;
const FILE: &str = "offers.json";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    version: u16,
    binding: serde_json::Value,
    pending: BTreeMap<String, StoredOffer>,
}

pub(super) struct OfferJournal {
    directory: PathBuf,
    binding: serde_json::Value,
    _owner: File,
}

fn binding(local: NodeAddr, policy: &QuotePolicy) -> serde_json::Value {
    let fees: BTreeMap<_, _> = policy
        .destination_fees
        .iter()
        .map(|(address, fee)| (address.to_string(), *fee))
        .collect();
    serde_json::json!({
        "local": local.to_string(), "destination_fees": fees,
        "billing": policy.billing, "mint_url": policy.mint_url,
        "receiver_pubkey_hex": policy.receiver_pubkey_hex,
        "fee_msat_per_kib": policy.fee_msat_per_kib,
        "max_rate_msat_per_kib": policy.max_rate_msat_per_kib,
        "lifetime_secs": policy.lifetime_secs, "max_units": policy.max_units,
        "capacity_sat": policy.capacity_sat, "grace_msat": policy.grace_msat,
    })
}

impl OfferJournal {
    fn open(
        directory: &Path,
        local: NodeAddr,
        policy: &QuotePolicy,
        create: bool,
    ) -> Result<(Self, BTreeMap<String, StoredOffer>), String> {
        let journal = Self {
            directory: directory.into(),
            binding: binding(local, policy),
            _owner: acquire_owner(directory).map_err(|e| e.to_string())?,
        };
        if create {
            if directory
                .join(FILE)
                .try_exists()
                .map_err(|e| e.to_string())?
            {
                return Err("quote journal already initialized".into());
            }
            journal.write(&BTreeMap::new())?;
            return Ok((journal, BTreeMap::new()));
        }
        let file = File::open(directory.join(FILE)).map_err(|e| e.to_string())?;
        if file.metadata().map_err(|e| e.to_string())?.len() > MAX_BYTES {
            return Err("quote journal too large".into());
        }
        let mut bytes = Vec::new();
        file.take(MAX_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("quote journal too large".into());
        }
        let mut saved: Saved =
            serde_json::from_slice(&bytes).map_err(|_| "invalid quote journal")?;
        if saved.version != 1
            || saved.binding != journal.binding
            || saved.pending.len() > MAX_OFFERS
        {
            return Err("quote journal identity, policy or capacity changed".into());
        }
        let now = unix_now()?;
        saved
            .pending
            .retain(|_, entry| entry.offer.expires_unix > now);
        let mut buyers = BTreeMap::new();
        for (id, entry) in &saved.pending {
            let count = buyers.entry(entry.offer.buyer).or_insert(0);
            *count += 1;
            if id != &entry.offer.id || *count > MAX_OFFERS_PER_BUYER {
                return Err("invalid retained quote identity or buyer capacity".into());
            }
            validate_saved(policy, local, entry, now)?;
        }
        Ok((journal, saved.pending))
    }

    fn write(&self, pending: &BTreeMap<String, StoredOffer>) -> Result<(), String> {
        let bytes = serde_json::to_vec(&Saved {
            version: 1,
            binding: self.binding.clone(),
            pending: pending.clone(),
        })
        .map_err(|e| e.to_string())?;
        if bytes.len() as u64 > MAX_BYTES {
            return Err("quote journal capacity".into());
        }
        write_private_journal(&self.directory, FILE, &bytes).map_err(|e| e.to_string())
    }
}

fn validate_saved(
    policy: &QuotePolicy,
    local: NodeAddr,
    entry: &StoredOffer,
    now: u64,
) -> Result<(), String> {
    let offer = &entry.offer;
    let mut request = QuoteRequest {
        destination: offer.destination,
        ancestors: vec![offer.buyer],
        deadline_unix: now.saturating_add(MAX_REQUEST_SECONDS),
        reuse_unchanged: false,
        requested_max_units: offer.trial.then_some(offer.max_units),
    };
    validation::validate_offer_address(policy, offer.buyer, offer, local, &request, now)?;
    let mut path = vec![local];
    if let Some(downstream) = &entry.downstream {
        request.ancestors.push(local);
        validation::validate_offer_address(
            policy,
            local,
            downstream,
            offer.next_hop,
            &request,
            now,
        )?;
        path.extend_from_slice(&downstream.path);
        if offer.expires_unix > downstream.expires_unix || offer.max_units > downstream.max_units {
            return Err("retained quote exceeds its downstream agreement".into());
        }
    } else {
        path.push(*offer.destination.node_addr());
    }
    let rate = policy
        .destination_fees
        .get(offer.destination.node_addr())
        .copied()
        .unwrap_or(policy.fee_msat_per_kib)
        .checked_add(entry.downstream.as_ref().map_or(0, |d| d.price.msat));
    if offer.path != path
        || Some(offer.price.msat) != rate
        || offer.mint_url != policy.mint_url
        || offer.receiver_pubkey_hex != policy.receiver_pubkey_hex
        || offer.capacity_sat != policy.capacity_sat
        || offer.grace_msat != policy.grace_msat
        || offer.max_units > policy.max_units
    {
        return Err("retained quote differs from its provider policy".into());
    }
    Ok(())
}

impl Offers {
    pub(super) fn ensure_ready(&self) -> Result<(), String> {
        if self.ready {
            Ok(())
        } else {
            Err("quote writer suspended; restart to recover".into())
        }
    }

    fn commit(&mut self, pending: BTreeMap<String, StoredOffer>) -> Result<(), String> {
        self.ensure_ready()?;
        if let Some(journal) = &self.journal
            && let Err(error) = journal.write(&pending)
        {
            // The rename may already be durable. Never reuse an uncertain ID
            // or expose an uncommitted offer from this process.
            self.ready = false;
            return Err(error);
        }
        self.pending = pending;
        Ok(())
    }

    pub(super) fn retire(&mut self, id: &str) -> Result<(), String> {
        self.ensure_ready()?;
        if self.pending.contains_key(id) {
            let mut pending = self.pending.clone();
            pending.remove(id);
            self.commit(pending)?;
        }
        Ok(())
    }
}

impl RouteQuotes {
    /// Call before starting the quote server. Create only during explicit profile
    /// initialization; loading never replaces a missing or corrupt journal.
    pub fn with_offer_journal(self, directory: &Path, create: bool) -> Result<Self, String> {
        let (journal, pending) =
            OfferJournal::open(directory, *self.endpoint.node_addr(), &self.policy, create)?;
        {
            let mut offers = self.offers.lock().map_err(|_| "quote state poisoned")?;
            if offers.journal.is_some() || !offers.pending.is_empty() {
                return Err("quote retention must precede issuance".into());
            }
            offers.journal = Some(journal);
            offers.pending = pending;
        }
        // Each boot keeps old issued IDs but uses a fresh epoch for new offers.
        // This also avoids reusing IDs allocated before a failed reply.
        Ok(self)
    }

    pub(super) async fn publish(
        &self,
        mut entry: StoredOffer,
        reuse: bool,
    ) -> Result<RouteOffer, String> {
        let (offers, free, lifetime) = (
            self.offers.clone(),
            self.free.clone(),
            self.policy.lifetime_secs,
        );
        tokio::task::spawn_blocking(move || {
            let now = unix_now()?;
            let mut offers = offers.lock().map_err(|_| "quote state poisoned")?;
            offers.ensure_ready()?;
            offers.pending.retain(|_, e| e.offer.expires_unix > now);
            let offered = &entry.offer;
            if offered.expires_unix <= now {
                return Err("quote expired before publication".into());
            }
            if reuse {
                let until = now.saturating_add((lifetime / 4).max(1));
                if let Some(saved) = offers.pending.values().find(|s| {
                    let old = &s.offer;
                    free.can_reuse_offer(old)
                        && old.buyer == offered.buyer
                        && old.destination == offered.destination
                        && old.path == offered.path
                        && old.price == offered.price
                        && old.max_units == offered.max_units
                        && old.trial == offered.trial
                        && old.expires_unix > until
                        && old.expires_unix <= offered.expires_unix
                }) {
                    free.offer(&saved.offer)?;
                    return Ok(saved.offer.clone());
                }
            }
            if offers.pending.len() >= MAX_OFFERS
                || offers
                    .pending
                    .values()
                    .filter(|s| s.offer.buyer == offered.buyer)
                    .count()
                    >= MAX_OFFERS_PER_BUYER
            {
                return Err("offer capacity".into());
            }
            entry.offer.id = format!("{}-{}", offers.epoch, offers.next_id);
            offers.next_id = offers
                .next_id
                .checked_add(1)
                .ok_or("quote sequence exhausted")?;
            let mut pending = offers.pending.clone();
            pending.insert(entry.offer.id.clone(), entry.clone());
            offers.commit(pending)?;
            free.offer(&entry.offer)?;
            Ok(entry.offer)
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

#[cfg(test)]
mod tests;
