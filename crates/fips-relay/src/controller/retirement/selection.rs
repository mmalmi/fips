//! Select complete reference groups and closed accounting expiry prefixes.
use super::*;

pub(super) fn select(
    j: &Journal,
    buyer: &BuyerAuthorizer,
    seller: &DurableRelay,
    timestamp: u64,
) -> Result<Option<Retirement>, String> {
    let mut outgoing: BTreeSet<_> = j
        .outgoing
        .iter()
        .filter(|(_, o)| {
            !j.watched_routes
                .values()
                .any(|watch| watch.selected_trial.as_ref() == Some(&o.purchase.contract.id))
                && closed_purchase(j, o)
                && o.offer.expires_unix <= timestamp
                && !o.purchase.contract.billing.is_legacy()
        })
        .map(|(id, _)| id.clone())
        .collect();
    let mut incoming: BTreeSet<_> = j
        .incoming
        .iter()
        .filter(|(_, i)| {
            i.phase == Phase::Stopped
                && i.offer.expires_unix <= timestamp
                && !i.contract.billing.is_legacy()
        })
        .map(|(id, _)| id.clone())
        .collect();
    loop {
        let before = outgoing.len() + incoming.len();
        for c in j.route_changes.values() {
            if !c.prepared
                || !c.is_finished(j)
                || !c.previous.iter().all(|p| outgoing.contains(&p.contract.id))
            {
                for p in &c.previous {
                    outgoing.remove(&p.contract.id);
                }
                for (id, o) in &j.outgoing {
                    if o.offer == c.offer {
                        outgoing.remove(id);
                    }
                }
            }
        }
        for r in j.renewals.values() {
            if !r.is_completed()
                || !r
                    .previous
                    .iter()
                    .all(|o| outgoing.contains(&o.purchase.contract.id))
            {
                for o in &r.previous {
                    outgoing.remove(&o.purchase.contract.id);
                }
                for (id, o) in &j.outgoing {
                    if r.requests(&o.offer.id) {
                        outgoing.remove(id);
                    }
                }
            }
        }
        for i in j.incoming.values().filter(|i| i.phase == Phase::Prepared) {
            if let Some(id) = &i.replaces {
                incoming.remove(id);
            }
        }
        let buying = prefixes(
            j.outgoing.iter().map(|(id, o)| (id, &o.purchase.contract)),
            &mut outgoing,
            |id, cutoff| buyer.retirement_plan(id, cutoff).ok(),
        );
        let selling = prefixes(
            j.incoming.iter().map(|(id, i)| (id, &i.contract)),
            &mut incoming,
            |id, cutoff| seller.retirement_plan(id, cutoff).ok(),
        );
        if outgoing.len() + incoming.len() == before {
            let plan = Retirement {
                through_unix: timestamp,
                buyer: buying,
                seller: selling,
            };
            if plan.count() == 0 {
                return Ok(None);
            }
            plan.validate(j)?;
            return Ok(Some(plan));
        }
    }
}

fn prefixes<'a>(
    contracts: impl Iterator<Item = (&'a String, &'a Contract)>,
    selected: &mut BTreeSet<String>,
    preview: impl Fn(&str, u64) -> Option<RouteRetirementPlan>,
) -> Vec<RouteRetirementPlan> {
    let contracts: Vec<_> = contracts.collect();
    let channels: BTreeSet<_> = contracts
        .iter()
        .filter(|(id, _)| selected.contains(*id))
        .map(|(_, c)| &c.channel_id)
        .collect();
    let mut plans = Vec::new();
    for channel in channels {
        let blocked = contracts
            .iter()
            .filter(|(id, c)| c.channel_id == *channel && !selected.contains(*id))
            .map(|(_, c)| c.expires_unix)
            .min();
        let cutoff = contracts
            .iter()
            .filter(|(id, c)| {
                c.channel_id == *channel
                    && selected.contains(*id)
                    && blocked.is_none_or(|b| c.expires_unix < b)
            })
            .map(|(_, c)| c.expires_unix)
            .max();
        let plan = cutoff
            .and_then(|cutoff| preview(channel, cutoff))
            .filter(|p| {
                !p.contracts.is_empty()
                    && p.contracts.iter().all(|c| {
                        selected.contains(&c.id)
                            && contracts
                                .iter()
                                .any(|(id, saved)| **id == c.id && **saved == *c)
                    })
                    && contracts
                        .iter()
                        .filter(|(_, c)| {
                            c.channel_id == *channel && c.expires_unix <= p.through_unix
                        })
                        .count()
                        == p.contracts.len()
            });
        selected.retain(|id| {
            contracts
                .iter()
                .find(|(key, _)| *key == id)
                .is_none_or(|(_, c)| {
                    c.channel_id != *channel
                        || plan
                            .as_ref()
                            .is_some_and(|p| p.contracts.iter().any(|c| &c.id == id))
                })
        });
        if let Some(plan) = plan {
            plans.push(plan);
        }
    }
    plans
}
