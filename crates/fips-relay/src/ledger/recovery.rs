//! Validate and recover durable seller accounting snapshots.
use super::*;

impl RelayLedger {
    pub fn snapshot(&self) -> Snapshot {
        let state = self.state.lock().unwrap();
        Snapshot {
            version: 4,
            limits: self.limits,
            next_token: state.next_token,
            channels: state
                .channels
                .values()
                .map(|c| ChannelSnapshot {
                    terms: c.terms.clone(),
                    usage: c.usage,
                    active: c.active,
                })
                .collect(),
            accounts: state
                .accounts
                .values()
                .map(|a| AccountSnapshot {
                    contract: a.contract.clone(),
                    usage: a.usage,
                    active: a.active,
                    attempts: a.attempts.iter().map(|(k, v)| (*k, v.clone())).collect(),
                    completed: a.completed,
                })
                .collect(),
        }
    }

    /// Retain all evidence but activate no traffic. A snapshot alone does not
    /// establish which sends occurred after its last durable checkpoint.
    pub fn restore(snapshot: Snapshot) -> Result<Self, LedgerError> {
        if !matches!(snapshot.version, 3 | 4)
            || snapshot.channels.len() > snapshot.limits.max_channels
            || snapshot.accounts.len() > snapshot.limits.max_contracts
        {
            return Err(LedgerError::InvalidSnapshot);
        }
        let mut state = State {
            next_token: snapshot.next_token,
            ..State::default()
        };
        let mut expected_channels = BTreeMap::new();
        for saved in snapshot.channels {
            let cap = validate_channel(&saved.terms).map_err(|_| LedgerError::InvalidSnapshot)?;
            if saved.usage.paid_msat > cap
                || saved.usage.reserved_msat > cap
                || saved.usage.reserved_msat
                    > saved.usage.paid_msat.saturating_add(saved.terms.grace_msat)
                || saved.usage.lost_msat > saved.usage.reserved_msat
                || state.channels.contains_key(&saved.terms.id)
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            expected_channels.insert(saved.terms.id.clone(), saved.usage);
            state.channels.insert(
                saved.terms.id.clone(),
                Channel {
                    terms: saved.terms,
                    usage: ChannelUsage {
                        paid_msat: saved.usage.paid_msat,
                        reserved_msat: saved.usage.lost_msat,
                        lost_msat: saved.usage.lost_msat,
                        ..ChannelUsage::default()
                    },
                    active: false,
                },
            );
        }
        let mut tokens = std::collections::BTreeSet::new();
        let mut outstanding = 0usize;
        for saved in snapshot.accounts {
            let legacy = saved.contract.billing.is_legacy();
            if state.accounts.contains_key(&saved.contract.id)
                || (legacy && saved.attempts.len() > snapshot.limits.max_packets_per_contract)
                || (snapshot.version == 3 && !legacy)
                || saved
                    .completed
                    .submitted_units
                    .checked_add(saved.completed.unconfirmed_units)
                    != Some(saved.completed.reserved_units)
                || (legacy && saved.completed.reserved_units != 0)
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            let channel = state
                .channels
                .get_mut(&saved.contract.channel_id)
                .ok_or(LedgerError::InvalidSnapshot)?;
            validate_contract(&saved.contract, &channel.terms)
                .map_err(|_| LedgerError::InvalidSnapshot)?;
            let mut reserved = saved.completed.reserved_units;
            let mut submitted = saved.completed.submitted_units;
            let mut unconfirmed = saved.completed.unconfirmed_units;
            let mut previously_unconfirmed = saved.completed.unconfirmed_units;
            let mut attempts = BTreeMap::new();
            for (digest, mut attempt) in saved.attempts {
                if attempt.token == 0
                    || attempt.token > snapshot.next_token
                    || !tokens.insert(attempt.token)
                    || attempt.units == 0
                    || attempts.contains_key(&digest)
                    || (!legacy
                        && (digest != attempt_key(attempt.token)
                            || attempt.state != AttemptState::Pending))
                {
                    return Err(LedgerError::InvalidSnapshot);
                }
                reserved = reserved
                    .checked_add(attempt.units)
                    .ok_or(LedgerError::InvalidSnapshot)?;
                if legacy && !state.seen.insert((channel.terms.buyer, digest)) {
                    return Err(LedgerError::InvalidSnapshot);
                }
                if attempt.state == AttemptState::Pending {
                    outstanding = outstanding
                        .checked_add(1)
                        .ok_or(LedgerError::InvalidSnapshot)?;
                    if outstanding > snapshot.limits.max_pending {
                        return Err(LedgerError::InvalidSnapshot);
                    }
                }
                match attempt.state {
                    AttemptState::Submitted => submitted += attempt.units,
                    AttemptState::Pending => {
                        unconfirmed += attempt.units;
                        attempt.state = AttemptState::Unconfirmed;
                    }
                    AttemptState::Unconfirmed => {
                        unconfirmed += attempt.units;
                        previously_unconfirmed += attempt.units;
                    }
                }
                if legacy {
                    attempts.insert(digest, attempt);
                }
            }
            if reserved != saved.usage.reserved_units
                || submitted != saved.usage.submitted_units
                || saved.usage.unconfirmed_units != previously_unconfirmed
                || reserved > saved.contract.max_units
            {
                return Err(LedgerError::InvalidSnapshot);
            }
            let reserved_cost = saved
                .contract
                .price
                .amount_due_msat(reserved)
                .ok_or(LedgerError::InvalidSnapshot)?;
            let submitted_cost = saved
                .contract
                .price
                .amount_due_msat(submitted)
                .ok_or(LedgerError::InvalidSnapshot)?;
            channel.usage.reserved_msat = channel
                .usage
                .reserved_msat
                .checked_add(reserved_cost)
                .ok_or(LedgerError::InvalidSnapshot)?;
            channel.usage.submitted_msat = channel
                .usage
                .submitted_msat
                .checked_add(submitted_cost)
                .ok_or(LedgerError::InvalidSnapshot)?;
            state.accounts.insert(
                saved.contract.id.clone(),
                Account {
                    contract: saved.contract,
                    usage: Usage {
                        unconfirmed_units: unconfirmed,
                        ..saved.usage
                    },
                    completed: if legacy {
                        Usage::default()
                    } else {
                        Usage {
                            reserved_units: reserved,
                            submitted_units: submitted,
                            unconfirmed_units: unconfirmed,
                        }
                    },
                    attempts,
                    active: false,
                },
            );
        }
        for (id, expected) in expected_channels {
            if state.channels[&id].usage != expected {
                return Err(LedgerError::InvalidSnapshot);
            }
        }
        Ok(Self {
            limits: snapshot.limits,
            state: Mutex::new(state),
        })
    }
}
