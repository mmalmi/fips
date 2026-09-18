//! Completed channels retain lifetime obligations and one immutable expiry floor.
use super::*;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct History {
    pub channels: u64,
    pub expires_through_unix: u64,
    pub authorized_sat: u64,
    pub capacity_sat: u64,
    pub advance_msat: u64,
    pub routes: RetiredRouteEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Plan {
    pub before: History,
    pub after: History,
    channels: Vec<RetiredChannel>,
}

// Installed entries keep their existing journal representation. A genuinely
// absent local account is explicit, and still installs the same expiry fence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
enum RetiredChannel {
    Installed(PurchaseChannel),
    NeverInstalled { never_installed: ChannelTerms },
}

impl RetiredChannel {
    fn terms(&self) -> &ChannelTerms {
        match self {
            Self::Installed(c) => &c.terms,
            Self::NeverInstalled { never_installed } => never_installed,
        }
    }
}

impl Plan {
    pub(crate) fn terms(&self) -> impl Iterator<Item = (&ChannelTerms, u64)> {
        self.channels.iter().map(|c| {
            (
                c.terms(),
                match c {
                    RetiredChannel::Installed(c) => c.authorized_sat,
                    RetiredChannel::NeverInstalled { .. } => 0,
                },
            )
        })
    }

    pub(crate) fn never_installed(&self) -> impl Iterator<Item = &ChannelTerms> {
        self.channels.iter().filter_map(|c| match c {
            RetiredChannel::NeverInstalled { never_installed } => Some(never_installed),
            RetiredChannel::Installed(_) => None,
        })
    }

    pub(crate) fn validate(&self) -> Result<(), BuyerError> {
        let mut after = self.before.clone();
        let mut ids = HashSet::new();
        for entry in &self.channels {
            let terms = entry.terms();
            validate_channel(terms).map_err(|_| BuyerError::Format)?;
            if !ids.insert(&terms.id) {
                return Err(BuyerError::Format);
            }
            match entry {
                RetiredChannel::Installed(c) => {
                    let routes = c.retired.ok_or(BuyerError::Format)?;
                    if c.active
                        || !routes.valid(c.terms.expires_unix)
                        || c.authorized_sat > c.terms.capacity_sat
                        || c.authorized_sat
                            > routes
                                .submitted_msat
                                .saturating_add(c.advance_msat)
                                .div_ceil(1000)
                    {
                        return Err(BuyerError::Format);
                    }
                    after = after.added(c)?;
                }
                RetiredChannel::NeverInstalled { never_installed } => {
                    after = after.added_absent(never_installed)?;
                }
            }
        }
        if self.channels.is_empty() || after != self.after || !after.valid() || !self.before.valid()
        {
            return Err(BuyerError::Format);
        }
        Ok(())
    }
}

impl History {
    fn added_absent(&self, terms: &ChannelTerms) -> Result<Self, BuyerError> {
        // Count verified retired funding, without inventing authorization,
        // advance credit, route usage, or an accepted PurchaseChannel.
        Ok(Self {
            channels: add(self.channels, 1)?,
            expires_through_unix: self.expires_through_unix.max(terms.expires_unix),
            capacity_sat: add(self.capacity_sat, terms.capacity_sat)?,
            ..self.clone()
        })
    }

    fn added(&self, c: &PurchaseChannel) -> Result<Self, BuyerError> {
        Ok(Self {
            channels: add(self.channels, 1)?,
            expires_through_unix: self.expires_through_unix.max(c.terms.expires_unix),
            authorized_sat: add(self.authorized_sat, c.authorized_sat)?,
            capacity_sat: add(self.capacity_sat, c.terms.capacity_sat)?,
            advance_msat: add(self.advance_msat, c.advance_msat)?,
            routes: self
                .routes
                .merged(c.retired.ok_or(BuyerError::Format)?)
                .ok_or(BuyerError::Capacity)?,
        })
    }

    fn valid(&self) -> bool {
        if self.channels == 0 {
            return *self == Self::default();
        }
        self.expires_through_unix != 0
            && self.channels <= self.capacity_sat
            && self.authorized_sat <= self.capacity_sat
            && self.authorized_sat
                <= self
                    .routes
                    .submitted_msat
                    .saturating_add(self.advance_msat)
                    .div_ceil(1000)
                    .saturating_add(self.channels - 1)
            && self.routes.valid(self.expires_through_unix)
    }
}

impl State {
    pub(super) fn validate_channel_history(&self) -> Result<(), BuyerError> {
        match &self.history {
            Some(h) if self.version == 4 && h.valid() => Ok(()),
            None if self.version < 4 => Ok(()),
            _ => Err(BuyerError::Format),
        }
    }
}

impl BuyerAuthorizer {
    pub(crate) fn channel_retirement_plan(
        &self,
        ids: &[String],
        never_installed: &[ChannelTerms],
        now: u64,
    ) -> Result<Plan, BuyerError> {
        let ready = self.writer_ready.lock().map_err(|_| BuyerError::Format)?;
        if !*ready {
            return Err(DurableError::Suspended.into());
        }
        let state = self.state.lock().map_err(|_| BuyerError::Format)?;
        let mut plan = Plan {
            before: state.history.clone().unwrap_or_default(),
            after: state.history.clone().unwrap_or_default(),
            channels: Vec::new(),
        };
        for id in ids {
            let c = state.channels.get(id).ok_or(BuyerError::UnknownAgreement)?;
            if c.active
                || c.terms.expires_unix >= now
                || state.quotes.values().any(|q| q.contract.channel_id == *id)
            {
                return Err(BuyerError::InvalidAgreement);
            }
            plan.channels.push(RetiredChannel::Installed(c.clone()));
            plan.after = plan.after.added(c)?;
        }
        for terms in never_installed {
            if terms.buyer != state.local
                || terms.expires_unix >= now
                || state.channels.contains_key(&terms.id)
                || state
                    .quotes
                    .values()
                    .any(|q| q.contract.channel_id == terms.id)
            {
                return Err(BuyerError::InvalidAgreement);
            }
            plan.channels.push(RetiredChannel::NeverInstalled {
                never_installed: terms.clone(),
            });
            plan.after = plan.after.added_absent(terms)?;
        }
        plan.validate()?;
        Ok(plan)
    }

    /// Controller has durably recorded completed settlement and this exact plan.
    /// Repeating the same handoff is a read-only acknowledgment, never a reset.
    pub(crate) fn retire_channels(&self, plan: &Plan) -> Result<(), BuyerError> {
        plan.validate()?;
        let mut ready = self.writer_ready.lock().map_err(|_| BuyerError::Format)?;
        if !*ready {
            return Err(DurableError::Suspended.into());
        }
        let snapshot = {
            let mut state = self.state.lock().map_err(|_| BuyerError::Format)?;
            if state.history.as_ref() == Some(&plan.after)
                && plan.channels.iter().all(|c| {
                    !state.channels.contains_key(&c.terms().id)
                        && !state
                            .quotes
                            .values()
                            .any(|q| q.contract.channel_id == c.terms().id)
                })
            {
                return Ok(());
            }
            if state.history.clone().unwrap_or_default() != plan.before
                || plan.channels.iter().any(|c| {
                    let current_matches = match c {
                        RetiredChannel::Installed(c) => state.channels.get(&c.terms.id) == Some(c),
                        RetiredChannel::NeverInstalled { never_installed } => {
                            !state.channels.contains_key(&never_installed.id)
                        }
                    };
                    !current_matches
                        || state
                            .quotes
                            .values()
                            .any(|q| q.contract.channel_id == c.terms().id)
                })
            {
                return Err(BuyerError::InvalidAgreement);
            }
            for c in &plan.channels {
                state.channels.remove(&c.terms().id);
            }
            state.history = Some(plan.after.clone());
            state.version = 4;
            state.clone()
        };
        self.persist(&snapshot, &mut ready)
    }
}

fn add(a: u64, b: u64) -> Result<u64, BuyerError> {
    a.checked_add(b).ok_or(BuyerError::Capacity)
}
