//! Retire known stopped agreements without creating forwarding accounts.
use super::*;

impl Retirement {
    pub(super) fn uninstalled_on(&self, channel: &str) -> Vec<Contract> {
        self.never_installed
            .iter()
            .filter(|c| c.channel_id == channel)
            .cloned()
            .collect()
    }

    pub(super) fn validate_uninstalled(&self, j: &Journal) -> Result<(), String> {
        if self.never_installed.len() > MAX_ROUTES
            || self
                .never_installed
                .iter()
                .map(|c| &c.id)
                .collect::<HashSet<_>>()
                .len()
                != self.never_installed.len()
            || self.never_installed.iter().any(|c| {
                j.incoming
                    .get(&c.id)
                    .is_none_or(|i| i.phase != Phase::Stopped || i.contract != *c)
                    || !self
                        .seller
                        .iter()
                        .any(|p| p.channel == c.channel_id && p.contracts.contains(c))
            })
        {
            return Err("invalid uninstalled incoming retirement".into());
        }
        Ok(())
    }
}

impl Store {
    /// Serialize the final forwarding installation with StopRoute and history
    /// retirement. A previously checked async worker cannot reinstall a stopped
    /// or removed agreement, including after a clock rollback.
    pub(in crate::controller) fn install_incoming_contract(
        &mut self,
        seller: &DurableRelay,
        expected: &Incoming,
        timestamp: u64,
    ) -> Result<(), String> {
        self.ensure_ready()?;
        if expected.phase != Phase::Prepared
            || self.journal.incoming.get(&expected.contract.id) != Some(expected)
            || expected.contract.expires_unix <= timestamp
            || self.journal.selling_stopped
            || self
                .journal
                .seller_settlements
                .contains_key(&expected.channel.id)
            || Controller::retired_offer(&self.journal, &expected.offer)
        {
            return Err("prepared route expired, stopped or changed".into());
        }
        seller
            .add_contract(expected.contract.clone())
            .map_err(|e| e.to_string())?;
        self.change(|j| {
            j.incoming.get_mut(&expected.contract.id).unwrap().phase = Phase::Active;
            Ok(())
        })
    }
}
