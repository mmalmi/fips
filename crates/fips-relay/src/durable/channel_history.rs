use super::*;
use crate::ledger::channel_history::Plan;

impl DurableRelay {
    pub(crate) fn channel_retirement_plan(
        &self,
        ids: &[String],
        now: u64,
    ) -> Result<Plan, DurableError> {
        let _writer = self.writer.lock().map_err(|_| DurableError::Suspended)?;
        if !self
            .windows
            .read()
            .map_err(|_| DurableError::Suspended)?
            .ready
        {
            return Err(DurableError::Suspended);
        }
        self.ledger
            .channel_retirement_plan(ids, now)
            .map_err(Into::into)
    }

    pub(crate) fn retire_channels(&self, plan: &Plan) -> Result<(), DurableError> {
        let _writer = self.writer.lock().map_err(|_| DurableError::Suspended)?;
        if !self
            .windows
            .read()
            .map_err(|_| DurableError::Suspended)?
            .ready
        {
            return Err(DurableError::Suspended);
        }
        if self.ledger.retire_channels(plan)? {
            self.persist(true)?;
        }
        Ok(())
    }
}
