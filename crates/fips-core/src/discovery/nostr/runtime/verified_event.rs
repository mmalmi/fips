use super::*;

#[derive(Debug)]
pub(in crate::discovery::nostr) struct VerifiedEvent<'a> {
    event: &'a Event,
}

impl<'a> VerifiedEvent<'a> {
    pub(super) fn as_event(&self) -> &'a Event {
        self.event
    }

    pub(super) fn pubkey(&self) -> &'a PublicKey {
        &self.event.pubkey
    }
}

impl<'a> TryFrom<&'a Event> for VerifiedEvent<'a> {
    type Error = BootstrapError;

    fn try_from(event: &'a Event) -> Result<Self, Self::Error> {
        event
            .verify()
            .map_err(|e| BootstrapError::InvalidAdvert(format!("invalid event signature: {e}")))?;
        Ok(Self { event })
    }
}
