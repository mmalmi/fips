use super::*;
use std::collections::VecDeque;

const VERIFICATION_CACHE_CAPACITY: usize = 512;

/// Retain only successful signature proofs, not caller-supplied event bodies.
#[derive(Default)]
pub(super) struct EventVerificationCache {
    signatures: HashMap<EventId, [u8; 64]>,
    order: VecDeque<EventId>,
}

impl EventVerificationCache {
    fn verify<'a>(&mut self, event: &'a Event) -> Result<VerifiedEvent<'a>, BootstrapError> {
        let signature = event.sig.serialize();
        if self.signatures.get(&event.id) == Some(&signature) {
            // A supplied ID is not proof of the author, tags, or content. A
            // replay can reuse the signature check only after binding all of
            // those fields to the previously verified ID again.
            if !event.verify_id() {
                return Err(BootstrapError::InvalidAdvert("invalid event ID".into()));
            }
            return Ok(VerifiedEvent { event });
        }

        let verified = VerifiedEvent::try_from(event)?;
        if !self.signatures.contains_key(&event.id) {
            if self.order.len() == VERIFICATION_CACHE_CAPACITY
                && let Some(oldest) = self.order.pop_front()
            {
                self.signatures.remove(&oldest);
            }
            self.order.push_back(event.id);
        }
        self.signatures.insert(event.id, signature);
        Ok(verified)
    }
}

impl NostrDiscovery {
    pub(super) fn verify_event<'a>(
        &self,
        event: &'a Event,
    ) -> Result<VerifiedEvent<'a>, BootstrapError> {
        self.verified_events
            .lock()
            .map_err(|_| {
                BootstrapError::InvalidAdvert("event verification cache unavailable".into())
            })?
            .verify(event)
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    fn event(keys: &nostr::Keys, content: &str) -> Event {
        EventBuilder::new(Kind::Custom(ADVERT_KIND), content)
            .sign_with_keys(keys)
            .unwrap()
    }

    #[test]
    fn cached_signature_still_authenticates_every_event_field() {
        let keys = nostr::Keys::generate();
        let original = event(&keys, "original");
        let mut cache = EventVerificationCache::default();
        cache.verify(&original).unwrap();
        cache.verify(&original).unwrap();

        let mut modified = original.clone();
        modified.content.push('!');
        assert!(cache.verify(&modified).is_err());
        modified = original.clone();
        modified.pubkey = nostr::Keys::generate().public_key();
        assert!(cache.verify(&modified).is_err());
        modified = original.clone();
        modified.created_at = Timestamp::from(original.created_at.as_secs() + 1);
        assert!(cache.verify(&modified).is_err());
        modified = original.clone();
        modified.tags = nostr::Tags::from_list(vec![Tag::identifier("modified")]);
        assert!(cache.verify(&modified).is_err());
        modified = original.clone();
        modified.kind = Kind::TextNote;
        assert!(cache.verify(&modified).is_err());
        modified = original.clone();
        modified.sig = event(&keys, "different").sig;
        assert!(cache.verify(&modified).is_err());

        assert_eq!(cache.signatures.len(), 1);
        cache.verify(&original).unwrap();
    }

    #[test]
    fn invalid_event_cannot_seed_a_verification_proof() {
        let keys = nostr::Keys::generate();
        let valid = event(&keys, "valid");
        let mut invalid = valid.clone();
        invalid.content.push('!');
        let mut cache = EventVerificationCache::default();
        assert!(cache.verify(&invalid).is_err());
        assert!(cache.signatures.is_empty() && cache.order.is_empty());
        cache.verify(&valid).unwrap();
        assert!(cache.verify(&invalid).is_err());
    }

    #[test]
    fn verification_proofs_are_bounded_and_evicted_events_are_reverified() {
        let keys = nostr::Keys::generate();
        let first = event(&keys, "first");
        let mut cache = EventVerificationCache::default();
        cache.verify(&first).unwrap();
        for index in 0..VERIFICATION_CACHE_CAPACITY {
            cache.verify(&event(&keys, &index.to_string())).unwrap();
        }
        assert_eq!(cache.signatures.len(), VERIFICATION_CACHE_CAPACITY);
        assert_eq!(cache.order.len(), VERIFICATION_CACHE_CAPACITY);
        assert!(!cache.signatures.contains_key(&first.id));
        let mut invalid = first.clone();
        invalid.sig = event(&keys, "wrong signature").sig;
        assert!(cache.verify(&invalid).is_err());
        assert!(!cache.signatures.contains_key(&first.id));
        cache.verify(&first).unwrap();
        assert_eq!(cache.signatures.len(), VERIFICATION_CACHE_CAPACITY);
    }
}
