//! Nested global and per-sender admission for inbound traversal offers.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OfferAdmissionReject {
    SenderFull,
    GlobalFull,
}

pub(super) struct OfferPermit {
    _sender: OwnedSemaphorePermit,
    _global: OwnedSemaphorePermit,
}

pub(super) struct OfferAdmission {
    global: Arc<Semaphore>,
    per_sender: Mutex<HashMap<String, Arc<Semaphore>>>,
    per_sender_limit: usize,
}

impl OfferAdmission {
    pub(super) fn new(global_limit: usize, per_sender_limit: usize) -> Self {
        Self {
            global: Arc::new(Semaphore::new(global_limit)),
            per_sender: Mutex::new(HashMap::new()),
            per_sender_limit,
        }
    }

    pub(super) fn try_admit(&self, sender_npub: &str) -> Result<OfferPermit, OfferAdmissionReject> {
        let mut senders = self.per_sender.lock().unwrap_or_else(|e| e.into_inner());
        // An outstanding owned permit holds another Arc. Entries whose map Arc
        // is the sole reference have no active offers and can be discarded.
        senders.retain(|_, semaphore| Arc::strong_count(semaphore) > 1);

        let sender = senders
            .entry(sender_npub.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(self.per_sender_limit)))
            .clone()
            .try_acquire_owned()
            .map_err(|_| OfferAdmissionReject::SenderFull)?;
        let global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| OfferAdmissionReject::GlobalFull)?;
        Ok(OfferPermit {
            _sender: sender,
            _global: global,
        })
    }

    #[cfg(test)]
    fn tracked_senders(&self) -> usize {
        self.per_sender
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_sender_cannot_take_the_global_pool() {
        let admission = OfferAdmission::new(4, 2);
        let first = admission.try_admit("attacker").unwrap();
        let second = admission.try_admit("attacker").unwrap();
        assert!(matches!(
            admission.try_admit("attacker"),
            Err(OfferAdmissionReject::SenderFull)
        ));
        let peer = admission.try_admit("peer").unwrap();
        drop((first, second, peer));
    }

    #[test]
    fn global_limit_remains_the_outer_bound() {
        let admission = OfferAdmission::new(2, 2);
        let first = admission.try_admit("one").unwrap();
        let second = admission.try_admit("two").unwrap();
        assert!(matches!(
            admission.try_admit("three"),
            Err(OfferAdmissionReject::GlobalFull)
        ));
        drop((first, second));
    }

    #[test]
    fn inactive_sender_entries_are_pruned() {
        let admission = OfferAdmission::new(2, 1);
        drop(admission.try_admit("one").unwrap());
        assert_eq!(admission.tracked_senders(), 1);
        drop(admission.try_admit("two").unwrap());
        assert_eq!(admission.tracked_senders(), 1);
    }
}
