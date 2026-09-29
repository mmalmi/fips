//! One owned admission check per bounded pending request or TCP exchange.
use super::{ControlAdmission, PeerIdentity, admission::AdmissionPermit};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::Arc,
    task::Poll,
};

type PendingCheck = Pin<Box<dyn Future<Output = Result<AdmissionPermit, String>> + Send>>;

pub(super) struct AdmissionCheck {
    permit: Option<AdmissionPermit>,
    pending: Option<PendingCheck>,
}

impl AdmissionCheck {
    pub(super) fn start(
        admission: Arc<ControlAdmission>,
        peer: PeerIdentity,
        outbound: bool,
    ) -> Self {
        Self {
            permit: None,
            pending: Some(Box::pin(
                async move { admission.admit(peer, outbound).await },
            )),
        }
    }

    /// Poll completion without waiting for the native node's status loop.
    pub(super) async fn ready(&mut self) -> Result<bool, String> {
        if self.permit.is_some() {
            return Ok(true);
        }
        let pending = self.pending.as_mut().expect("unfinished admission check");
        let Poll::Ready(result) = poll_fn(|cx| Poll::Ready(pending.as_mut().poll(cx))).await else {
            return Ok(false);
        };
        self.pending = None;
        self.permit = Some(result?);
        Ok(true)
    }

    /// Retain the original permit and its resource charge during revalidation.
    pub(super) fn recheck(&mut self) {
        assert!(self.pending.is_none());
        let permit = self.permit.take().expect("completed admission check");
        self.pending = Some(Box::pin(async move {
            permit.recheck().await?;
            Ok(permit)
        }));
    }
}
