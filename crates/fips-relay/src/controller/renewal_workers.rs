//! Bounded renewal jobs independent of recovery waits and other neighbors.
use super::*;

#[derive(Default)]
pub(super) struct RenewalWorkers {
    jobs: BTreeMap<String, JoinHandle<Result<(), String>>>,
}

impl RenewalWorkers {
    pub(super) async fn tick(&mut self, controller: &Arc<Controller>) -> Result<(), String> {
        let mut error = None;
        let finished: Vec<_> = self
            .jobs
            .iter()
            .filter_map(|(id, job)| job.is_finished().then_some(id.clone()))
            .collect();
        for id in finished {
            if let Err(reason) = self.finish(&id).await {
                error.get_or_insert(reason);
            }
        }
        let (pending, reservation_error) = controller.pending_renewals().await?;
        error = error.or(reservation_error);
        for id in pending {
            if self.jobs.contains_key(&id) {
                continue;
            }
            if self.jobs.len() >= MAX_CHANNELS {
                error.get_or_insert_with(|| "renewal worker capacity exhausted".into());
                break;
            }
            let controller = controller.clone();
            let channel = id.clone();
            self.jobs.insert(
                id,
                tokio::spawn(async move { controller.resume_renewal(&channel).await }),
            );
        }
        error.map_or(Ok(()), Err)
    }

    async fn finish(&mut self, id: &str) -> Result<(), String> {
        // Retain the handle while awaiting it so cancellation still aborts it.
        let result = self.jobs.get_mut(id).expect("tracked renewal").await;
        self.jobs.remove(id);
        result.map_err(|error| error.to_string())?
    }

    pub(super) async fn drain(&mut self) -> Result<(), String> {
        let mut error = None;
        while let Some(id) = self.jobs.keys().next().cloned() {
            if let Err(reason) = self.finish(&id).await {
                error.get_or_insert(reason);
            }
        }
        error.map_or(Ok(()), Err)
    }
}

impl Drop for RenewalWorkers {
    fn drop(&mut self) {
        for job in self.jobs.values() {
            job.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, task::Poll};
    use tokio::sync::oneshot;

    struct OnDrop(Option<oneshot::Sender<()>>);
    impl Drop for OnDrop {
        fn drop(&mut self) {
            let _ = self.0.take().unwrap().send(());
        }
    }

    #[tokio::test]
    async fn aborting_a_drain_does_not_detach_renewal_work() {
        let (dropped, was_dropped) = oneshot::channel();
        let (started, was_started) = oneshot::channel();
        let mut workers = RenewalWorkers::default();
        workers.jobs.insert(
            "pending".into(),
            tokio::spawn(async move {
                let _guard = OnDrop(Some(dropped));
                started.send(()).unwrap();
                std::future::pending().await
            }),
        );
        was_started.await.unwrap();
        let (draining, is_draining) = oneshot::channel();
        let supervisor = tokio::spawn(async move {
            let mut drain = Box::pin(workers.drain());
            std::future::poll_fn(|cx| {
                assert!(drain.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            draining.send(()).unwrap();
            drain.await
        });
        is_draining.await.unwrap();
        supervisor.abort();
        assert!(supervisor.await.unwrap_err().is_cancelled());
        tokio::time::timeout(Duration::from_secs(1), was_dropped)
            .await
            .expect("canceled drain aborts its renewal")
            .unwrap();
    }
}
