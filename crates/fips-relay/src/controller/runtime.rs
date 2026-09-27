//! Resume retained work and supervise control and payment workers.
use super::cadence::SCAN_INTERVAL;
use super::payments::PaymentWorkers;
use super::*;
use crate::measurements::{Operation, measure};

impl Controller {
    /// Resume durable incomplete requests. A missing reply is not permission to
    /// allocate a new funding identity or another channel. Expired/changed routes
    /// remain stopped until a separate replacement agreement is authorized.
    pub async fn resume_pending(&self) -> Result<(), String> {
        self.withdraw_expired_purchases().await?;
        self.retire_unfunded_reservations().await?;
        self.withdraw_disconnected_purchases().await?;
        self.retire_channels(false).await?;
        // Recover financial identity before applying quote expiry/pause gates.
        // Restoring original funding never authorizes route activation.
        let mut first_error = self.recover_funding().await.err();
        if let Err(error) = self.recover_expired_sales().await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.recover_expired_funding().await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.resume_route_changes().await {
            first_error.get_or_insert(error);
        }
        let snapshot = self.snapshot().await?;
        let paused_offers: HashSet<_> = snapshot
            .requested
            .values()
            .filter(|o| Self::offer_paused(&snapshot, &o.id))
            .map(|o| o.id.clone())
            .collect();
        // Native destination identities/coordinates are memory state. A router
        // restart does not necessarily restart the endpoints' FSP sessions, so
        // established traffic cannot rely on another handshake to restore them.
        // Prime bounded native discovery from retained agreements. This neither
        // authorizes a changed next hop nor creates a new financial agreement.
        let timestamp = now()?;
        let mut routes = Vec::new();
        for outgoing in snapshot.outgoing.values().filter(|o| {
            o.accepted
                && Self::routing_eligible(&snapshot, o)
                && o.purchase.contract.expires_unix > timestamp
                && !snapshot
                    .buyer_settlements
                    .contains_key(&o.purchase.channel.id)
        }) {
            if let Err(error) = self.activate_source_route(&outgoing.offer).await {
                first_error.get_or_insert(error);
            }
            routes.push((outgoing.offer.destination, None));
        }
        for incoming in snapshot
            .incoming
            .values()
            .filter(|i| i.phase == Phase::Active && i.contract.expires_unix > timestamp)
        {
            routes.push((incoming.offer.destination, Some(incoming.channel.buyer)));
        }
        let mut seen = HashSet::new();
        for (destination, previous) in routes {
            if !seen.insert((*destination.node_addr(), previous)) {
                continue;
            }
            if let Err(error) = self
                .services
                .endpoint
                .resolve_next_hop(destination, previous)
                .await
            {
                first_error.get_or_insert(error.to_string());
            }
        }
        for incoming in snapshot
            .incoming
            .into_values()
            .filter(|i| i.phase == Phase::Prepared)
        {
            let claim = {
                let mut claims = self.accepting.lock().unwrap();
                if !claims.insert(incoming.contract.id.clone()) {
                    continue;
                }
                AcceptGuard {
                    claims: &self.accepting,
                    id: incoming.contract.id.clone(),
                }
            };
            if let Err(error) = self.activate(incoming).await {
                first_error.get_or_insert(error);
            }
            drop(claim);
        }
        for offer in snapshot.requested.into_values().filter(|offer| {
            let paused = snapshot.renewals_paused
                && snapshot.renewals.values().any(|r| r.requests(&offer.id))
                || paused_offers.contains(&offer.id);
            let accepted = snapshot
                .outgoing
                .values()
                .any(|o| o.offer.id == offer.id && o.accepted);
            !(paused || accepted)
        }) {
            if let Err(error) = self.purchase_offer(offer).await {
                first_error.get_or_insert(error);
            }
        }
        if let Err(error) = self.recover_withdrawn_channels().await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.resume_settlements().await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.maintain_renewals().await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.retire_history().await {
            first_error.get_or_insert(error);
        }
        if let Err(error) = self.retire_channels(true).await {
            first_error.get_or_insert(error);
        }
        first_error.map_or(Ok(()), Err)
    }
}

pub struct ControllerTasks {
    requests: JoinHandle<mpsc::Receiver<IncomingRequest>>,
    payments: JoinHandle<()>,
    checkpoints: JoinHandle<()>,
    recovery: JoinHandle<()>,
    refresh: JoinHandle<()>,
    stopping: watch::Sender<bool>,
}
impl ControllerTasks {
    pub fn start(controller: Arc<Controller>, incoming: mpsc::Receiver<IncomingRequest>) -> Self {
        Self::start_with_cadence(controller, incoming, PaymentCadence::default())
            .expect("default payment cadence is valid")
    }

    pub fn start_with_cadence(
        controller: Arc<Controller>,
        mut incoming: mpsc::Receiver<IncomingRequest>,
        cadence: PaymentCadence,
    ) -> Result<Self, String> {
        cadence.validate()?;
        let (stopping, mut stop_requests) = watch::channel(false);
        let mut stop_payments = stop_requests.clone();
        let mut stop_checkpoints = stop_requests.clone();
        let mut stop_recovery = stop_requests.clone();
        let mut stop_refresh = stop_requests.clone();
        let handler = controller.clone();
        let requests = tokio::spawn(async move {
            let permits = Arc::new(Semaphore::new(8));
            let mut jobs = JoinSet::new();
            loop {
                tokio::select! {
                    _ = stop_requests.changed() => break,
                    request = incoming.recv() => {
                        let Some(request) = request else { break; };
                        let Ok(permit) = permits.clone().try_acquire_owned() else {
                            let _ = request.respond.send(
                                serde_json::to_vec(&ControllerResponse::Pending).expect("serializable")
                            );
                            continue;
                        };
                        let handler = handler.clone();
                        jobs.spawn(async move {
                            let _permit = permit;
                            let response = handler.handle(request.peer, &request.body).await;
                            let _ = request.respond.send(serde_json::to_vec(&response).expect("serializable"));
                        });
                    }
                    _ = jobs.join_next(), if !jobs.is_empty() => {}
                }
            }
            // Finish wallet/journal operations before returning ownership of
            // the request stream to a replacement controller.
            while jobs.join_next().await.is_some() {}
            incoming
        });
        let payer = controller.clone();
        let payments = tokio::spawn(async move {
            let mut workers = PaymentWorkers::default();
            let mut ticker = tokio::time::interval(SCAN_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop_payments.changed() => break,
                    _ = ticker.tick() => {
                        if let Err(error) = workers.tick(&payer, &cadence).await {
                            *payer.last_error.lock().unwrap() = Some(error);
                        }
                    }
                }
            }
            if let Err(error) = workers.drain().await {
                *payer.last_error.lock().unwrap() = Some(error);
            }
        });
        let checkpoint_controller = controller.clone();
        let checkpoints = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(SCAN_INTERVAL);
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop_checkpoints.changed() => break,
                    _ = ticker.tick() => {
                        let result = match checkpoint_controller.services.seller.checkpoint_due() {
                            Ok(true) => {
                                let seller = checkpoint_controller.services.seller.clone();
                                blocking(move || measure(Operation::WindowCheckpoint, || {
                                    seller.checkpoint().map(|_| ()).map_err(|e| e.to_string())
                                })).await
                            },
                            Ok(false) => Ok(()),
                            Err(error) => Err(error.to_string()),
                        };
                        if let Err(error) = result {
                            *checkpoint_controller.last_error.lock().unwrap() = Some(error);
                        }
                    }
                }
            }
        });
        let watcher = controller.clone();
        let refresh = tokio::spawn(async move {
            let mut delay = Duration::ZERO;
            loop {
                tokio::select! {
                    _ = stop_refresh.changed() => break,
                    _ = tokio::time::sleep(delay) => {
                        let scan_started = tokio::time::Instant::now();
                        if let Err(error) = watcher.refresh_watched_routes().await {
                            *watcher.last_error.lock().unwrap() = Some(error);
                        }
                        // Wake at an existing quote deadline instead of rounding
                        // five-second refreshes up to the next two-second tick.
                        delay = watcher.next_refresh_delay(scan_started);
                    }
                }
            }
        });
        let recovery = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(Duration::from_secs(2));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! {
                    _ = stop_recovery.changed() => break,
                    _ = ticker.tick() => {
                        if let Err(error) = controller.resume_pending().await {
                            *controller.last_error.lock().unwrap() = Some(error);
                        }
                    }
                }
            }
        });
        Ok(Self {
            requests,
            payments,
            checkpoints,
            recovery,
            refresh,
            stopping,
        })
    }
    /// Drain in-flight work and return the live transport's request stream for
    /// a controller reload. Dropping tasks instead is an abrupt cancellation.
    pub async fn stop(mut self) -> Option<mpsc::Receiver<IncomingRequest>> {
        let _ = self.stopping.send(true);
        let incoming = (&mut self.requests).await.ok();
        let _ = (&mut self.payments).await;
        let _ = (&mut self.checkpoints).await;
        let _ = (&mut self.recovery).await;
        let _ = (&mut self.refresh).await;
        incoming
    }
}
impl Drop for ControllerTasks {
    fn drop(&mut self) {
        self.requests.abort();
        self.payments.abort();
        self.checkpoints.abort();
        self.recovery.abort();
        self.refresh.abort();
    }
}
