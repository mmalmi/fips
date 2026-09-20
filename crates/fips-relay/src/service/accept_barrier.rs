//! One-shot local test fault: hold committed full Accept replies, never payments.
use crate::{
    control_transport::{IncomingRequest, MAX_RECORD_BYTES},
    controller::{ControllerRequest, ControllerResponse, Purchase},
    ledger::ChannelTerms,
};
use fips_core::{NodeAddr, PeerIdentity};
use serde::Serialize;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{Notify, mpsc, oneshot},
    task::{JoinHandle, JoinSet},
    time::Instant,
};

const CAPACITY: usize = 8;
const QUEUE: usize = 16;
const MAX_HOLD_MS: u64 = 180_000;
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Serialize)]
pub(super) struct Captured {
    offer_id: String,
    purchase: Purchase,
}

#[derive(Clone, Default, Serialize)]
pub(super) struct Snapshot {
    armed: bool,
    active: bool,
    buyer: Option<String>,
    destination: Option<String>,
    trial_max_units: Option<u64>,
    hold_ms: Option<u64>,
    terminal_reason: Option<&'static str>,
    candidate_requests: u64,
    waiting_responses: usize,
    held_responses: usize,
    captured: Option<Captured>,
    capacity_bypassed: u64,
    response_timeouts: u64,
    response_cancellations: u64,
    /// Handed to the local transport responder, not confirmed network delivery.
    forwarded_replies: u64,
    closed_responders: u64,
}

struct Selection {
    buyer: PeerIdentity,
    destination: PeerIdentity,
    trial_max_units: u64,
    deadline: Instant,
}

struct Held {
    bytes: Vec<u8>,
    respond: oneshot::Sender<Vec<u8>>,
}

#[derive(Default)]
struct State {
    selection: Option<Selection>,
    snapshot: Snapshot,
    held: Vec<Held>,
}

impl State {
    fn forward(&mut self, reply: Held) {
        if reply.respond.send(reply.bytes).is_ok() {
            self.snapshot.forwarded_replies += 1;
        } else {
            self.snapshot.closed_responders += 1;
        }
    }

    fn finish(&mut self, reason: &'static str) {
        if self.snapshot.active {
            self.snapshot.active = false;
            self.snapshot.terminal_reason = Some(reason);
        }
        for reply in std::mem::take(&mut self.held) {
            self.forward(reply);
        }
    }

    fn expire(&mut self) {
        if self.snapshot.active
            && self
                .selection
                .as_ref()
                .is_some_and(|s| Instant::now() >= s.deadline)
        {
            self.finish("expired");
        }
    }

    fn deadline(&mut self) -> Instant {
        self.expire();
        self.selection
            .as_ref()
            .filter(|_| self.snapshot.active)
            .map(|s| s.deadline)
            .unwrap_or_else(|| Instant::now() + Duration::from_millis(MAX_HOLD_MS))
    }

    fn snapshot(&mut self) -> Snapshot {
        self.expire();
        let mut result = self.snapshot.clone();
        result.held_responses = self.held.len();
        result
    }

    fn claim(
        &mut self,
        request: &IncomingRequest,
        worker_available: bool,
    ) -> Option<(String, ChannelTerms)> {
        self.expire();
        let selection = self.selection.as_ref().filter(|_| self.snapshot.active)?;
        if request.peer.node_addr() != selection.buyer.node_addr() {
            return None;
        }
        let ControllerRequest::Accept {
            offer_id, channel, ..
        } = serde_json::from_slice(&request.body).ok()?
        else {
            return None;
        };
        if channel.buyer != *selection.buyer.node_addr() {
            return None;
        }
        self.snapshot.candidate_requests += 1;
        if self.snapshot.waiting_responses + self.held.len() >= CAPACITY || !worker_available {
            self.snapshot.capacity_bypassed += 1;
            self.finish("capacity_exceeded");
            return None;
        }
        self.snapshot.waiting_responses += 1;
        Some((offer_id, channel))
    }

    fn response(
        &mut self,
        provider: NodeAddr,
        offer_id: String,
        channel: ChannelTerms,
        reply: Held,
    ) {
        self.snapshot.waiting_responses -= 1;
        self.expire();
        if !self.snapshot.active || reply.bytes.len() > MAX_RECORD_BYTES {
            self.forward(reply);
            return;
        }
        let matching = match serde_json::from_slice::<ControllerResponse>(&reply.bytes) {
            Ok(ControllerResponse::Accepted { purchase }) => {
                let selection = self.selection.as_ref().expect("active arm");
                (purchase.provider == provider
                    && purchase.channel == channel
                    && purchase.contract.channel_id == channel.id
                    && purchase.contract.destination == *selection.destination.node_addr()
                    && purchase.contract.max_units > selection.trial_max_units)
                    .then_some(*purchase)
            }
            _ => None,
        };
        let Some(purchase) = matching else {
            self.forward(reply);
            return;
        };
        if let Some(first) = &self.snapshot.captured {
            if first.offer_id != offer_id || first.purchase != purchase {
                self.finish("different_full_acceptance");
                self.forward(reply);
                return;
            }
        } else {
            self.snapshot.captured = Some(Captured { offer_id, purchase });
        }
        self.held.push(reply);
    }
}

pub(super) struct AcceptBarrier {
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
    stopping: Arc<Notify>,
    task: Option<JoinHandle<()>>,
}

impl AcceptBarrier {
    pub(super) fn interpose(
        incoming: mpsc::Receiver<IncomingRequest>,
        provider: NodeAddr,
    ) -> (mpsc::Receiver<IncomingRequest>, Self) {
        Self::start(incoming, provider, RESPONSE_TIMEOUT)
    }

    fn start(
        incoming: mpsc::Receiver<IncomingRequest>,
        provider: NodeAddr,
        response_timeout: Duration,
    ) -> (mpsc::Receiver<IncomingRequest>, Self) {
        let state = Arc::new(Mutex::new(State::default()));
        let changed = Arc::new(Notify::new());
        let stopping = Arc::new(Notify::new());
        let (forward, receive) = mpsc::channel(QUEUE);
        let task = tokio::spawn(run(
            incoming,
            forward,
            provider,
            state.clone(),
            changed.clone(),
            stopping.clone(),
            response_timeout,
        ));
        (
            receive,
            Self {
                state,
                changed,
                stopping,
                task: Some(task),
            },
        )
    }

    pub(super) fn arm(
        &self,
        buyer: &str,
        destination: &str,
        trial_max_units: u64,
        hold_ms: u64,
    ) -> Result<Snapshot, String> {
        let buyer = PeerIdentity::from_npub(buyer).map_err(|_| "invalid barrier buyer npub")?;
        let destination =
            PeerIdentity::from_npub(destination).map_err(|_| "invalid barrier destination npub")?;
        if trial_max_units == 0
            || trial_max_units == u64::MAX
            || !(1..=MAX_HOLD_MS).contains(&hold_ms)
        {
            return Err("barrier requires a positive trial cap and hold_ms in 1..=180000".into());
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| "accept barrier state poisoned")?;
        if state.snapshot.armed {
            return Err(
                "accept barrier is one-shot; prior evidence is retained until process exit".into(),
            );
        }
        state.snapshot = Snapshot {
            armed: true,
            active: true,
            buyer: Some(buyer.npub()),
            destination: Some(destination.npub()),
            trial_max_units: Some(trial_max_units),
            hold_ms: Some(hold_ms),
            ..Snapshot::default()
        };
        state.selection = Some(Selection {
            buyer,
            destination,
            trial_max_units,
            deadline: Instant::now() + Duration::from_millis(hold_ms),
        });
        self.changed.notify_one();
        Ok(state.snapshot())
    }

    pub(super) fn status(&self) -> Result<Snapshot, String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "accept barrier state poisoned")?
            .snapshot())
    }

    pub(super) fn release(&self) -> Result<Snapshot, String> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| "accept barrier state poisoned")?;
        state.expire();
        state.finish("released");
        self.changed.notify_one();
        Ok(state.snapshot())
    }

    /// Stop interception before controller shutdown; late committed replies pass through.
    pub(super) fn releasing_for_shutdown(&self) {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .finish("shutdown");
        self.changed.notify_one();
    }

    pub(super) async fn shutdown(mut self) {
        self.releasing_for_shutdown();
        self.stopping.notify_one();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for AcceptBarrier {
    fn drop(&mut self) {
        self.releasing_for_shutdown();
        self.stopping.notify_one();
        // The task owns only bounded response waiters. It drains them instead
        // of aborting handlers or inventing a response during cancellation.
    }
}

async fn run(
    mut incoming: mpsc::Receiver<IncomingRequest>,
    forward: mpsc::Sender<IncomingRequest>,
    provider: NodeAddr,
    state: Arc<Mutex<State>>,
    changed: Arc<Notify>,
    stopping: Arc<Notify>,
    response_timeout: Duration,
) {
    let mut jobs = JoinSet::new();
    'requests: loop {
        let deadline = { state.lock().unwrap_or_else(|e| e.into_inner()).deadline() };
        tokio::select! {
            _ = stopping.notified() => break,
            _ = forward.closed() => break,
            _ = changed.notified() => {},
            _ = tokio::time::sleep_until(deadline) => {},
            _ = jobs.join_next(), if !jobs.is_empty() => {},
            request = incoming.recv() => {
                let Some(mut request) = request else { break; };
                while jobs.try_join_next().is_some() {}
                let claim = state.lock().unwrap_or_else(|e| e.into_inner()).claim(&request, jobs.len() < CAPACITY);
                if let Some((offer_id, channel)) = claim {
                    let (respond, response) = oneshot::channel();
                    let original = std::mem::replace(&mut request.respond, respond);
                    let state = state.clone();
                    jobs.spawn(async move {
                        let result = tokio::time::timeout(response_timeout, response).await;
                        let mut state = state.lock().unwrap_or_else(|e| e.into_inner());
                        match result {
                            Ok(Ok(bytes)) => state.response(provider, offer_id, channel, Held { bytes, respond: original }),
                            failed => {
                                state.snapshot.waiting_responses -= 1;
                                if failed.is_err() {
                                    state.snapshot.response_timeouts += 1;
                                    state.finish("response_timeout");
                                } else {
                                    state.snapshot.response_cancellations += 1;
                                    state.finish("response_canceled");
                                }
                            }
                        }
                    });
                }
                let send = forward.send(request);
                tokio::pin!(send);
                loop {
                    let deadline = {
                        state.lock().unwrap_or_else(|e| e.into_inner()).deadline()
                    };
                    tokio::select! {
                        _ = stopping.notified() => break 'requests,
                        _ = changed.notified() => {},
                        _ = tokio::time::sleep_until(deadline) => {},
                        result = &mut send => {
                            if result.is_err() { break 'requests; }
                            break;
                        },
                    }
                }
            }
        }
    }
    state
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .finish("shutdown");
    while jobs.join_next().await.is_some() {}
}

#[cfg(test)]
mod tests;
