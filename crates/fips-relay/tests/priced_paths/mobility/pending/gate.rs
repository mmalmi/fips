//! Hold real successful responses after the production handler commits.
use super::*;
use fips_relay::control_transport::IncomingRequest;
use fips_relay::controller::{ControllerRequest, ControllerResponse, SettlementReport};
use tokio::sync::{mpsc, oneshot, watch};

#[derive(Clone, Debug)]
pub(super) struct Accepted {
    pub(super) offer_id: String,
    pub(super) purchase: Purchase,
}

#[derive(Clone, Copy, Debug, Default)]
pub(super) struct Released {
    pub(super) attempted: usize,
    pub(super) delivered: usize,
    pub(super) canceled: usize,
}

enum Command {
    Release(oneshot::Sender<Released>),
    DiscardSettled(oneshot::Sender<usize>),
    Stop,
}

struct Held {
    response: Vec<u8>,
    respond: oneshot::Sender<Vec<u8>>,
}

pub(crate) struct ResponseGate {
    captured: watch::Receiver<Option<Accepted>>,
    settled: watch::Receiver<Option<SettlementReport>>,
    hold_settlement: bool,
    commands: mpsc::Sender<Command>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl ResponseGate {
    pub(super) fn holds_settlement(&self) -> bool {
        self.hold_settlement
    }

    pub(super) async fn settled(&mut self) -> SettlementReport {
        tokio::time::timeout(Duration::from_secs(50), async {
            loop {
                if let Some(report) = self.settled.borrow().clone() {
                    return report;
                }
                self.settled
                    .changed()
                    .await
                    .expect("settlement response gate stopped before capture");
            }
        })
        .await
        .expect("automatic settlement must reach the held response boundary")
    }

    pub(super) async fn discard_settled(&self) -> usize {
        let (send, receive) = oneshot::channel();
        self.commands
            .send(Command::DiscardSettled(send))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(12), receive)
            .await
            .unwrap()
            .unwrap()
    }

    pub(super) async fn accepted(&mut self) -> Accepted {
        self.try_accepted()
            .await
            .expect("provider must return a real successful Accept before the reply-loss fault")
    }

    pub(super) async fn try_accepted(&mut self) -> Result<Accepted, String> {
        tokio::time::timeout(Duration::from_secs(50), async {
            loop {
                if let Some(accepted) = self.captured.borrow().clone() {
                    return Ok(accepted);
                }
                self.captured
                    .changed()
                    .await
                    .map_err(|_| "acceptance response gate stopped before capture".to_string())?;
            }
        })
        .await
        .map_err(|_| "no successful Accept captured within 50 seconds".to_string())?
    }

    pub(super) async fn release(&self) -> Released {
        let (send, receive) = oneshot::channel();
        self.commands.send(Command::Release(send)).await.unwrap();
        tokio::time::timeout(Duration::from_secs(12), receive)
            .await
            .expect("held acceptance response release deadline")
            .unwrap()
    }

    pub(crate) async fn stop(mut self) {
        self.commands.send(Command::Stop).await.unwrap();
        tokio::time::timeout(Duration::from_secs(12), self.task.as_mut().unwrap())
            .await
            .expect("acceptance response gate shutdown deadline")
            .unwrap();
        self.task.take();
    }
}

impl Drop for ResponseGate {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn release(held: &mut Vec<Held>) -> Released {
    let mut result = Released::default();
    for reply in held.drain(..) {
        result.attempted += 1;
        if reply.respond.send(reply.response).is_ok() {
            result.delivered += 1;
        } else {
            result.canceled += 1;
        }
    }
    result
}

pub(crate) fn interpose(
    incoming: mpsc::Receiver<IncomingRequest>,
    buyer: PeerIdentity,
    hold_settlement: bool,
) -> (mpsc::Receiver<IncomingRequest>, ResponseGate) {
    interpose_matching(incoming, buyer, None, hold_settlement)
}

pub(crate) fn interpose_promotion(
    incoming: mpsc::Receiver<IncomingRequest>,
    buyer: PeerIdentity,
    trial_max_units: u64,
) -> (mpsc::Receiver<IncomingRequest>, ResponseGate) {
    interpose_matching(incoming, buyer, Some(trial_max_units), false)
}

fn interpose_matching(
    mut incoming: mpsc::Receiver<IncomingRequest>,
    buyer: PeerIdentity,
    trial_max_units: Option<u64>,
    hold_settlement: bool,
) -> (mpsc::Receiver<IncomingRequest>, ResponseGate) {
    let (send, receive) = mpsc::channel(16);
    let (capture, captured) = watch::channel(None::<Accepted>);
    let (capture_settled, settled) = watch::channel(None::<SettlementReport>);
    let (commands, mut command) = mpsc::channel(2);
    let task = tokio::spawn(async move {
        let mut held = Vec::new();
        let mut held_settled = Vec::new();
        let mut discarded = !hold_settlement;
        let mut released = false;
        loop {
            tokio::select! {
                message = command.recv() => {
                    match message {
                        Some(Command::Release(done)) => {
                            released = true;
                            let _ = done.send(release(&mut held));
                        }
                        Some(Command::DiscardSettled(done)) => {
                            discarded = true;
                            let count = held_settled.len();
                            // Drop the real responders: none of these bytes
                            // may reach the buyer through TCP/FIPS.
                            held_settled.clear();
                            let _ = done.send(count);
                        }
                        Some(Command::Stop) | None => {
                            release(&mut held);
                            release(&mut held_settled);
                            return;
                        }
                    }
                }
                request = incoming.recv() => {
                    let Some(request) = request else { return; };
                    let matched = if request.peer.node_addr() == buyer.node_addr() {
                        match serde_json::from_slice::<ControllerRequest>(&request.body) {
                            Ok(value @ ControllerRequest::Accept { .. }) if !released => Some(value),
                            Ok(value @ ControllerRequest::Settle { .. }) if !discarded => Some(value),
                            _ => None,
                        }
                    } else {
                        None
                    };
                    let Some(matched) = matched else {
                        if send.send(request).await.is_err() { return; }
                        continue;
                    };
                    let (respond, response) = oneshot::channel();
                    send.send(IncomingRequest {
                        peer: request.peer,
                        body: request.body,
                        respond,
                    }).await.unwrap();
                    let bytes = tokio::time::timeout(Duration::from_secs(10), response)
                        .await.expect("real provider acceptance handler deadline").unwrap();
                    if let ControllerRequest::Settle { channel_id, .. } = matched {
                        if let Ok(ControllerResponse::Settled { report }) = serde_json::from_slice(&bytes) {
                            assert_eq!(report.channel_id, channel_id);
                            let expected = capture.borrow().clone().expect("settlement must follow the captured acceptance");
                            assert_eq!(channel_id, expected.purchase.channel.id);
                            if let Some(first) = capture_settled.borrow().as_ref() {
                                assert_eq!(&report, first, "retried settlement changed its report");
                            }
                            assert!(held_settled.len() < 8, "bounded held settlement responses");
                            held_settled.push(Held { response: bytes, respond: request.respond });
                            capture_settled.send(Some(report)).unwrap();
                        } else {
                            let _ = request.respond.send(bytes);
                        }
                        continue;
                    }
                    let ControllerRequest::Accept { offer_id, channel, .. } = matched else {
                        unreachable!("only Accept and Settle are intercepted")
                    };
                    if let Ok(ControllerResponse::Accepted { purchase }) =
                        serde_json::from_slice::<ControllerResponse>(&bytes)
                    {
                        if trial_max_units.is_some_and(|limit| purchase.contract.max_units <= limit) {
                            let _ = request.respond.send(bytes);
                            continue;
                        }
                        assert_eq!(purchase.channel, channel);
                        assert_eq!(purchase.channel.buyer, *buyer.node_addr());
                        assert_eq!(purchase.contract.channel_id, channel.id);
                        let accepted = Accepted { offer_id, purchase: *purchase };
                        if let Some(first) = capture.borrow().as_ref() {
                            assert_eq!(accepted.offer_id, first.offer_id, "the source cannot replace a purchase while its first acceptance remains pending");
                            assert_eq!(accepted.purchase, first.purchase);
                        }
                        assert!(held.len() < 8, "bounded held acceptance response capacity");
                        held.push(Held { response: bytes, respond: request.respond });
                        capture.send(Some(accepted)).unwrap();
                    } else {
                        let _ = request.respond.send(bytes);
                    }
                }
            }
        }
    });
    (
        receive,
        ResponseGate {
            captured,
            settled,
            hold_settlement,
            commands,
            task: Some(task),
        },
    )
}
