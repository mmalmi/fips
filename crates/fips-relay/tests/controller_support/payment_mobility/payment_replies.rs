//! Lose updates before application and replies after it, using the real scheduler.
use super::*;
use fips_relay::{
    controller::Purchase,
    payment_control::{PaymentRequest, PaymentResponse},
};
use std::{path::Path, sync::Mutex};
use tokio::sync::oneshot;

#[derive(Default)]
struct Observation {
    channel: Option<String>,
    capture: Option<(LossPoint, oneshot::Sender<HeldUpdate>)>,
    captures: u8,
    requests: Vec<Request>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LossPoint {
    BeforeApply,
    AfterApply,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Request {
    Usage,
    Update(u64),
}

pub(super) struct ReplyGate {
    observation: Arc<Mutex<Observation>>,
    task: tokio::task::JoinHandle<()>,
}

struct HeldUpdate {
    balance: u64,
    discard: oneshot::Sender<()>,
    expired: oneshot::Receiver<Duration>,
}

impl ReplyGate {
    fn arm(&self, channel: &str, point: LossPoint) -> oneshot::Receiver<HeldUpdate> {
        let (capture, applied) = oneshot::channel();
        let mut state = self.observation.lock().unwrap();
        assert!(state.captures < 2 && state.capture.is_none());
        assert!(state.channel.as_ref().is_none_or(|old| old == channel));
        state.channel = Some(channel.into());
        state.captures += 1;
        state.capture = Some((point, capture));
        applied
    }

    fn observed(&self) -> Vec<Request> {
        self.observation.lock().unwrap().requests.clone()
    }
}

impl Drop for ReplyGate {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn discard_reply(
    capture: oneshot::Sender<HeldUpdate>,
    balance: u64,
    mut respond: oneshot::Sender<Vec<u8>>,
) {
    let started = tokio::time::Instant::now();
    let (discard, release) = oneshot::channel();
    let (expired, expiry) = oneshot::channel();
    assert!(
        capture
            .send(HeldUpdate {
                balance,
                discard,
                expired: expiry
            })
            .is_ok()
    );
    // The transport's real 30-second deadline must discard a silent request.
    // Applied replies can also be lost promptly through the cancellation path.
    tokio::time::timeout(Duration::from_secs(35), async {
        tokio::select! {
            _ = respond.closed() => { let _ = expired.send(started.elapsed()); }
            released = release => released.unwrap(),
        }
    })
    .await
    .unwrap();
    drop(respond);
}

pub(super) fn proxy(
    mut incoming: mpsc::Receiver<IncomingRequest>,
    buyer: PeerIdentity,
) -> (mpsc::Receiver<IncomingRequest>, ReplyGate) {
    let observation = Arc::new(Mutex::new(Observation::default()));
    let observed = observation.clone();
    let (send, receive) = mpsc::channel(16);
    let task = tokio::spawn(async move {
        let mut replies = tokio::task::JoinSet::new();
        loop {
            let request = tokio::select! {
                result = replies.join_next(), if !replies.is_empty() => {
                    result.unwrap().expect("reply interception failed");
                    continue;
                }
                request = incoming.recv() => match request {
                    Some(request) => request,
                    None => return,
                },
            };
            let captured = if request.peer.node_addr() == buyer.node_addr() {
                let mut state = observed.lock().unwrap();
                match serde_json::from_slice::<PaymentRequest>(&request.body) {
                    Ok(PaymentRequest::Update {
                        channel_id,
                        payment,
                    }) if state.channel.as_ref() == Some(&channel_id) => {
                        assert!(state.requests.len() < 32, "bounded payment observation");
                        state.requests.push(Request::Update(payment.balance));
                        state
                            .capture
                            .take()
                            .map(|(point, capture)| (point, capture, channel_id, payment.balance))
                    }
                    Ok(PaymentRequest::Usage { channel_id })
                        if state.channel.as_ref() == Some(&channel_id) =>
                    {
                        assert!(state.requests.len() < 32, "bounded payment observation");
                        state.requests.push(Request::Usage);
                        None
                    }
                    _ => None,
                }
            } else {
                None
            };
            let Some((point, capture, channel_id, balance)) = captured else {
                if send.send(request).await.is_err() {
                    return;
                }
                continue;
            };
            if point == LossPoint::BeforeApply {
                replies.spawn(discard_reply(capture, balance, request.respond));
                continue;
            }
            let (respond, response) = oneshot::channel();
            send.send(IncomingRequest {
                peer: request.peer,
                body: request.body,
                respond,
            })
            .await
            .unwrap();
            // The real server remains free to serve every other channel while
            // this one completed reply is held outside the transport.
            replies.spawn(async move {
                let bytes = tokio::time::timeout(Duration::from_secs(10), response)
                    .await
                    .unwrap()
                    .unwrap();
                let PaymentResponse::Status {
                    channel_id: actual,
                    usage,
                } = serde_json::from_slice(&bytes).unwrap()
                else {
                    panic!("real payment handler rejected the captured update");
                };
                assert_eq!(actual, channel_id);
                assert_eq!(usage.paid_msat, balance * 1_000);
                discard_reply(capture, balance, request.respond).await;
            });
        }
    });
    (receive, ReplyGate { observation, task })
}

fn journal(root: &Path, relative: &str) -> serde_json::Value {
    serde_json::from_slice(&std::fs::read(root.join(relative)).unwrap()).unwrap()
}

async fn acknowledged(controller: &Controller, channel: &str, minimum: u64) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let progress = controller.payment_progress().await.unwrap();
            let state = &progress[channel];
            if state.acknowledged_msat.is_some_and(|paid| paid >= minimum) && !state.in_flight {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("automatic scheduler must acknowledge the retained payment");
}

pub(super) async fn lost_updates_and_replies_recover_automatically(
    root: &Path,
    traffic: &mut Traffic<'_>,
    gate: &ReplyGate,
    purchases: &[Purchase],
    buyers: &[Arc<BuyerAuthorizer>],
) {
    let purchase = &purchases[0];
    let channel = &purchase.channel.id;
    let slow = traffic
        .peers
        .iter()
        .position(|p| *p.node_addr() == purchase.provider)
        .unwrap();
    let healthy = traffic
        .peers
        .iter()
        .position(|p| *p.node_addr() == purchases[1].provider)
        .unwrap();
    let controller = traffic.controllers[2].clone();
    let buyer = &buyers[2];
    let sellers = traffic.sellers;
    let funding = journal(root, "controller-2/controller.json")["funding"].clone();
    let budget = controller.funding_budget().await.unwrap();
    let prior = buyer.authorized_sat(channel).unwrap();
    acknowledged(&controller, channel, prior * 1_000).await;
    let applied = gate.arm(channel, LossPoint::AfterApply);
    traffic.send(if slow == 1 { 4 } else { 0 }, 170).await;
    let applied = tokio::time::timeout(Duration::from_secs(10), applied)
        .await
        .unwrap()
        .unwrap();
    assert!(applied.balance > prior);
    let captured_evidence = buyer.evidence_msat(channel).unwrap();
    assert_eq!(buyer.authorized_sat(channel), Some(applied.balance));
    assert_eq!(
        journal(root, "buyer-2/buyer.json")["channels"][channel]["authorized_sat"],
        applied.balance
    );
    assert_eq!(
        sellers[slow].channel_usage(channel).unwrap().paid_msat,
        applied.balance * 1_000
    );
    let stored = journal(root, &format!("seller-{slow}/ledger.json"));
    let saved = stored["ledger"]["channels"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["terms"]["id"] == *channel)
        .unwrap();
    assert_eq!(saved["usage"]["paid_msat"], applied.balance * 1_000);
    let progress = controller.payment_progress().await.unwrap();
    assert!(progress[channel].in_flight);
    assert!(
        progress[channel]
            .acknowledged_msat
            .is_none_or(|paid| paid < applied.balance * 1_000)
    );

    assert_eq!(
        buyer.authorized_sat(channel),
        Some(applied.balance),
        "held reply cannot sign again"
    );
    assert_eq!(controller.funding_budget().await.unwrap(), budget);
    assert_eq!(
        journal(root, "controller-2/controller.json")["funding"],
        funding
    );
    let requests_before = gate.observed().len();
    applied.discard.send(()).unwrap();
    acknowledged(&controller, channel, applied.balance * 1_000).await;
    let progress = serde_json::to_value(controller.payment_progress().await.unwrap()).unwrap();
    assert_eq!(
        progress[channel]["last_failure_stage"], "update_request",
        "a successful retry must retain the failed exchange stage for diagnosis"
    );
    let requests = gate.observed();
    assert_eq!(
        requests.get(requests_before),
        Some(&Request::Usage),
        "the first recovery request must reconcile retained credit"
    );
    let updates: Vec<_> = requests
        .iter()
        .filter_map(|request| match request {
            Request::Update(balance) => Some(*balance),
            Request::Usage => None,
        })
        .collect();
    assert_eq!(
        updates
            .iter()
            .filter(|balance| **balance == applied.balance)
            .count(),
        1
    );
    assert!(
        updates.windows(2).all(|pair| pair[0] < pair[1]),
        "cumulative updates cannot replay or decrease"
    );
    let authorized = buyer.authorized_sat(channel).unwrap();
    let evidence = buyer.evidence_msat(channel).unwrap();
    assert!(authorized <= applied.balance.max(evidence.div_ceil(1_000)));
    // FIPS may produce priced background envelopes. Only unchanged evidence
    // justifies requiring the exact balance to remain fixed through recovery.
    if evidence == captured_evidence {
        assert_eq!(authorized, applied.balance);
        assert_eq!(updates, vec![applied.balance]);
    }
    assert_eq!(controller.purchases().await.unwrap(), purchases);
    assert_eq!(controller.funding_budget().await.unwrap(), budget);
    assert_eq!(
        journal(root, "controller-2/controller.json")["funding"],
        funding
    );
    let saved = journal(root, "buyer-2/buyer.json");
    assert_eq!(saved["total_budget_sat"], 64);
    let signed: u64 = saved["channels"]
        .as_object()
        .unwrap()
        .values()
        .map(|channel| channel["authorized_sat"].as_u64().unwrap())
        .sum();
    assert!(
        signed <= 64,
        "retained lifetime authority cannot exceed its original cap"
    );

    let held = gate.arm(channel, LossPoint::BeforeApply);
    traffic.send(if slow == 1 { 4 } else { 0 }, 177).await;
    let held = tokio::time::timeout(Duration::from_secs(10), held)
        .await
        .unwrap()
        .unwrap();
    // An earlier exchange can finish before the gate is armed. Sample credit
    // only after this update is held, when the channel worker cannot sign again.
    let previous_credit = sellers[slow].channel_usage(channel).unwrap().paid_msat;
    assert!(previous_credit < held.balance * 1_000);
    assert!(held.balance > authorized);
    assert_eq!(buyer.authorized_sat(channel), Some(held.balance));
    assert_eq!(
        journal(root, "buyer-2/buyer.json")["channels"][channel]["authorized_sat"],
        held.balance
    );
    assert!(controller.payment_progress().await.unwrap()[channel].in_flight);
    assert_eq!(
        sellers[slow].channel_usage(channel).unwrap().paid_msat,
        previous_credit
    );
    let captured_evidence = buyer.evidence_msat(channel).unwrap();
    let requests_before = gate.observed().len();
    traffic
        .paid_bursts(healthy, &purchases[1], sellers, buyer, 173)
        .await;
    assert_eq!(buyer.authorized_sat(channel), Some(held.balance));
    assert_eq!(
        sellers[slow].channel_usage(channel).unwrap().paid_msat,
        previous_credit
    );
    assert_eq!(controller.funding_budget().await.unwrap(), budget);
    // Keep the responder alive without applying the update or canceling it.
    // Only the production request deadline may wake the automatic retry.
    let elapsed = tokio::time::timeout(Duration::from_secs(35), held.expired)
        .await
        .expect("silent payment request must expire")
        .unwrap();
    assert!(
        elapsed >= Duration::from_secs(25),
        "request canceled before its deadline"
    );
    eprintln!(
        "silent payment update expired after {:.3}s",
        elapsed.as_secs_f64()
    );
    let due = buyer.evidence_msat(channel).unwrap().div_ceil(1_000) * 1_000;
    assert!(due > authorized * 1_000);
    acknowledged(&controller, channel, due).await;
    let progress = serde_json::to_value(controller.payment_progress().await.unwrap()).unwrap();
    assert_eq!(
        progress[channel]["last_failure_stage"], "update_request",
        "a successful retry must retain the failed exchange stage for diagnosis"
    );
    let requests = gate.observed();
    assert_eq!(requests.get(requests_before), Some(&Request::Usage));
    let resent: Vec<_> = requests[requests_before..]
        .iter()
        .filter_map(|request| match request {
            Request::Update(balance) => Some(*balance),
            Request::Usage => None,
        })
        .collect();
    assert!(
        !resent.is_empty(),
        "unapplied credit requires a real update retry"
    );
    assert!(resent.iter().all(|balance| *balance >= held.balance));
    if buyer.evidence_msat(channel) == Some(captured_evidence) {
        assert_eq!(resent, vec![held.balance]);
    }
    assert!(sellers[slow].channel_usage(channel).unwrap().paid_msat >= due);
    assert_eq!(controller.purchases().await.unwrap(), purchases);
    assert_eq!(controller.funding_budget().await.unwrap(), budget);
    assert_eq!(
        journal(root, "controller-2/controller.json")["funding"],
        funding
    );
}
