//! Delay real control requests without replacing the payment implementation.
use super::*;
use fips_core::FipsEndpointServiceReceiver;
use fips_relay::control_transport::IncomingRequest;
use tokio::sync::{Notify, mpsc, watch};

pub(super) struct Gate {
    pause: watch::Sender<bool>,
    held: Arc<Notify>,
    task: tokio::task::JoinHandle<()>,
}

impl Gate {
    fn pause(&self) {
        self.pause.send(true).unwrap();
    }

    fn release(&self) {
        self.pause.send(false).unwrap();
    }

    async fn held(&self) -> bool {
        tokio::time::timeout(Duration::from_secs(10), self.held.notified())
            .await
            .is_ok()
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(super) fn gate(
    mut incoming: mpsc::Receiver<IncomingRequest>,
    buyer: PeerIdentity,
    enabled: bool,
) -> (mpsc::Receiver<IncomingRequest>, Option<Gate>) {
    if !enabled {
        return (incoming, None);
    }
    let (send, receive) = mpsc::channel(16);
    let (pause, mut paused) = watch::channel(false);
    let held = Arc::new(Notify::new());
    let notify = held.clone();
    let task = tokio::spawn(async move {
        let mut pending = Vec::new();
        loop {
            tokio::select! {
                changed = paused.changed() => {
                    if changed.is_err() { return; }
                    if !*paused.borrow() {
                        for request in pending.drain(..) {
                            if send.send(request).await.is_err() { return; }
                        }
                    }
                }
                request = incoming.recv() => {
                    let Some(request) = request else { return; };
                    if request.peer.node_addr() == buyer.node_addr() && *paused.borrow() {
                        notify.notify_one();
                        // Delay only this link's control traffic. Other buyers
                        // of the provider must still be serviced normally.
                        if pending.len() < 16 { pending.push(request); }
                    } else if send.send(request).await.is_err() { return; }
                }
            }
        }
    });
    (receive, Some(Gate { pause, held, task }))
}

#[tokio::test]
async fn pause_matches_the_fips_identity_across_public_key_representations() {
    let full = (1..=32)
        .map(|n| {
            let identity = fips_core::Identity::from_secret_bytes(&[n; 32]).unwrap();
            PeerIdentity::from_pubkey_full(identity.pubkey_full())
        })
        .find(|p| *p != PeerIdentity::from_npub(&p.npub()).unwrap())
        .unwrap();
    let canonical = PeerIdentity::from_npub(&full.npub()).unwrap();
    assert_eq!(full.node_addr(), canonical.node_addr());
    let (send, incoming) = mpsc::channel(1);
    let (mut receive, gate) = gate(incoming, full, true);
    let gate = gate.unwrap();
    gate.pause();
    let (respond, _response) = tokio::sync::oneshot::channel();
    send.send(IncomingRequest {
        peer: canonical,
        body: vec![1],
        respond,
    })
    .await
    .unwrap();
    assert!(gate.held().await);
    assert!(receive.try_recv().is_err());
    gate.release();
    let request = tokio::time::timeout(Duration::from_secs(1), receive.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(request.body, vec![1]);
}

struct Traffic<'a> {
    nodes: &'a [Arc<FipsEndpoint>],
    peers: &'a [PeerIdentity],
    data: &'a mut [FipsEndpointServiceReceiver],
    controllers: &'a [Arc<Controller>],
    sellers: &'a [Arc<DurableRelay>],
}

impl Traffic<'_> {
    async fn send(&mut self, source: usize, tag: u8) {
        let destination = 4 - source;
        // The session envelope makes this cost more than one sat, while the
        // complete packet still fits the default 1280-byte native link MTU.
        let payload = vec![tag; 1_000];
        self.nodes[source]
            .send_datagram(self.peers[destination], 44_740, 44_740, payload.clone())
            .await
            .unwrap();
        let delivery = tokio::time::timeout(Duration::from_secs(4), async {
            let mut received = Vec::new();
            loop {
                self.data[destination]
                    .recv_batch_into(&mut received, 8)
                    .await
                    .unwrap();
                if received.iter().any(|m| m.data.as_slice() == payload) {
                    break;
                }
            }
        })
        .await;
        if delivery.is_err() {
            let mut usage = Vec::new();
            for (index, controller) in self.controllers.iter().enumerate() {
                for p in controller.purchases().await.unwrap() {
                    let provider = self
                        .peers
                        .iter()
                        .position(|n| *n.node_addr() == p.provider)
                        .unwrap();
                    usage.push((
                        index,
                        provider,
                        self.sellers[provider].channel_usage(&p.channel.id),
                    ));
                }
            }
            panic!("delivery source={source} tag={tag}, usage={usage:?}");
        }
    }

    async fn paid_bursts(
        &mut self,
        healthy: usize,
        purchase: &fips_relay::controller::Purchase,
        sellers: &[Arc<DurableRelay>],
        buyer: &BuyerAuthorizer,
        tag: u8,
    ) {
        for round in 0..3 {
            let before = sellers[healthy]
                .channel_usage(&purchase.channel.id)
                .unwrap()
                .paid_msat;
            self.send(if healthy == 1 { 4 } else { 0 }, tag + round)
                .await;
            let expected = buyer
                .evidence_msat(&purchase.channel.id)
                .unwrap()
                .div_ceil(1_000)
                * 1_000;
            assert!(expected > before, "each burst needs a new signed balance");
            tokio::time::timeout(Duration::from_secs(4), async {
                loop {
                    if sellers[healthy]
                        .channel_usage(&purchase.channel.id)
                        .unwrap()
                        .paid_msat
                        >= expected
                    {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("a healthy channel must keep getting paid while another neighbor is held");
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn exercise(
    nodes: &[Arc<FipsEndpoint>],
    peers: &[PeerIdentity],
    data: &mut [FipsEndpointServiceReceiver],
    controllers: &[Arc<Controller>],
    sellers: &[Arc<DurableRelay>],
    buyers: &[Arc<BuyerAuthorizer>],
    payments: &[Option<Gate>],
    settlements: &[Option<Gate>],
) {
    let buyer = &controllers[2];
    buyer.flush_payments().await.unwrap();
    let purchases = buyer.purchases().await.unwrap();
    assert_eq!(purchases.len(), 2);
    // First in the old serial loop: a regression cannot pass by favorable order.
    let slow_purchase = &purchases[0];
    let healthy_purchase = &purchases[1];
    let slow = peers
        .iter()
        .position(|p| *p.node_addr() == slow_purchase.provider)
        .unwrap();
    let healthy = peers
        .iter()
        .position(|p| *p.node_addr() == healthy_purchase.provider)
        .unwrap();
    let payment_gate = payments[slow].as_ref().unwrap();
    let settlement_gate = settlements[slow].as_ref().unwrap();
    let capital = buyer.locked_capital_sat().await.unwrap();
    let mut traffic = Traffic {
        nodes,
        peers,
        data,
        controllers,
        sellers,
    };
    payment_gate.pause();
    traffic.send(if slow == 1 { 4 } else { 0 }, 180).await;
    assert!(
        payment_gate.held().await,
        "the selected neighbor must hold a real payment request: slow={slow}, usage={:?}, evidence={:?}, authorized={:?}, errors={:?}",
        sellers[slow].channel_usage(&slow_purchase.channel.id),
        buyers[2].evidence_msat(&slow_purchase.channel.id),
        buyers[2].authorized_sat(&slow_purchase.channel.id),
        controllers
            .iter()
            .map(|c| c.last_error())
            .collect::<Vec<_>>()
    );
    traffic
        .paid_bursts(healthy, healthy_purchase, sellers, &buyers[2], 190)
        .await;
    assert_eq!(buyer.locked_capital_sat().await.unwrap(), capital);
    assert_eq!(buyer.purchases().await.unwrap(), purchases);

    // Settlement waits for its own in-flight payment, then holds a real Seal RPC.
    // A healthy channel must make several further payments in both phases.
    settlement_gate.pause();
    let settling = buyer.clone();
    let id = slow_purchase.channel.id.clone();
    let close = tokio::spawn(async move { settling.settle_channel(&id).await });
    payment_gate.release();
    assert!(
        settlement_gate.held().await,
        "the selected neighbor must hold a real settlement request: errors={:?}",
        controllers
            .iter()
            .map(|c| c.last_error())
            .collect::<Vec<_>>()
    );
    traffic
        .paid_bursts(healthy, healthy_purchase, sellers, &buyers[2], 200)
        .await;
    assert_eq!(
        buyer.locked_capital_sat().await.unwrap(),
        capital,
        "absence during settlement cannot release unresolved capital"
    );
    settlement_gate.release();
    let report = tokio::time::timeout(Duration::from_secs(20), close)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(report.channel_id, slow_purchase.channel.id);
    assert_eq!(
        report.paid_sat * 1_000,
        buyers[2].authorized_sat(&slow_purchase.channel.id).unwrap() * 1_000
    );
    assert_eq!(
        buyer.locked_capital_sat().await.unwrap(),
        capital - slow_purchase.channel.capacity_sat
    );
    assert_eq!(
        buyer.purchases().await.unwrap(),
        vec![healthy_purchase.clone()]
    );
}
