//! App-facing traffic and conservative receive timestamps; no routing calls.
use super::*;
use crate::node::{EndpointDataBatchTx, NodeEndpointDataBatch};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Packet {
    submitted: [u128; 2],
    received: Option<[u128; 2]>,
}

#[derive(Default)]
struct State {
    packets: BTreeMap<[u8; 5], Packet>,
}

pub(super) struct Traffic {
    started: Instant,
    ids: Vec<PeerIdentity>,
    senders: Vec<EndpointDataBatchTx>,
    state: Arc<Mutex<State>>,
    reader_stop: Option<oneshot::Sender<()>>,
    reader: Option<tokio::task::JoinHandle<()>>,
    local: Option<(oneshot::Sender<()>, tokio::task::JoinHandle<()>)>,
}

fn key(kind: u8, source: usize, destination: usize, sequence: u16) -> [u8; 5] {
    let [low, high] = sequence.to_le_bytes();
    [kind, source as u8, destination as u8, low, high]
}

fn send(
    senders: &[EndpointDataBatchTx],
    ids: &[PeerIdentity],
    state: &Mutex<State>,
    started: Instant,
    key: [u8; 5],
) {
    let batch = NodeEndpointDataBatch::from_payloads(
        ids[usize::from(key[2])],
        vec![crate::node::EndpointDataPayload::from_packet_payload(key.to_vec()).unwrap()],
        None,
    )
    .unwrap();
    let mut state = state.lock().unwrap();
    assert!(state.packets.len() < 1024, "bounded unique test packets");
    let before = started.elapsed().as_millis();
    // Exactly one normal app-queue submission. Receipt, not this API's return,
    // proves admission: send_or_drop can discard at its bounded queue limit.
    senders[usize::from(key[1])].send_or_drop(batch).unwrap();
    assert!(
        state
            .packets
            .insert(
                key,
                Packet {
                    submitted: [before, started.elapsed().as_millis()],
                    received: None,
                },
            )
            .is_none()
    );
}

impl Traffic {
    pub(super) fn start(
        mut endpoints: Vec<EndpointDataIo>,
        ids: Vec<PeerIdentity>,
        started: Instant,
    ) -> Self {
        let senders = endpoints
            .iter()
            .map(|io| io.data_batch_tx.clone())
            .collect();
        let state = Arc::new(Mutex::new(State::default()));
        let received = state.clone();
        let receiver_ids = ids.clone();
        let (stop, mut stopped) = oneshot::channel();
        let reader = tokio::spawn(async move {
            loop {
                for (destination, io) in endpoints.iter_mut().enumerate() {
                    while let Ok(event) = io.event_rx.try_recv() {
                        let count = event.message_count();
                        for message in event.messages {
                            let before = started.elapsed().as_millis();
                            let key: [u8; 5] = message.payload.as_slice().try_into().unwrap();
                            assert_eq!(usize::from(key[2]), destination);
                            assert_eq!(
                                message.source_peer.node_addr(),
                                receiver_ids[usize::from(key[1])].node_addr()
                            );
                            let mut state = received.lock().unwrap();
                            let packet = state.packets.get_mut(&key).expect("offered original");
                            assert!(
                                packet
                                    .received
                                    .replace([before, started.elapsed().as_millis()])
                                    .is_none(),
                                "no duplicate may supply progress"
                            );
                        }
                        io.event_rx.release_messages(count);
                    }
                }
                tokio::select! {
                    _ = &mut stopped => break,
                    _ = tokio::time::sleep(Duration::from_millis(2)) => {}
                }
            }
        });
        Self {
            started,
            ids,
            senders,
            state,
            reader_stop: Some(stop),
            reader: Some(reader),
            local: None,
        }
    }

    pub(super) fn start_local(&mut self) {
        assert!(self.local.is_none());
        let (stop, mut stopped) = oneshot::channel();
        let senders = self.senders.clone();
        let ids = self.ids.clone();
        let state = self.state.clone();
        let started = self.started;
        let task = tokio::spawn(async move {
            for sequence in 0..u16::MAX {
                for (source, destination) in LOCAL_FLOWS {
                    send(
                        &senders,
                        &ids,
                        &state,
                        started,
                        key(0, source, destination, sequence),
                    );
                }
                tokio::select! {
                    _ = &mut stopped => return,
                    _ = tokio::time::sleep(Duration::from_millis(500)) => {}
                }
            }
            panic!("finite traffic sequence exhausted");
        });
        self.local = Some((stop, task));
    }

    pub(super) fn offer_originals(&self) {
        for (source, destination) in [(2, 3), (3, 2)] {
            send(
                &self.senders,
                &self.ids,
                &self.state,
                self.started,
                key(1, source, destination, 0),
            );
        }
    }

    pub(super) fn assert_local_progress(&self, require_all: bool) {
        let now = self.started.elapsed().as_millis();
        let state = self.state.lock().unwrap();
        for (key, packet) in &state.packets {
            if key[0] != 0 {
                continue;
            }
            if let Some(received) = packet.received {
                assert!(
                    received[1] - packet.submitted[0] < 2000,
                    "local delivery stays within two seconds"
                );
            } else {
                assert!(
                    !require_all && now - packet.submitted[0] < 2000,
                    "local original must continue"
                );
            }
        }
    }

    pub(super) fn originals_before(&self, cut_ms: u128) -> bool {
        let state = self.state.lock().unwrap();
        [(2, 3), (3, 2)].into_iter().all(|(from, to)| {
            state.packets.get(&key(1, from, to, 0)).is_some_and(|p| {
                p.submitted[1] < cut_ms && p.received.is_some_and(|r| r[1] < cut_ms)
            })
        })
    }

    pub(super) fn local_complete(&self) -> bool {
        self.state
            .lock()
            .unwrap()
            .packets
            .iter()
            .all(|(key, packet)| key[0] != 0 || packet.received.is_some())
    }

    pub(super) fn summary(&self) -> Value {
        let state = self.state.lock().unwrap();
        let originals: Vec<_> = state
            .packets
            .iter()
            .filter(|(key, _)| key[0] == 1)
            .map(|(key, p)| {
                json!({"source":key[1],"destination":key[2],
                "submission_ms":p.submitted,"receipt_ms":p.received})
            })
            .collect();
        let local: Vec<_> = state
            .packets
            .iter()
            .filter(|(key, _)| key[0] == 0)
            .collect();
        json!({"originals":originals,"local_offered":local.len(),
            "local_received":local.iter().filter(|(_,p)|p.received.is_some()).count()})
    }

    pub(super) async fn stop_local(&mut self) {
        if let Some((stop, task)) = self.local.take() {
            let _ = stop.send(());
            task.await.unwrap();
        }
    }

    pub(super) async fn stop(&mut self) {
        self.stop_local().await;
        let _ = self.reader_stop.take().unwrap().send(());
        self.reader.take().unwrap().await.unwrap();
    }
}
