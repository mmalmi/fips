//! Exercise both sides of persistent records against the ordinary TCP adapter.
use super::*;
use fips_relay::control_transport::{ControlAdmission, NeighborAdmission};
use fips_tcp::{ConnectionId, State};
use fips_tcp_endpoint::FipsTcpEndpoint;
use std::time::Instant;

const PORT: u16 = 44_721;

struct WirePeer {
    tcp: FipsTcpEndpoint,
    started: Instant,
}

impl WirePeer {
    async fn new(endpoint: Arc<FipsEndpoint>) -> Self {
        Self {
            tcp: FipsTcpEndpoint::bind(
                endpoint,
                PORT,
                fips_tcp::Config {
                    receive_buffer: u16::MAX as usize,
                    send_buffer: u16::MAX as usize,
                    ..Default::default()
                },
                71,
            )
            .await
            .unwrap(),
            started: Instant::now(),
        }
    }

    fn now(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    async fn step(&mut self) {
        let now = self.now();
        tokio::select! {
            result = self.tcp.receive_report(now) => { result.unwrap(); }
            _ = tokio::time::sleep(Duration::from_millis(5)) => {
                self.tcp.poll(now).await.unwrap();
            }
        }
    }

    async fn read(&mut self, connection: &mut Option<ConnectionId>) -> Vec<u8> {
        let mut record = Vec::new();
        loop {
            while let Some(accepted) = self.tcp.accept() {
                assert!(
                    connection.is_none_or(|previous| previous == accepted),
                    "consecutive control records opened another TCP connection"
                );
                *connection = Some(accepted);
            }
            if let Some(id) = *connection {
                if matches!(
                    self.tcp.state(id),
                    Some(State::Established | State::CloseWait)
                ) {
                    record.extend(
                        self.tcp
                            .read(id, 65_540 - record.len(), self.now())
                            .await
                            .unwrap(),
                    );
                    if record.len() >= 4 {
                        let size = u32::from_be_bytes(record[..4].try_into().unwrap()) as usize;
                        assert!(size <= 65_536 && record.len() <= size + 4);
                        if record.len() == size + 4 {
                            return record.split_off(4);
                        }
                    }
                }
                assert!(
                    !self.tcp.is_read_closed(id),
                    "stream closed between control records"
                );
            }
            self.step().await;
        }
    }

    async fn write(&mut self, id: ConnectionId, body: &[u8]) {
        while self.tcp.state(id) == Some(State::SynSent) {
            self.step().await;
        }
        assert_eq!(self.tcp.state(id), Some(State::Established));
        let mut record = (body.len() as u32).to_be_bytes().to_vec();
        record.extend_from_slice(body);
        assert_eq!(
            self.tcp.write(id, &record, self.now()).await.unwrap(),
            record.len()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consecutive_requests_reuse_one_tcp_connection() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (a, b) = pair().await;
        let bob = PeerIdentity::from_npub(b.npub()).unwrap();
        let (client, _) = ControlTransport::start(a.clone(), PORT, vec![bob], 72)
            .await
            .unwrap();
        let mut server = WirePeer::new(b.clone()).await;
        let bodies = [b"first".to_vec(), vec![42; 24_000], b"last".to_vec()];
        let requests = async {
            for body in &bodies {
                assert_eq!(client.request(bob, body.clone()).await.unwrap(), *body);
            }
            tokio::time::sleep(Duration::from_secs(6)).await;
            assert_eq!(
                client.request(bob, b"after idle".to_vec()).await.unwrap(),
                b"after idle"
            );
        };
        let responses = async {
            let mut connection = None;
            for body in &bodies {
                assert_eq!(server.read(&mut connection).await, *body);
                server.write(connection.unwrap(), body).await;
            }
            let previous = connection.unwrap();
            while !server.tcp.is_read_closed(previous) {
                server.step().await;
            }
            server.tcp.close(previous, server.now()).await.unwrap();
            connection = None;
            assert_eq!(server.read(&mut connection).await, b"after idle");
            assert_ne!(
                connection,
                Some(previous),
                "idle expiry must release the old stream"
            );
            server.write(connection.unwrap(), b"after idle").await;
        };
        tokio::join!(requests, responses);
        let counters = client.statistics().snapshot();
        assert_eq!(counters.requests_started, 4);
        let bytes = bodies.iter().map(|b| (b.len() + 4) as u64).sum::<u64>() + 14;
        assert_eq!(counters.stream_bytes_sent, bytes);
        assert_eq!(counters.stream_bytes_received, bytes);
        drop((client, server));
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("bounded persistent client exchange");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn consecutive_server_records_release_and_reacquire_shared_admission() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (a, b) = pair().await;
        let alice = PeerIdentity::from_npub(a.npub()).unwrap();
        let bob = PeerIdentity::from_npub(b.npub()).unwrap();
        let admission = ControlAdmission::new(
            b.clone(),
            vec![],
            None,
            NeighborAdmission::AuthenticatedAdjacent,
        )
        .unwrap();
        let (server, mut incoming) =
            ControlTransport::start_with_admission(b.clone(), PORT, admission.clone(), 72)
                .await
                .unwrap();
        let mut client = WirePeer::new(a.clone()).await;
        let id = client.tcp.connect(bob, client.now()).await.unwrap();
        let (released, mut observed_release) = tokio::sync::mpsc::channel(1);
        let requests = async {
            for byte in 0..3 {
                client.write(id, &[byte]).await;
                assert_eq!(client.read(&mut Some(id)).await, [byte]);
                observed_release.recv().await.unwrap();
            }
        };
        let responses = async {
            for byte in 0..3 {
                let request = incoming.recv().await.unwrap();
                assert_eq!(request.peer, alice);
                assert_eq!(request.body, [byte]);
                assert_eq!(
                    admission.active_unconfigured_exchanges(*alice.node_addr()),
                    1
                );
                request.respond.send(request.body).unwrap();
                while admission.active_unconfigured_exchanges(*alice.node_addr()) != 0 {
                    tokio::task::yield_now().await;
                }
                released.send(()).await.unwrap();
            }
        };
        tokio::join!(requests, responses);
        assert_eq!(server.statistics().snapshot().requests_received, 3);
        assert_eq!(server.statistics().snapshot().stream_bytes_received, 15);
        assert_eq!(server.statistics().snapshot().stream_bytes_sent, 15);
        drop((client, server));
        a.shutdown().await.unwrap();
        b.shutdown().await.unwrap();
    })
    .await
    .expect("bounded persistent server exchange");
}
