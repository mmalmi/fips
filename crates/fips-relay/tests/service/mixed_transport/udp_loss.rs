//! Counted carrier loss without replacing the daemon's UDP or receive loop.
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{net::UdpSocket, task::JoinHandle};

pub(super) struct UdpLoss {
    pub address: SocketAddr,
    state: Arc<Mutex<(bool, u64, u64)>>,
    task: JoinHandle<()>,
}

impl UdpLoss {
    pub async fn start(endpoint: SocketAddr, middle: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let state = Arc::new(Mutex::new((false, 0u64, 0u64)));
        let shared = state.clone();
        let task = tokio::spawn(async move {
            let mut buffer = vec![0; 65_536];
            loop {
                let (bytes, source) = socket.recv_from(&mut buffer).await.unwrap();
                let destination = if source == endpoint {
                    middle
                } else {
                    assert_eq!(source, middle, "unexpected carrier source");
                    let mut state = shared.lock().unwrap();
                    if state.0 {
                        state.1 += 1;
                        if state.1.is_multiple_of(20) {
                            state.2 += 1;
                            continue;
                        }
                    }
                    endpoint
                };
                assert_eq!(
                    socket.send_to(&buffer[..bytes], destination).await.unwrap(),
                    bytes
                );
            }
        });
        Self {
            address,
            state,
            task,
        }
    }

    pub fn enable(&self, enabled: bool) {
        assert!(!self.task.is_finished(), "carrier proxy stopped");
        self.state.lock().unwrap().0 = enabled;
    }

    pub fn counts(&self) -> (u64, u64) {
        assert!(!self.task.is_finished(), "carrier proxy stopped");
        let state = self.state.lock().unwrap();
        (state.1, state.2)
    }
}

impl Drop for UdpLoss {
    fn drop(&mut self) {
        self.task.abort();
    }
}
