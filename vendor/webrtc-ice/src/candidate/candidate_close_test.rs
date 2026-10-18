use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;
use crate::agent::agent_vnet_test::MockConn;
use crate::error::Error;
use util::Conn;

#[derive(Default)]
struct TrackedConnection(AtomicUsize);

#[async_trait]
impl Conn for TrackedConnection {
    async fn connect(&self, addr: SocketAddr) -> util::Result<()> {
        MockConn.connect(addr).await
    }
    async fn recv(&self, buf: &mut [u8]) -> util::Result<usize> {
        MockConn.recv(buf).await
    }
    async fn recv_from(&self, buf: &mut [u8]) -> util::Result<(usize, SocketAddr)> {
        MockConn.recv_from(buf).await
    }
    async fn send(&self, buf: &[u8]) -> util::Result<usize> {
        MockConn.send(buf).await
    }
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> util::Result<usize> {
        MockConn.send_to(buf, addr).await
    }
    fn local_addr(&self) -> util::Result<SocketAddr> {
        MockConn.local_addr()
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        None
    }
    async fn close(&self) -> util::Result<()> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

#[tokio::test]
async fn closing_unstarted_or_repeated_candidate_still_releases_connection() {
    for started in [false, true] {
        let connection = Arc::new(TrackedConnection::default());
        let candidate = CandidateBase {
            conn: Some(connection.clone()),
            ..Default::default()
        };
        if started {
            *candidate.closed_ch.lock().await = Some(broadcast::channel(1).0);
        }
        let first = candidate.close().await;
        assert_eq!(first.is_ok(), started);
        assert_eq!(connection.0.load(Ordering::SeqCst), 1);
        assert!(matches!(candidate.close().await, Err(Error::ErrClosed)));
        assert_eq!(connection.0.load(Ordering::SeqCst), 2);
    }
}
