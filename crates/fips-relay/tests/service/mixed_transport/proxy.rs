//! Bounded loopback carrier interruption, shared by WS and TLS process checks.
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::TlsAcceptor;

pub struct StreamProxy {
    pub address: SocketAddr,
    connections: Arc<AtomicUsize>,
    interrupt: mpsc::Sender<oneshot::Sender<usize>>,
    task: JoinHandle<()>,
}

impl StreamProxy {
    pub async fn start(backend: SocketAddr, acceptor: Option<TlsAcceptor>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let (interrupt, mut requests) = mpsc::channel::<oneshot::Sender<usize>>(1);
        let accepted = connections.clone();
        let task = tokio::spawn(async move {
            let mut sessions = JoinSet::new();
            loop {
                tokio::select! {
                    Some(reply) = requests.recv() => {
                        let count = sessions.len();
                        sessions.abort_all();
                        while let Some(result) = sessions.join_next().await {
                            if let Err(error) = result {
                                assert!(error.is_cancelled(), "proxy session panicked: {error}");
                            }
                        }
                        // Acknowledge after both halves of every stream have closed.
                        reply.send(count).unwrap();
                    }
                    stream = listener.accept(), if sessions.len() < 16 => {
                        let (stream, _) = stream.unwrap();
                        let acceptor = acceptor.clone();
                        let accepted = accepted.clone();
                        sessions.spawn(async move {
                            if let Some(acceptor) = acceptor {
                                if let Ok(Ok(stream)) = tokio::time::timeout(
                                    Duration::from_secs(5), acceptor.accept(stream),
                                ).await {
                                    forward(stream, backend, accepted).await;
                                }
                            } else {
                                forward(stream, backend, accepted).await;
                            }
                        });
                    }
                    Some(result) = sessions.join_next(), if !sessions.is_empty() => {
                        result.unwrap();
                    }
                }
            }
        });
        Self {
            address,
            connections,
            interrupt,
            task,
        }
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    pub async fn interrupt(&self) -> usize {
        let (reply, received) = oneshot::channel();
        self.interrupt.send(reply).await.unwrap();
        received.await.unwrap()
    }
}

impl Drop for StreamProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn forward<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    backend: SocketAddr,
    accepted: Arc<AtomicUsize>,
) {
    let Ok(mut upstream) = TcpStream::connect(backend).await else {
        return;
    };
    accepted.fetch_add(1, Ordering::SeqCst);
    let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
}
