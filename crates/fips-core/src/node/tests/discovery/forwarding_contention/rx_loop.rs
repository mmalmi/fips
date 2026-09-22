//! The transit must wake deferred requests without any locally originated lookup.
use super::*;
use tokio::sync::oneshot;

pub(super) struct Transit {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<Node>,
    _directory: tempfile::TempDir,
}

impl Transit {
    pub(super) async fn start(test: &mut TestNode) -> Self {
        let mut node = std::mem::replace(&mut test.node, make_node());
        assert_eq!(node.pending_lookups.len(), 0);
        let (_, empty) = packet_channel(1);
        node.packet_rx = Some(std::mem::replace(&mut test.packet_rx, empty));
        let directory = tempfile::tempdir().unwrap();
        node.config.node.control.socket_path = directory
            .path()
            .join("relay.sock")
            .to_string_lossy()
            .into_owned();
        node.config.node.discovery.lan.enabled = false;
        node.config.node.discovery.nostr.enabled = false;
        node.config.node.discovery.local.enabled = false;
        node.state = NodeState::Running;
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            tokio::select! {
                result = node.run_rx_loop() => panic!("transit RX loop stopped: {result:?}"),
                _ = stopped => {}
            }
            assert_eq!(
                node.pending_lookups.len(),
                0,
                "transit must have no local lookup timer"
            );
            node
        });
        Self {
            stop,
            task,
            _directory: directory,
        }
    }

    pub(super) async fn restore(self, test: &mut TestNode) {
        self.stop.send(()).unwrap();
        test.node = self.task.await.unwrap();
        let stats = &test.node.stats().discovery;
        eprintln!(
            "autonomous transit: forwarded={}, limited={}",
            stats.req_forwarded, stats.req_forward_rate_limited
        );
    }
}
