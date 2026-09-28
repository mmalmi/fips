//! Recover the complete Ethernet binding when a named interface comes and goes.

use super::*;
use std::ffi::{CStr, CString};
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_RETRY: Duration = Duration::from_secs(30);

pub(super) struct Binding {
    pub socket: Arc<AsyncPacketSocket>,
    pub local_mac: [u8; 6],
    pub mtu: u16,
    pub shutdown: tokio::sync::watch::Sender<bool>,
    if_index: u32,
}

impl Binding {
    pub fn shutdown(&self) {
        self.shutdown.send_replace(true);
        self.socket.shutdown();
    }
}

struct Workers {
    binding: Arc<Binding>,
    receive: JoinHandle<()>,
    beacon: Option<JoinHandle<()>>,
}

impl Workers {
    fn finished(&self) -> bool {
        self.receive.is_finished() || self.beacon.as_ref().is_some_and(JoinHandle::is_finished)
    }
}

impl Drop for Workers {
    fn drop(&mut self) {
        self.binding.shutdown();
        self.receive.abort();
        if let Some(task) = &self.beacon {
            task.abort();
        }
    }
}

pub(super) struct BindingSupervisor {
    published: Arc<RwLock<Option<Arc<Binding>>>>,
    config: EthernetConfig,
    interface: CString,
    transport_id: TransportId,
    packet_tx: PacketTx,
    discovery_buffer: Arc<DiscoveryBuffer>,
    stats: Arc<EthernetStats>,
    pubkey: Option<XOnlyPublicKey>,
    discovery_root: Arc<Mutex<Option<NodeAddr>>>,
    workers: Option<Workers>,
    retry_at: Instant,
    retry_delay: Duration,
    last_index: Option<u32>,
}

impl BindingSupervisor {
    pub fn new(transport: &EthernetTransport) -> Result<Self, TransportError> {
        let name = &transport.interface;
        if name.is_empty() || name.len() >= libc::IFNAMSIZ {
            return Err(TransportError::InvalidAddress(
                "invalid Ethernet interface name".into(),
            ));
        }
        let interface = CString::new(name.as_str())
            .map_err(|_| TransportError::InvalidAddress("interface name contains NUL".into()))?;
        Ok(Self {
            published: transport.binding.clone(),
            config: transport.config.clone(),
            interface,
            transport_id: transport.transport_id,
            packet_tx: transport.packet_tx.clone(),
            discovery_buffer: transport.discovery_buffer.clone(),
            stats: transport.stats.clone(),
            pubkey: transport.local_pubkey,
            discovery_root: transport.discovery_root.clone(),
            workers: None,
            retry_at: Instant::now(),
            retry_delay: POLL_INTERVAL,
            last_index: None,
        })
    }

    pub async fn run(mut self) {
        loop {
            tokio::time::sleep(POLL_INTERVAL).await;
            self.refresh().await;
        }
    }

    pub async fn refresh(&mut self) {
        let now = Instant::now();
        let index = match present_interface(&self.interface) {
            Ok(index) => index,
            Err(error) => {
                if now >= self.retry_at {
                    self.retry(error, now);
                }
                return;
            }
        };
        if index != self.last_index {
            self.retry_at = now;
            self.retry_delay = POLL_INTERVAL;
            self.last_index = index;
        }
        if self
            .workers
            .as_ref()
            .is_some_and(|w| Some(w.binding.if_index) != index || w.finished())
        {
            self.published
                .write()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(workers) = self.workers.take() {
                workers.binding.shutdown();
                workers.receive.abort();
                if let Some(task) = &workers.beacon {
                    task.abort();
                }
                // Give aborted workers a chance to release their socket before rebinding.
                tokio::task::yield_now().await;
                drop(workers);
            }
            self.discovery_buffer.take();
            info!(transport_id = %self.transport_id, interface = %self.config.interface,
                "Ethernet binding lost; waiting to recover");
        }
        if self.workers.is_some() || index.is_none() || now < self.retry_at {
            return;
        }
        match self.bind() {
            Ok(workers) => {
                info!(transport_id = %self.transport_id, interface = %self.config.interface,
                    mac = %format_mac(&workers.binding.local_mac), mtu = workers.binding.mtu,
                    "Ethernet interface bound");
                *self.published.write().unwrap_or_else(|e| e.into_inner()) =
                    Some(workers.binding.clone());
                self.workers = Some(workers);
                self.retry_delay = POLL_INTERVAL;
            }
            Err(error) => self.retry(error, now),
        }
    }

    fn retry(&mut self, error: impl std::fmt::Display, now: Instant) {
        warn!(transport_id = %self.transport_id, interface = %self.config.interface,
            %error, retry_secs = self.retry_delay.as_secs(), "Ethernet binding unavailable; will retry");
        self.retry_at = now + self.retry_delay;
        self.retry_delay = (self.retry_delay * 2).min(MAX_RETRY);
    }

    fn bind(&self) -> Result<Workers, TransportError> {
        let raw = PacketSocket::open(&self.config.interface, self.config.ethertype())?;
        let local_mac = raw.local_mac()?;
        let mtu = raw
            .interface_mtu()?
            .saturating_sub(3)
            .min(self.config.mtu.unwrap_or(u16::MAX));
        let if_index = raw.if_index() as u32;
        raw.set_recv_buffer_size(self.config.recv_buf_size())?;
        raw.set_send_buffer_size(self.config.send_buf_size())?;
        let socket = Arc::new(raw.into_async()?);
        let (shutdown, _) = tokio::sync::watch::channel(false);
        let binding = Arc::new(Binding {
            socket: socket.clone(),
            local_mac,
            mtu,
            if_index,
            shutdown,
        });
        let receive = tokio::spawn(ethernet_receive_loop(EthernetReceiveContext {
            socket: socket.clone(),
            transport_id: self.transport_id,
            packet_tx: self.packet_tx.clone(),
            mtu,
            discovery_enabled: self.config.discovery(),
            discovery_buffer: self.discovery_buffer.clone(),
            stats: self.stats.clone(),
            local_mac,
        }));
        let beacon = if self.config.announce() {
            self.pubkey.map(|pubkey| {
                tokio::spawn(beacon_sender_loop(EthernetBeaconContext {
                    socket,
                    pubkey,
                    discovery_scope: self.config.discovery_scope().map(str::to_string),
                    discovery_root: self.discovery_root.clone(),
                    interval_secs: self.config.beacon_interval_secs(),
                    stats: self.stats.clone(),
                    transport_id: self.transport_id,
                }))
            })
        } else {
            None
        };
        Ok(Workers {
            binding,
            receive,
            beacon,
        })
    }
}

impl Drop for BindingSupervisor {
    fn drop(&mut self) {
        self.published
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        // Workers' Drop closes the socket and aborts both tasks, including on cancellation.
    }
}

/// Only an administratively up interface is bindable. The index distinguishes
/// a recreated interface with the same name from the previous socket's device.
fn present_interface(name: &CStr) -> std::io::Result<Option<u32>> {
    let mut head = std::ptr::null_mut();
    // SAFETY: getifaddrs initializes head on success; the list lives until freeifaddrs below.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut current = head;
    let mut present = false;
    while !current.is_null() {
        // SAFETY: current traverses the valid getifaddrs list.
        let entry = unsafe { &*current };
        if !entry.ifa_name.is_null()
            && unsafe { CStr::from_ptr(entry.ifa_name) } == name
            && entry.ifa_flags & libc::IFF_UP as u32 != 0
        {
            present = true;
            break;
        }
        current = entry.ifa_next;
    }
    unsafe { libc::freeifaddrs(head) };
    if !present {
        return Ok(None);
    }
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    Ok((index != 0).then_some(index))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn missing_interface_can_stop_and_restart() {
        let (tx, _rx) = crate::transport::packet_channel(4);
        let config = EthernetConfig {
            interface: "fips-absent".into(),
            ..Default::default()
        };
        assert_eq!(
            present_interface(&CString::new(config.interface.clone()).unwrap()).unwrap(),
            None
        );
        let mut transport = EthernetTransport::new(TransportId::new(1), None, config, tx);
        transport.start_async().await.unwrap();
        assert_eq!(transport.state(), TransportState::Down);
        assert!(matches!(
            transport.start_async().await,
            Err(TransportError::AlreadyStarted)
        ));
        assert!(matches!(
            transport
                .send_async(&TransportAddr::from_bytes(&[1; 6]), b"hello")
                .await,
            Err(TransportError::NotStarted)
        ));
        tokio::time::timeout(Duration::from_millis(500), transport.stop_async())
            .await
            .unwrap()
            .unwrap();
        transport.start_async().await.unwrap();
        transport.stop_async().await.unwrap();
        assert!(transport.binding_task.is_none());
    }

    #[cfg(target_os = "linux")]
    fn ip(args: &[&str]) {
        let output = std::process::Command::new("ip")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "ip {args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[cfg(target_os = "linux")]
    struct Pair {
        left: String,
        right: String,
        created: bool,
    }

    #[cfg(target_os = "linux")]
    impl Pair {
        fn create(&mut self, mtu: &str) {
            ip(&[
                "link",
                "add",
                &self.left,
                "type",
                "veth",
                "peer",
                "name",
                &self.right,
            ]);
            self.created = true;
            for name in [&self.left, &self.right] {
                ip(&["link", "set", name, "mtu", mtu, "up"]);
            }
        }
        fn remove(&mut self) {
            ip(&["link", "del", &self.left]);
            self.created = false;
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for Pair {
        fn drop(&mut self) {
            if self.created {
                let _ = std::process::Command::new("ip")
                    .args(["link", "del", &self.left])
                    .status();
            }
        }
    }

    #[cfg(target_os = "linux")]
    async fn until(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(6), async {
            while !condition() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("interface binding did not converge");
    }

    #[cfg(target_os = "linux")]
    async fn exchange(
        from: &EthernetTransport,
        to: &EthernetTransport,
        rx: &mut crate::transport::PacketRx,
        payload: &[u8],
    ) {
        let destination = TransportAddr::from_bytes(&to.local_mac().unwrap());
        assert_eq!(
            from.send_async(&destination, payload).await.unwrap(),
            payload.len()
        );
        let packet = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet.data.as_slice(), payload);
        assert_eq!(packet.remote_addr.as_bytes(), &from.local_mac().unwrap());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires CAP_NET_ADMIN, CAP_NET_RAW and ip in an isolated network namespace"]
    async fn kernel_ethernet_recovers_data_and_beacons_after_interface_churn() {
        let id = std::process::id();
        let mut pair = Pair {
            left: format!("fb{id}a"),
            right: format!("fb{id}b"),
            created: false,
        };
        let (left_tx, mut left_rx) = crate::transport::packet_channel(16);
        let (right_tx, mut right_rx) = crate::transport::packet_channel(16);
        let config = |name: &str| EthernetConfig {
            interface: name.into(),
            announce: Some(true),
            discovery: Some(true),
            ..Default::default()
        };
        let mut left =
            EthernetTransport::new(TransportId::new(1), None, config(&pair.left), left_tx);
        let mut right =
            EthernetTransport::new(TransportId::new(2), None, config(&pair.right), right_tx);
        let public_key = |byte| {
            secp256k1::SecretKey::from_slice(&[byte; 32])
                .unwrap()
                .public_key(&secp256k1::Secp256k1::new())
                .x_only_public_key()
                .0
        };
        left.set_local_pubkey(public_key(1));
        right.set_local_pubkey(public_key(2));
        left.start_async().await.unwrap();
        right.start_async().await.unwrap();
        assert_eq!(left.state(), TransportState::Down);
        pair.create("1500");
        until(|| left.state().is_operational() && right.state().is_operational()).await;
        exchange(&left, &right, &mut right_rx, b"first").await;
        exchange(&right, &left, &mut left_rx, b"reply").await;

        ip(&["link", "set", &pair.left, "down"]);
        until(|| left.state() == TransportState::Down).await;
        ip(&["link", "set", &pair.left, "up"]);
        until(|| left.state().is_operational()).await;
        exchange(&left, &right, &mut right_rx, b"after administrative up").await;

        // Recreate between polls: name remains the same, index/MAC/MTU change.
        let old = left.current_binding().unwrap();
        let old_right = right.current_binding().unwrap();
        pair.remove();
        pair.create("1300");
        until(|| {
            left.current_binding()
                .is_some_and(|b| b.if_index != old.if_index)
                && right
                    .current_binding()
                    .is_some_and(|b| b.if_index != old_right.if_index)
        })
        .await;
        assert!(*old.shutdown.borrow());
        assert!(*old_right.shutdown.borrow());
        assert_ne!(left.local_mac(), Some(old.local_mac));
        assert_eq!(left.mtu(), 1297);
        exchange(&left, &right, &mut right_rx, b"after recreation").await;
        exchange(&right, &left, &mut left_rx, b"new receive socket").await;
        assert!(matches!(
            left.send_async(
                &TransportAddr::from_bytes(&right.local_mac().unwrap()),
                &[0; 1298]
            )
            .await,
            Err(TransportError::MtuExceeded { mtu: 1297, .. })
        ));
        // Fresh worker beacons share the new data socket and preserve discovery.
        until(|| !left.discover().unwrap().is_empty() || !right.discover().unwrap().is_empty())
            .await;

        pair.remove();
        until(|| left.state() == TransportState::Down && right.state() == TransportState::Down)
            .await;
        left.stop_async().await.unwrap();
        right.stop_async().await.unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires Linux CAP_NET_RAW; run alone to count descriptors"]
    fn kernel_failed_socket_bind_does_not_leak_descriptors() {
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let before = count();
        for _ in 0..100 {
            assert!(PacketSocket::open("fips-absent", 0x2121).is_err());
        }
        assert_eq!(count(), before);
    }
}
