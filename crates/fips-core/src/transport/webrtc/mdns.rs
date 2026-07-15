use super::*;
use futures::stream::{self, StreamExt, TryStreamExt};
use mdns_sd::{DaemonStatus, HostnameResolutionEvent, ServiceDaemon};
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::ops::Range;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use tokio::sync::{Mutex, Semaphore};

const MAX_MDNS_WAITERS: usize = 8;
const MAX_MDNS_HOSTNAMES: usize = 32;
const MDNS_RESOLVE_TIMEOUT: Duration = Duration::from_millis(1_750);
const MDNS_BATCH_TIMEOUT: Duration = Duration::from_millis(1_900);

#[derive(Clone)]
pub(super) struct SharedMdnsResolver(Option<Arc<SharedMdnsResolverInner>>);

struct SharedMdnsResolverInner {
    daemon: StdMutex<Option<ServiceDaemon>>,
    request_lock: Mutex<()>,
    waiter_permits: Arc<Semaphore>,
    max_waiters: usize,
    active_waiters: AtomicUsize,
    peak_waiters: AtomicUsize,
    accepting: AtomicBool,
}

struct ResolutionGuard {
    resolver: Arc<SharedMdnsResolverInner>,
    daemon: ServiceDaemon,
    hostname: String,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct MdnsResolverSnapshot {
    pub owner_count: usize,
    pub max_waiters: usize,
    pub active_waiters: usize,
    pub peak_waiters: usize,
}

impl SharedMdnsResolver {
    pub(super) fn new(enabled: bool, max_connections: usize) -> Result<Self, TransportError> {
        if !enabled {
            return Ok(Self(None));
        }
        let max_waiters = max_connections.clamp(1, MAX_MDNS_WAITERS);
        Ok(Self(Some(Arc::new(SharedMdnsResolverInner {
            daemon: StdMutex::new(None),
            request_lock: Mutex::new(()),
            waiter_permits: Arc::new(Semaphore::new(max_waiters)),
            max_waiters,
            active_waiters: AtomicUsize::new(0),
            peak_waiters: AtomicUsize::new(0),
            accepting: AtomicBool::new(true),
        }))))
    }

    pub(super) fn start_accepting(&self) {
        if let Some(inner) = &self.0 {
            inner.accepting.store(true, Ordering::Release);
        }
    }

    pub(super) async fn stop(&self) -> Result<(), TransportError> {
        let Some(inner) = &self.0 else {
            return Ok(());
        };
        inner.accepting.store(false, Ordering::Release);
        let daemon = inner.daemon.lock().expect("WebRTC mDNS daemon").take();
        let Some(daemon) = daemon else {
            return Ok(());
        };
        let shutdown = daemon.shutdown().map_err(|error| {
            TransportError::ShutdownFailed(format!(
                "failed to stop shared WebRTC mDNS resolver: {error}"
            ))
        })?;
        match tokio::time::timeout(WEBRTC_IO_TIMEOUT, shutdown.recv_async()).await {
            Ok(Ok(DaemonStatus::Shutdown)) => Ok(()),
            Ok(Ok(status)) => Err(TransportError::ShutdownFailed(format!(
                "shared WebRTC mDNS resolver stopped with {status:?}"
            ))),
            Ok(Err(error)) => Err(TransportError::ShutdownFailed(format!(
                "shared WebRTC mDNS resolver status channel closed: {error}"
            ))),
            Err(_) => Err(TransportError::ShutdownFailed(
                "shared WebRTC mDNS resolver did not stop before timeout".into(),
            )),
        }
    }

    pub(super) async fn resolve_sdp(&self, sdp: &str) -> Result<String, TransportError> {
        let hostnames = mdns_candidate_hostnames(sdp)?;
        if hostnames.is_empty() {
            return Ok(sdp.to_string());
        }
        let Some(inner) = &self.0 else {
            return strip_mdns_candidates(sdp);
        };
        if !inner.accepting.load(Ordering::Acquire) {
            return Err(TransportError::NotStarted);
        }

        // mdns-sd has one listener slot per hostname. Serializing SDP batches
        // prevents two negotiations for the same browser hostname from
        // replacing one another while still resolving distinct candidates in
        // parallel under the transport-wide waiter bound.
        let resolve = async {
            let _request = inner.request_lock.lock().await;
            let daemon = inner.daemon()?;
            stream::iter(hostnames)
                .map(|hostname| {
                    let inner = Arc::clone(inner);
                    let daemon = daemon.clone();
                    async move {
                        let address = resolve_hostname(inner, daemon, hostname.clone()).await?;
                        Ok::<_, TransportError>((hostname, address))
                    }
                })
                .buffer_unordered(inner.max_waiters)
                .try_collect::<HashMap<_, _>>()
                .await
        };
        let resolved = tokio::time::timeout(MDNS_BATCH_TIMEOUT, resolve)
            .await
            .map_err(|_| TransportError::Timeout)??;

        rewrite_mdns_candidates(sdp, &resolved)
    }

    #[cfg(test)]
    pub(super) fn snapshot(&self) -> MdnsResolverSnapshot {
        match &self.0 {
            Some(inner) => MdnsResolverSnapshot {
                owner_count: usize::from(
                    inner.daemon.lock().expect("WebRTC mDNS daemon").is_some(),
                ),
                max_waiters: inner.max_waiters,
                active_waiters: inner.active_waiters.load(Ordering::Acquire),
                peak_waiters: inner.peak_waiters.load(Ordering::Acquire),
            },
            None => MdnsResolverSnapshot {
                owner_count: 0,
                max_waiters: 0,
                active_waiters: 0,
                peak_waiters: 0,
            },
        }
    }
}

impl Drop for SharedMdnsResolverInner {
    fn drop(&mut self) {
        self.accepting.store(false, Ordering::Release);
        if let Some(daemon) = self.daemon.get_mut().expect("WebRTC mDNS daemon").take() {
            let _ = daemon.shutdown();
        }
    }
}

impl SharedMdnsResolverInner {
    fn daemon(&self) -> Result<ServiceDaemon, TransportError> {
        if !self.accepting.load(Ordering::Acquire) {
            return Err(TransportError::NotStarted);
        }
        let mut daemon = self.daemon.lock().expect("WebRTC mDNS daemon");
        if daemon.is_none() {
            *daemon = Some(ServiceDaemon::new().map_err(|error| {
                TransportError::StartFailed(format!(
                    "failed to start shared WebRTC mDNS resolver: {error}"
                ))
            })?);
        }
        Ok(daemon.as_ref().expect("initialized mDNS daemon").clone())
    }
}

impl Drop for ResolutionGuard {
    fn drop(&mut self) {
        self.resolver.active_waiters.fetch_sub(1, Ordering::AcqRel);
        // This also runs when the negotiation future is aborted, removing the
        // daemon's hostname listener instead of leaving a background query.
        let _ = self.daemon.stop_resolve_hostname(&self.hostname);
    }
}

async fn resolve_hostname(
    resolver: Arc<SharedMdnsResolverInner>,
    daemon: ServiceDaemon,
    hostname: String,
) -> Result<IpAddr, TransportError> {
    let _permit = Arc::clone(&resolver.waiter_permits)
        .acquire_owned()
        .await
        .map_err(|_| TransportError::NotStarted)?;
    let receiver = daemon
        .resolve_hostname(&hostname, Some(MDNS_RESOLVE_TIMEOUT.as_millis() as u64))
        .map_err(|error| {
            TransportError::StartFailed(format!(
                "failed to resolve WebRTC mDNS candidate {hostname}: {error}"
            ))
        })?;
    let active = resolver.active_waiters.fetch_add(1, Ordering::AcqRel) + 1;
    resolver.peak_waiters.fetch_max(active, Ordering::AcqRel);
    let _guard = ResolutionGuard {
        resolver,
        daemon,
        hostname: hostname.clone(),
    };

    let wait = async {
        loop {
            match receiver.recv_async().await {
                Ok(HostnameResolutionEvent::AddressesFound(_, addresses)) => {
                    if let Some(address) =
                        preferred_address(addresses.iter().map(|ip| ip.to_ip_addr()))
                    {
                        return Ok(address);
                    }
                }
                Ok(HostnameResolutionEvent::SearchTimeout(_)) => {
                    return Err(TransportError::Timeout);
                }
                Ok(HostnameResolutionEvent::SearchStopped(_)) | Err(_) => {
                    return Err(TransportError::StartFailed(format!(
                        "WebRTC mDNS resolution stopped for {hostname}"
                    )));
                }
                Ok(_) => {}
            }
        }
    };
    tokio::time::timeout(MDNS_RESOLVE_TIMEOUT + Duration::from_millis(100), wait)
        .await
        .map_err(|_| TransportError::Timeout)?
}

fn preferred_address(addresses: impl Iterator<Item = IpAddr>) -> Option<IpAddr> {
    let mut addresses = addresses.collect::<Vec<_>>();
    addresses.sort_by_key(|address| (usize::from(address.is_ipv6()), address.to_string()));
    addresses.into_iter().next()
}

fn mdns_candidate_hostnames(sdp: &str) -> Result<Vec<String>, TransportError> {
    let mut hostnames = BTreeSet::new();
    for line in sdp.lines() {
        let Some(range) = candidate_address_range(line) else {
            continue;
        };
        let address = &line[range];
        if is_mdns_hostname(address) {
            hostnames.insert(normalize_mdns_hostname(address)?);
            if hostnames.len() > MAX_MDNS_HOSTNAMES {
                return Err(TransportError::InvalidAddress(format!(
                    "WebRTC SDP contains more than {MAX_MDNS_HOSTNAMES} mDNS candidates"
                )));
            }
        }
    }
    Ok(hostnames.into_iter().collect())
}

fn strip_mdns_candidates(sdp: &str) -> Result<String, TransportError> {
    let mut stripped = String::with_capacity(sdp.len());
    for segment in sdp.split_inclusive('\n') {
        let line = segment
            .strip_suffix("\r\n")
            .or_else(|| segment.strip_suffix('\n'))
            .unwrap_or(segment);
        let Some(range) = candidate_address_range(line) else {
            stripped.push_str(segment);
            continue;
        };
        let address = &line[range];
        if is_mdns_hostname(address) {
            normalize_mdns_hostname(address)?;
        } else {
            stripped.push_str(segment);
        }
    }
    Ok(stripped)
}

fn rewrite_mdns_candidates(
    sdp: &str,
    addresses: &HashMap<String, IpAddr>,
) -> Result<String, TransportError> {
    let mut rewritten = String::with_capacity(sdp.len());
    for segment in sdp.split_inclusive('\n') {
        let (line, ending) = segment
            .strip_suffix("\r\n")
            .map(|line| (line, "\r\n"))
            .or_else(|| segment.strip_suffix('\n').map(|line| (line, "\n")))
            .unwrap_or((segment, ""));
        let Some(range) = candidate_address_range(line) else {
            rewritten.push_str(segment);
            continue;
        };
        let candidate = &line[range.clone()];
        if !is_mdns_hostname(candidate) {
            rewritten.push_str(segment);
            continue;
        }
        let hostname = normalize_mdns_hostname(candidate)?;
        let address = addresses.get(&hostname).ok_or_else(|| {
            TransportError::StartFailed(format!(
                "WebRTC mDNS candidate {hostname} was not resolved"
            ))
        })?;
        rewritten.push_str(&line[..range.start]);
        rewritten.push_str(&address.to_string());
        rewritten.push_str(&line[range.end..]);
        rewritten.push_str(ending);
    }
    Ok(rewritten)
}

fn candidate_address_range(line: &str) -> Option<Range<usize>> {
    const PREFIX: &str = "a=candidate:";
    line.strip_prefix(PREFIX)?;
    let mut fields = Vec::with_capacity(6);
    let mut start = None;
    for (index, character) in line
        .char_indices()
        .skip_while(|(index, _)| *index < PREFIX.len())
    {
        if character.is_ascii_whitespace() {
            if let Some(field_start) = start.take() {
                fields.push(field_start..index);
                if fields.len() == 6 {
                    break;
                }
            }
        } else if start.is_none() {
            start = Some(index);
        }
    }
    if fields.len() < 6
        && let Some(field_start) = start
    {
        fields.push(field_start..line.len());
    }
    fields.get(4).cloned()
}

fn is_mdns_hostname(address: &str) -> bool {
    address
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .ends_with(".local")
}

fn normalize_mdns_hostname(hostname: &str) -> Result<String, TransportError> {
    let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
    let labels = hostname.split('.').collect::<Vec<_>>();
    let valid = hostname.len() <= 253
        && labels.len() >= 2
        && labels.last() == Some(&"local")
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(TransportError::InvalidAddress(format!(
            "invalid WebRTC mDNS candidate hostname {hostname}"
        )));
    }
    Ok(format!("{hostname}."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    fn first_non_loopback_ipv4() -> Option<std::net::Ipv4Addr> {
        if_addrs::get_if_addrs()
            .ok()?
            .into_iter()
            .filter(|interface| {
                interface.is_oper_up()
                    && !interface.is_p2p()
                    && !interface.is_loopback()
                    && !interface.name.starts_with("awdl")
                    && !interface.name.starts_with("llw")
            })
            .find_map(|interface| match interface.ip() {
                IpAddr::V4(address) => Some(address),
                IpAddr::V6(_) => None,
            })
    }

    #[test]
    fn candidate_parser_rewrites_only_the_connection_address() {
        let sdp = concat!(
            "v=0\r\n",
            "a=candidate:1 1 UDP 2122260223 browser-host.local 5000 typ host generation 0\r\n",
            "a=candidate:2 1 UDP 1 192.0.2.4 5001 typ host\r\n",
            "a=ice-options:trickle\r\n"
        );
        let hostname = "browser-host.local.".to_string();
        assert_eq!(
            mdns_candidate_hostnames(sdp).unwrap(),
            vec![hostname.clone()]
        );
        let rewritten = rewrite_mdns_candidates(
            sdp,
            &HashMap::from([(hostname, "192.0.2.8".parse().unwrap())]),
        )
        .unwrap();
        assert_eq!(
            rewritten,
            sdp.replacen("browser-host.local", "192.0.2.8", 1)
        );
    }

    #[test]
    fn candidate_parser_deduplicates_and_validates_mdns_names() {
        let repeated = concat!(
            "a=candidate:1 1 UDP 1 Browser-Host.LOCAL 5000 typ host\n",
            "a=candidate:2 1 UDP 1 browser-host.local. 5001 typ host\n"
        );
        assert_eq!(
            mdns_candidate_hostnames(repeated).unwrap(),
            vec!["browser-host.local.".to_string()]
        );
        let invalid = "a=candidate:1 1 UDP 1 -bad.local 5000 typ host\r\n";
        assert!(matches!(
            mdns_candidate_hostnames(invalid),
            Err(TransportError::InvalidAddress(_))
        ));
    }

    #[test]
    fn malformed_or_non_candidate_lines_are_left_to_the_sdp_parser() {
        let sdp = concat!(
            "a=x-note:browser.local\r\n",
            "a=candidate:too few browser.local\r\n",
            "a=candidate:1 1 UDP 1 198.51.100.1 5000 typ host\r\n"
        );
        assert!(mdns_candidate_hostnames(sdp).unwrap().is_empty());
        assert_eq!(rewrite_mdns_candidates(sdp, &HashMap::new()).unwrap(), sdp);
    }

    #[test]
    fn candidate_parser_caps_unique_mdns_hostnames() {
        let sdp = (0..=MAX_MDNS_HOSTNAMES)
            .map(|index| {
                format!("a=candidate:{index} 1 UDP 1 browser-{index}.local 5000 typ host\r\n")
            })
            .collect::<String>();
        assert!(matches!(
            mdns_candidate_hostnames(&sdp),
            Err(TransportError::InvalidAddress(message)) if message.contains("more than 32")
        ));
    }

    #[tokio::test]
    async fn batch_deadline_includes_waiting_for_the_request_lock() {
        let resolver = SharedMdnsResolver::new(true, 1).expect("shared resolver");
        let first = resolver.clone();
        let first_task = tokio::spawn(async move {
            first
                .resolve_sdp("a=candidate:1 1 UDP 1 first-unresolved.local 5000 typ host\r\n")
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), async {
            while resolver.snapshot().active_waiters == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first query owns request lock");

        let started = tokio::time::Instant::now();
        assert!(matches!(
            resolver
                .resolve_sdp("a=candidate:2 1 UDP 1 second-unresolved.local 5001 typ host\r\n")
                .await,
            Err(TransportError::Timeout)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        first_task.abort();
        let _ = first_task.await;
        resolver.stop().await.expect("stop shared resolver");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn registered_hostname_is_resolved_and_rewritten_by_the_shared_owner() {
        let address = first_non_loopback_ipv4().expect("non-loopback IPv4 interface");
        let hostname = format!("fips-webrtc-{}.local.", random_session_id());
        let server = ServiceDaemon::new().expect("mDNS test responder");
        let service = mdns_sd::ServiceInfo::new(
            "_fips-wrtc._udp.local.",
            "shared-resolver",
            &hostname,
            IpAddr::V4(address),
            9,
            None,
        )
        .expect("mDNS test service");
        let resolver = SharedMdnsResolver::new(true, 4).expect("shared resolver");
        let sdp = format!(
            "v=0\r\na=candidate:1 1 UDP 1 {} 5000 typ host\r\n",
            hostname.trim_end_matches('.')
        );
        let task_resolver = resolver.clone();
        let resolve_task = tokio::spawn(async move { task_resolver.resolve_sdp(&sdp).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while resolver.snapshot().active_waiters != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shared resolver query starts");
        server.register(service).expect("register mDNS test host");

        let rewritten = resolve_task
            .await
            .expect("mDNS resolution task")
            .expect("resolve mDNS SDP");
        assert!(rewritten.contains(&address.to_string()));
        assert!(!rewritten.contains(".local"));
        assert_eq!(resolver.snapshot().owner_count, 1);
        resolver.stop().await.expect("stop shared resolver");
        assert_eq!(resolver.snapshot().owner_count, 0);

        let shutdown = server.shutdown().expect("stop mDNS test responder");
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(1), shutdown.recv_async()).await,
            Ok(Ok(DaemonStatus::Shutdown))
        ));
    }
}
