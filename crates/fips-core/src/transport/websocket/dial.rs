//! Outbound attempts own their slot and cancellation before any network work.
use super::*;
use tokio::sync::OwnedSemaphorePermit;

pub(super) struct DialAttempt {
    generation: u64,
    network_generation: u64,
    cancelled: oneshot::Receiver<()>,
    _slot: OwnedSemaphorePermit,
}

impl Runtime {
    pub(super) fn prepare_dial(&self, addr: &TransportAddr) -> Result<DialAttempt, TransportError> {
        let pool = self.connections();
        if !self.running.load(Ordering::Acquire) {
            return Err(TransportError::NotStarted);
        }
        let mut statuses = self.statuses();
        if pool.contains_key(addr)
            || statuses.get(addr).is_some_and(|status| {
                matches!(
                    status.state,
                    ConnectionState::Connecting | ConnectionState::Connected
                )
            })
        {
            return Err(TransportError::AlreadyStarted);
        }
        let slot = self
            .total_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| TransportError::ConnectionRefused)?;
        let generation = self.next_generation();
        let (cancel, cancelled) = oneshot::channel();
        statuses.insert(
            addr.clone(),
            ConnectionStatus {
                generation,
                state: ConnectionState::Connecting,
                _cancel: Some(cancel),
            },
        );
        Ok(DialAttempt {
            generation,
            network_generation: *self.network_rebind_generation.borrow(),
            cancelled,
            _slot: slot,
        })
    }
}

pub(super) async fn run_seed_dialer(runtime: Runtime, addr: TransportAddr) {
    let mut delay_ms = runtime.config.reconnect_initial_ms();
    let mut network_rebind_generation = runtime.network_rebind_generation.subscribe();
    let mut observed_network_rebind = *network_rebind_generation.borrow_and_update();
    while runtime.running.load(Ordering::Acquire) {
        runtime
            .stats
            .reconnect_attempts
            .fetch_add(1, Ordering::Relaxed);
        let result = tokio::select! {
            result = async {
                let attempt = runtime.prepare_dial(&addr)?;
                run_dial(runtime.clone(), addr.clone(), attempt).await
            } => result,
            changed = network_rebind_generation.changed() => {
                if changed.is_err() {
                    break;
                }
                observed_network_rebind = *network_rebind_generation.borrow_and_update();
                continue;
            }
        };
        if !runtime.running.load(Ordering::Acquire) {
            break;
        }
        match result {
            Ok(()) => delay_ms = runtime.config.reconnect_initial_ms(),
            Err(error) => {
                debug!(remote_addr = %addr, %error, "WebSocket seed connection failed");
                delay_ms = delay_ms
                    .saturating_mul(2)
                    .min(runtime.config.reconnect_max_ms());
            }
        }
        let requested_network_rebind = *network_rebind_generation.borrow_and_update();
        if requested_network_rebind != observed_network_rebind {
            observed_network_rebind = requested_network_rebind;
            // Explicit network changes bypass ordinary reconnect backoff.
            continue;
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
            changed = network_rebind_generation.changed() => {
                if changed.is_err() {
                    break;
                }
                observed_network_rebind = *network_rebind_generation.borrow_and_update();
            }
        }
    }
}

pub(super) async fn run_one_shot_dial(runtime: Runtime, addr: TransportAddr, attempt: DialAttempt) {
    let _ = run_dial(runtime, addr, attempt).await;
}

async fn run_dial(
    runtime: Runtime,
    addr: TransportAddr,
    mut attempt: DialAttempt,
) -> Result<(), TransportError> {
    let outcome = async {
        let url = addr.as_str().ok_or_else(|| TransportError::InvalidAddress(addr.to_string()))?;
        let connect = connect_async_tls_with_config(
            url, Some(runtime.websocket_config()), false,
            tls::connector(runtime.config.tls_verification())?,
        );
        let (websocket, _) = tokio::select! {
            biased;
            _ = &mut attempt.cancelled => return Ok(()),
            result = tokio::time::timeout(Duration::from_millis(runtime.config.connect_timeout_ms()), connect) => {
                result.map_err(|_| TransportError::Timeout)?
                    .map_err(|error| TransportError::StartFailed(error.to_string()))?
            }
        };
        run_connection(
            runtime.clone(), addr.clone(), websocket, attempt.generation,
            Direction::Outbound, true, attempt.network_generation,
        ).await
    }.await;
    if let Err(error) = &outcome {
        let mut statuses = runtime.statuses();
        if let Some(status) = statuses.get_mut(&addr)
            && status.generation == attempt.generation
        {
            status.state = ConnectionState::Failed(error.to_string());
            status._cancel = None;
        }
    }
    outcome
}
