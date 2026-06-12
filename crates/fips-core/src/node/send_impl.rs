use super::*;

impl Node {
    // === Sending ===

    /// Encrypt and send a link-layer message to an authenticated peer.
    ///
    /// The plaintext should include the message type byte followed by the
    /// message-specific payload (e.g., `[0x50, reason]` for Disconnect).
    ///
    /// The send path prepends a 4-byte session-relative timestamp (inner
    /// header) before encryption. The full 16-byte outer header is used
    /// as AAD for the AEAD construction.
    ///
    /// This is the standard path for sending any link-layer control message
    /// to a peer over their encrypted Noise session.
    pub(super) async fn send_encrypted_link_message(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
    ) -> Result<(), NodeError> {
        self.send_encrypted_link_message_with_ce(node_addr, plaintext, false)
            .await
    }

    pub(super) fn map_fmp_send_preparation_error(
        node_addr: NodeAddr,
        error: FmpSendPreparationError,
    ) -> NodeError {
        match error {
            FmpSendPreparationError::MissingPeer => NodeError::PeerNotFound(node_addr),
            FmpSendPreparationError::MissingTheirIndex => NodeError::SendFailed {
                node_addr,
                reason: "no their_index".into(),
            },
            FmpSendPreparationError::MissingTransportId => NodeError::SendFailed {
                node_addr,
                reason: "no transport_id".into(),
            },
            FmpSendPreparationError::MissingCurrentAddr => NodeError::SendFailed {
                node_addr,
                reason: "no current_addr".into(),
            },
            FmpSendPreparationError::MissingNoiseSession => NodeError::SendFailed {
                node_addr,
                reason: "no noise session".into(),
            },
            FmpSendPreparationError::PayloadLengthMismatch => NodeError::SendFailed {
                node_addr,
                reason: "payload length mismatch".into(),
            },
            FmpSendPreparationError::CounterReservationFailed => NodeError::SendFailed {
                node_addr,
                reason: "counter reservation failed".into(),
            },
            FmpSendPreparationError::EncryptionFailed => NodeError::SendFailed {
                node_addr,
                reason: "encryption failed".into(),
            },
        }
    }

    #[cfg(unix)]
    pub(super) fn map_fsp_worker_send_reservation_error(
        node_addr: NodeAddr,
        error: FspWorkerSendReservationError,
    ) -> NodeError {
        match error {
            FspWorkerSendReservationError::MissingSession => NodeError::SendFailed {
                node_addr,
                reason: "no session".into(),
            },
            FspWorkerSendReservationError::NotEstablished => NodeError::SendFailed {
                node_addr,
                reason: "session not established".into(),
            },
            FspWorkerSendReservationError::CounterReservationFailed => NodeError::SendFailed {
                node_addr,
                reason: "session counter reservation failed".into(),
            },
        }
    }

    /// Like `send_encrypted_link_message` but allows setting the FMP CE flag.
    ///
    /// Used by the forwarding path to relay congestion signals hop-by-hop.
    pub(super) async fn send_encrypted_link_message_with_ce(
        &mut self,
        node_addr: &NodeAddr,
        plaintext: &[u8],
        ce_flag: bool,
    ) -> Result<(), NodeError> {
        // The inner-plaintext layout is `[ts:4 LE][plaintext...]`, so
        // its length is exactly `INNER_TS_LEN + plaintext.len()` — no
        // need to build the Vec just to measure it. The worker path uses
        // this length to size the wire buffer directly; the legacy path
        // below still materialises a separate `inner_plaintext` Vec for
        // the inline encrypt-and-send call.
        const INNER_TS_LEN: usize = 4;
        let inner_len = INNER_TS_LEN + plaintext.len();
        let payload_len = inner_len as u16;
        let prepared = self
            .peers
            .prepare_fmp_send(node_addr, ce_flag, payload_len)
            .map_err(|e| Self::map_fmp_send_preparation_error(*node_addr, e))?;

        // **Unix UDP send fast path.** On Unix, the encrypt-worker pool
        // is spawned at lifecycle start (workers = num_cpus) in
        // production, so this branch is taken for every authentic send on
        // every UDP-transported established session. The AEAD work +
        // sendmsg syscall run on a dedicated OS thread; the rx_loop only
        // builds the wire buffer + reserves the counter inline.
        //
        // Other transport kinds (BLE, TCP, sim, ethernet) fall
        // through to the inline encrypt + transport.send path
        // below — those don't have raw-fd / sendmmsg / UDP_GSO
        // benefits to expose through the worker pool, so the simpler
        // synchronous send is the right shape for them.
        //
        // Windows intentionally stays on the inline tokio UDP send path:
        // lifecycle::start does not spawn these raw-fd workers there, and
        // tests may still set `encrypt_workers` manually.
        //
        // The `encrypt_workers.is_some()` check below is true in Unix
        // production (lifecycle::start spawns the pool); it stays checked
        // rather than `expect()`-ed because unit tests construct `Node`
        // without calling `start()`.
        let transport_for_send = self
            .transports
            .get(&prepared.transport_id)
            .ok_or(NodeError::TransportNotFound(prepared.transport_id))?;
        match transport_for_send.connection_state(&prepared.remote_addr) {
            ConnectionState::Connected => {}
            other => {
                if matches!(other, ConnectionState::None) {
                    let _ = transport_for_send.connect(&prepared.remote_addr).await;
                }
                return Err(NodeError::SendFailed {
                    node_addr: *node_addr,
                    reason: format!("transport connection not ready: {:?}", other),
                });
            }
        }
        #[cfg(unix)]
        {
            let is_udp = matches!(transport_for_send, TransportHandle::Udp(_));
            if let Some(workers) = self.encrypt_workers.as_ref().cloned()
                && is_udp
            {
                let transport = transport_for_send;
                // Snapshot the per-peer connected UDP socket before
                // resolving the fallback address. On the established
                // steady-state path this socket already carries the
                // kernel peer address, so re-parsing the configured
                // transport address and touching the DNS cache on every
                // packet is pure overhead on the sender hot path.
                let send_target = {
                    if let TransportHandle::Udp(udp) = transport {
                        let socket_addr = {
                            #[cfg(any(target_os = "linux", target_os = "macos"))]
                            {
                                match prepared.connected_socket.as_ref() {
                                    Some(socket) => Some(socket.peer_addr()),
                                    None => {
                                        udp.resolve_for_off_task(&prepared.remote_addr).await.ok()
                                    }
                                }
                            }
                            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                            {
                                udp.resolve_for_off_task(&prepared.remote_addr).await.ok()
                            }
                        };
                        match (udp.async_socket(), socket_addr) {
                            (Some(socket), Some(socket_addr)) => Some((socket, socket_addr)),
                            _ => None,
                        }
                    } else {
                        None
                    }
                };
                if let Some((socket, socket_addr)) = send_target {
                    // Worker sends reserve their FMP counter only after
                    // the worker target is known. If the off-task path is
                    // unavailable, the inline path below remains the sole
                    // counter owner for this packet.
                    if let Some(worker_send) = self
                        .peers
                        .prepare_fmp_worker_send(node_addr, &prepared, plaintext)
                        .map_err(|e| Self::map_fmp_send_preparation_error(*node_addr, e))?
                    {
                        let reserved_counter = worker_send.counter;
                        let predicted_bytes = worker_send.predicted_bytes;
                        // Lifecycle send bookkeeping uses the predicted
                        // wire size, exact for ChaCha20-Poly1305 because the
                        // tag is constant 16 bytes. When `connected_socket`
                        // is `Some`, the worker sends on it without a
                        // destination sockaddr, so the kernel skips the
                        // per-packet sockaddr + route + neighbor resolve.
                        let _ = self.peers.record_fmp_send_bookkeeping(
                            node_addr,
                            reserved_counter,
                            prepared.timestamp_ms,
                            predicted_bytes,
                        );
                        let scheduling_weight = self.send_weight_for_peer(node_addr);
                        let traffic_class = classify_fmp_plaintext_traffic(plaintext);
                        workers.dispatch(self::encrypt_worker::FmpSendJob {
                            cipher: worker_send.cipher,
                            counter: reserved_counter,
                            wire_buf: worker_send.wire_buf,
                            fsp_seal: None,
                            send_target: self::encrypt_worker::SelectedSendTarget::new(
                                socket,
                                #[cfg(any(target_os = "linux", target_os = "macos"))]
                                prepared.connected_socket.clone(),
                                socket_addr,
                            ),
                            bulk_endpoint_data: traffic_class.bulk_endpoint_data,
                            drop_on_backpressure: traffic_class.drop_on_backpressure,
                            scheduling_weight,
                            queued_at: crate::perf_profile::stamp(),
                        });
                        return Ok(());
                    }
                }
            }
        }

        // Inline (legacy) path: encrypt + send on the rx_loop.
        // Build the inner plaintext lazily here — the worker path
        // above never reaches this point, so the prepend_inner_header
        // alloc is avoided in the fast path.
        let inner_plaintext = prepend_inner_header(prepared.timestamp_ms, plaintext);
        let inline = self
            .peers
            .seal_prepared_fmp_inline_send(node_addr, &prepared, &inner_plaintext)
            .map_err(|e| Self::map_fmp_send_preparation_error(*node_addr, e))?;

        // Re-borrow peer for stats update after sending
        let send_result = {
            let _t = crate::perf_profile::Timer::start(crate::perf_profile::Stage::UdpSend);
            let transport = self
                .transports
                .get(&prepared.transport_id)
                .ok_or(NodeError::TransportNotFound(prepared.transport_id))?;
            transport
                .send(&prepared.remote_addr, &inline.wire_packet)
                .await
        };
        self.note_local_send_outcome(node_addr, &send_result);
        let bytes_sent = send_result.map_err(|e| match e {
            TransportError::MtuExceeded { packet_size, mtu } => NodeError::MtuExceeded {
                node_addr: *node_addr,
                packet_size,
                mtu,
            },
            other => NodeError::SendFailed {
                node_addr: *node_addr,
                reason: format!("transport send: {}", other),
            },
        })?;

        // Update send statistics
        let _ = self.peers.record_fmp_send_bookkeeping(
            node_addr,
            inline.counter,
            prepared.timestamp_ms,
            bytes_sent,
        );

        Ok(())
    }
}
