use super::*;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

fn recorder() -> Arc<Recorder> {
    let now = Instant::now();
    Arc::new(Recorder {
        plan: Plan {
            token: TOKEN.into(),
            epoch_ms: 0,
            start: now,
            end: now + Duration::from_secs(30),
        },
        state: Mutex::new(State::default()),
        closed: AtomicBool::new(false),
    })
}

fn carrier(recorder: &Arc<Recorder>, generation: u64) -> Handle {
    let addr = TransportAddr::from_string(&format!("private-must-not-escape/{generation}"));
    recorder.register(TransportId::new(1), &addr, generation);
    recorder.lookup(TransportId::new(1), &addr).unwrap()
}

#[test]
fn only_one_exact_marker_selects_a_request() {
    let recorder = recorder();
    for query in [
        None,
        Some(""),
        Some("fips_trace=wrong"),
        Some("unrelated=value"),
    ] {
        assert!(!recorder.plan.matches(query));
    }
    assert!(recorder.plan.matches(Some(&format!("fips_trace={TOKEN}"))));
    assert!(
        recorder
            .plan
            .matches(Some(&format!("other=1&fips_trace={TOKEN}")))
    );
    for query in [
        format!("fips_trace={TOKEN}&fips_trace={TOKEN}"),
        format!("fips_trace={TOKEN}&fips_trace"),
        format!("fips_trace={TOKEN}extra"),
        format!("fips_trace={}", TOKEN.to_uppercase()),
        format!("fips%5ftrace={TOKEN}"),
    ] {
        assert!(!recorder.plan.matches(Some(&query)));
    }
}

#[test]
fn arming_has_fixed_future_bounds_and_does_not_echo_invalid_values() {
    let now = Instant::now();
    let plan = Plan::parse(TOKEN.into(), "6000", 1000, now).unwrap();
    assert_eq!(plan.start.duration_since(now), Duration::from_secs(5));
    assert_eq!(plan.end.duration_since(plan.start), Duration::from_secs(30));
    assert!(Plan::parse(TOKEN.into(), "121000", 1000, now).is_ok());
    for epoch in ["private-value", "999", "5999", "121001"] {
        assert!(Plan::parse(TOKEN.into(), epoch, 1000, now).is_err());
    }
    assert!(Plan::parse("private-invalid-token".into(), "6000", 1000, now).is_err());
}

#[test]
fn marked_generations_are_distinct_retained_after_close_and_never_evicted() {
    let recorder = recorder();
    let first = carrier(&recorder, 1);
    first.terminal("peer_eof");
    first.terminal("task_aborted");
    for generation in 2..=CARRIERS as u64 {
        carrier(&recorder, generation);
    }
    let ninth = TransportAddr::from_string("private-must-not-escape/9");
    recorder.register(TransportId::new(1), &ninth, 9);
    assert!(recorder.lookup(TransportId::new(1), &ninth).is_none());
    let first_addr = TransportAddr::from_string("private-must-not-escape/1");
    assert!(recorder.lookup(TransportId::new(1), &first_addr).is_some());
    assert!(recorder.lookup(TransportId::new(2), &first_addr).is_none());
    let state = recorder.lock();
    assert_eq!(state.carriers.len(), CARRIERS);
    assert_eq!(state.carrier_overflow, 1);
    assert_eq!(state.carriers[0].terminal, Some("peer_eof"));
}

#[test]
fn cancellation_retires_unadmitted_tracking_but_close_preserves_admitted_tracking() {
    let recorder = recorder();
    let handle = carrier(&recorder, 1);
    handle.update(|c, _| {
        c.admissions_active = 2;
        c.pending_msg1.extend([(42, 1), (42, 2)]);
    });
    drop(Span {
        handle: handle.clone(),
        operation: Operation::Admission,
        index: 42,
        seq: Some(1),
        done: false,
    });
    Span {
        handle: handle.clone(),
        operation: Operation::Admission,
        index: 42,
        seq: Some(2),
        done: false,
    }
    .finish("admitted");
    handle.terminal("local_close");
    {
        let state = recorder.lock();
        assert_eq!(state.carriers[0].admissions_active, 0);
        assert_eq!(state.carriers[0].pending_msg1, [(42, 2)]);
        assert_eq!(
            state.carriers[0]
                .at_close
                .as_ref()
                .unwrap()
                .msg1_not_handled,
            1
        );
    }
    // The handler's later result remains observable on the retained generation.
    handle.update(|c, _| {
        c.pending_msg1.clear();
        c.handlers_active = 1;
    });
    Span {
        handle,
        operation: Operation::Handler,
        index: 42,
        seq: Some(2),
        done: false,
    }
    .decision("Stranger", "rate_limit", "close_requested");
    let mut state = recorder.lock();
    let c = &mut state.carriers[0];
    c.cutoff();
    assert!(!c.incomplete);
    assert_eq!(c.events.last().unwrap().stage, "handler_end");
    assert_eq!(c.events.last().unwrap().detail, Some("rate_limit"));
    assert_eq!(c.events[1].detail, Some("cancelled"));
}

#[test]
fn event_overflow_keeps_terminal_cause_and_incomplete_status() {
    let recorder = recorder();
    let handle = carrier(&recorder, 1);
    handle.update(|c, r| {
        for _ in 0..EVENTS {
            c.record(r.event("write_start", Some(42), None, None));
        }
    });
    handle.terminal("idle_timeout");
    let mut state = recorder.lock();
    let c = &mut state.carriers[0];
    c.cutoff();
    assert_eq!(c.events.len(), EVENTS);
    assert_eq!(c.event_overflow, 2);
    assert_eq!(c.terminal, Some("idle_timeout"));
    assert!(c.incomplete);
}

#[test]
fn cutoff_exposes_unfinished_work_and_late_calls_do_not_mutate_the_snapshot() {
    let recorder = recorder();
    let handle = carrier(&recorder, 1);
    handle.update(|c, _| {
        c.writes_active = 1;
        c.msg2_queued = 1;
        c.msg2_started = 1;
    });
    handle.terminal("local_close");
    recorder.closed.store(true, Ordering::Relaxed);
    let span = Span {
        handle,
        operation: Operation::Write,
        index: 42,
        seq: None,
        done: false,
    };
    drop(span);
    let mut state = recorder.lock();
    let c = &mut state.carriers[0];
    c.cutoff();
    assert_eq!(c.writes_active, 1);
    assert_eq!(c.at_close.as_ref().unwrap().writes, 1);
    assert!(c.incomplete);
}

#[test]
fn serializer_has_hard_byte_cap_and_never_exports_marker_or_addresses() {
    let recorder = recorder();
    let handle = carrier(&recorder, 1);
    handle.terminal("peer_close");
    let state = recorder.lock();
    let json = bounded_json(&state.carriers[0], CARRIER_BYTES).unwrap();
    assert!(!json.contains("private-must-not-escape"));
    assert!(!json.contains(TOKEN));
    assert!(bounded_json(&state.carriers[0], 10).is_err());
    assert!(CARRIERS * CARRIER_BYTES + TERMINAL_BYTES + 1024 <= 65536);
}

// One isolated process exercises the real HTTP selector, stream queue and
// writer without changing any production limit or involving public hosts.
#[tokio::test]
#[ignore = "run alone: installs the process-wide marked-carrier recorder"]
async fn marked_upgrade_covers_reconnect_queue_cancellation_and_delayed_handler() {
    use crate::config::WebSocketConfig;
    use crate::node::wire::{build_msg1, build_msg2};
    use crate::transport::websocket::WebSocketTransport;
    use crate::transport::{PacketBuffer, ReceivedPacket, packet_channel};
    use crate::utils::index::SessionIndex;
    use futures::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let recorder = recorder();
    assert!(SESSION.set(Some(Arc::clone(&recorder))).is_ok());
    let transport_id = TransportId::new(1);
    let (tx, mut rx) = packet_channel(8);
    let mut server = WebSocketTransport::new(
        transport_id,
        None,
        WebSocketConfig {
            bind_addr: Some("127.0.0.1:0".into()),
            ping_interval_secs: Some(0),
            ..Default::default()
        },
        tx.clone(),
        &crate::Identity::generate(),
    );
    server.start_async().await.unwrap();
    let url = format!("ws://{}/fips", server.local_addr().unwrap());
    let marked = format!("{url}?fips_trace={TOKEN}");
    let msg1 = build_msg1(
        SessionIndex::new(42),
        &[0; crate::noise::HANDSHAKE_MSG1_SIZE],
    );
    let msg2 = build_msg2(
        SessionIndex::new(43),
        SessionIndex::new(42),
        &[0; crate::noise::HANDSHAKE_MSG2_SIZE],
    );

    tokio::time::timeout(Duration::from_secs(5), async {
        // Unmarked HTTP upgrades and physical records still work and do not
        // consume any selected generation, even through the same listener.
        let (mut ordinary, _) = tokio_tungstenite::connect_async(url.as_str())
            .await
            .unwrap();
        ordinary
            .send(Message::Binary(msg1.clone().into()))
            .await
            .unwrap();
        let unmarked_packet = rx.recv().await.unwrap();
        assert_eq!(unmarked_packet.data.as_slice(), msg1);
        server
            .send_async(&unmarked_packet.remote_addr, &msg2)
            .await
            .unwrap();
        assert_eq!(
            ordinary.next().await.unwrap().unwrap().into_data().as_ref(),
            msg2
        );
        assert!(recorder.lock().carriers.is_empty());
        server
            .close_connection_async(&unmarked_packet.remote_addr)
            .await;
        drop(ordinary);

        // The first selected socket closes after admission. Its delayed Node
        // handler and failed Msg2 send must still join the same generation.
        let (mut first, _) = tokio_tungstenite::connect_async(marked.as_str())
            .await
            .unwrap();
        first
            .send(Message::Binary(msg1.clone().into()))
            .await
            .unwrap();
        let queued = rx.recv().await.unwrap();
        server.close_connection_async(&queued.remote_addr).await;
        loop {
            if recorder.lock().carriers[0].terminal.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let handler =
            handler_entry(transport_id, &queued.remote_addr, queued.data.as_slice()).unwrap();
        assert!(server.send_async(&queued.remote_addr, &msg2).await.is_err());
        handler.decision("Stranger", "rate_limit", "close_requested");
        drop(first);

        // Fill the actual priority queue. The second marked generation must
        // expose a pending read and its cancellation, without leaking credit.
        let filler = ReceivedPacket::with_timestamp(
            transport_id,
            unmarked_packet.remote_addr,
            PacketBuffer::new(msg1.clone()),
            0,
        );
        for _ in 0..256 {
            tx.send(filler.clone()).unwrap();
        }
        let (mut second, _) = tokio_tungstenite::connect_async(marked.as_str())
            .await
            .unwrap();
        second
            .send(Message::Binary(msg1.clone().into()))
            .await
            .unwrap();
        let waiting_addr = loop {
            let found = {
                let state = recorder.lock();
                state
                    .carriers
                    .get(1)
                    .filter(|c| c.admissions_active == 1)
                    .map(|c| c.addr.clone())
            };
            if let Some(addr) = found {
                break addr;
            }
            tokio::task::yield_now().await;
        };
        server.close_connection_async(&waiting_addr).await;
        loop {
            let complete = {
                let state = recorder.lock();
                state.carriers[1].terminal.is_some() && state.carriers[1].admissions_active == 0
            };
            if complete {
                break;
            }
            tokio::task::yield_now().await;
        }
        drop(second);
        while rx.try_recv().is_ok() {}

        // A further marked generation preserves bytes and records actual
        // socket completion, independently of the first two terminal causes.
        let (mut third, _) = tokio_tungstenite::connect_async(marked.as_str())
            .await
            .unwrap();
        third
            .send(Message::Binary(msg1.clone().into()))
            .await
            .unwrap();
        let packet = rx.recv().await.unwrap();
        let handler =
            handler_entry(transport_id, &packet.remote_addr, packet.data.as_slice()).unwrap();
        server.send_async(&packet.remote_addr, &msg2).await.unwrap();
        assert_eq!(
            third.next().await.unwrap().unwrap().into_data().as_ref(),
            msg2
        );
        handler.decision("Stranger", "accepted", "retained");
        server.close_connection_async(&packet.remote_addr).await;
        loop {
            if recorder.lock().carriers[2].terminal.is_some() {
                break;
            }
            tokio::task::yield_now().await;
        }
        drop(third);
    })
    .await
    .expect("marked local trace scenario did not complete");
    server.stop_async().await.unwrap();
    let mut state = recorder.lock();
    assert_eq!(state.carriers.len(), 3);
    assert_eq!(state.carrier_overflow, 0);
    for c in &mut state.carriers {
        c.cutoff();
        assert!(!c.incomplete);
    }
    assert!(
        state.carriers[0]
            .events
            .iter()
            .any(|e| e.stage == "msg2_queue" && e.detail == Some("not_started"))
    );
    assert!(
        state.carriers[1]
            .events
            .iter()
            .any(|e| e.stage == "admission_end" && e.detail == Some("cancelled"))
    );
    assert!(
        state.carriers[2]
            .events
            .iter()
            .any(|e| e.stage == "write_end" && e.detail == Some("sent"))
    );
    assert_ne!(state.carriers[0].generation, state.carriers[1].generation);
    assert_ne!(state.carriers[1].generation, state.carriers[2].generation);
}
