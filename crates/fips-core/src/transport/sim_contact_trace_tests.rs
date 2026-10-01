use super::*;

#[tokio::test(start_paused = true)]
async fn contact_trace_brackets_scheduled_and_delivered_packet() {
    let network = SimNetwork::new(9);
    let identities = std::array::from_fn(|_| *crate::Identity::generate().node_addr());
    let trace = crate::test_trace::Trace::new(
        Instant::now(),
        identities,
        std::array::from_fn(|i| i.to_string()),
        [b"one", b"two"],
        8,
    );
    network.set_contact_trace(Some(trace.clone()));
    trace.set_active(true);
    let (tx, mut rx) = crate::transport::packet_channel(8);
    network
        .register_endpoint("1".into(), TransportId::new(1), tx, None)
        .unwrap();
    let bytes = vec![1, 2, 3, 4];
    network
        .send("0", &TransportAddr::from_string("1"), bytes.clone())
        .await
        .unwrap();
    let packet = rx.recv().await.unwrap();
    let observed = trace.stamp();
    assert_eq!(packet.data.as_slice(), bytes);
    let result = trace.finish();
    let records = result["records"].as_array().unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["kind"], "wire_scheduled");
    assert_eq!(records[1]["kind"], "wire_send_ok");
    let scheduled = records[0]["stamp"]["us"].as_u64().unwrap();
    let delay = records[0]["values"][3].as_u64().unwrap();
    let before = records[1]["values"][4].as_u64().unwrap();
    let after = records[1]["values"][5].as_u64().unwrap();
    assert!(delay >= DEFAULT_SIM_LINK.latency_ms * 1_000);
    assert!(scheduled + delay <= before && before <= after && after <= observed.us);
    assert_eq!(records[1]["values"][3], scheduled);
    assert_eq!(result["overflowed"], false);

    // PacketTx deliberately returns Ok for pressure drops. A send-call record
    // must never be presented as actual channel admission or wire delivery.
    let pressure_trace = crate::test_trace::Trace::new(
        Instant::now(),
        identities,
        std::array::from_fn(|i| i.to_string()),
        [b"one", b"two"],
        8,
    );
    network.unregister_endpoint("1");
    let (tx, mut rx) = crate::transport::packet_channel(1);
    network
        .register_endpoint("1".into(), TransportId::new(1), tx, None)
        .unwrap();
    network.set_contact_trace(Some(pressure_trace.clone()));
    pressure_trace.set_active(true);
    for _ in 0..2 {
        network
            .send("0", &TransportAddr::from_string("1"), vec![0xff; 20])
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_millis(5)).await;
    assert!(rx.try_recv().is_ok());
    assert!(
        rx.try_recv().is_err(),
        "bulk capacity dropped the second packet"
    );
    let result = pressure_trace.finish();
    let records = result["records"].as_array().unwrap();
    assert_eq!(
        records
            .iter()
            .filter(|r| r["kind"] == "wire_send_ok")
            .count(),
        2
    );
    assert!(records.iter().all(|r| r["kind"] != "wire_delivered"));
    assert_eq!(result["overflowed"], false);
}
