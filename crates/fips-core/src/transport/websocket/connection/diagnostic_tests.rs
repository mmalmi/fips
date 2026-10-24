use super::*;
use crate::msg1_ingress_diagnostic::tests::{capture, install_isolated_test_window, msg1};
use crate::transport::packet_channel;

#[tokio::test]
#[ignore = "run alone: exercises the fixed process-wide diagnostic window"]
async fn ingress_hooks_distinguish_waiting_admitted_and_cancelled_stream_reads() {
    install_isolated_test_window();
    let (events, _guard) = capture(true);
    let (packet_tx, mut packet_rx) = packet_channel(1);
    let transport = WebSocketTransport::new(
        TransportId::new(1),
        None,
        WebSocketConfig::default(),
        packet_tx.clone(),
        &Identity::generate(),
    );
    let addr = TransportAddr::from_string("private-carrier-must-not-be-logged");
    let filler = ReceivedPacket::with_timestamp(
        TransportId::new(1),
        addr.clone(),
        PacketBuffer::new(msg1(1)),
        now_ms(),
    );

    for (index, cancel) in [(1517719947, false), (42, true)] {
        // Find the existing priority capacity without copying its private limit.
        loop {
            let before = packet_tx.reserved_packets_for_test();
            packet_tx.send(filler.clone()).unwrap();
            let after = packet_tx.reserved_packets_for_test();
            assert!(after < 256, "unexpected priority test capacity");
            if before == after {
                break;
            }
        }
        let stream = futures::stream::iter([Ok(Message::Binary(msg1(index).into()))])
            .chain(futures::stream::pending());
        let (replies, _reply_rx) = mpsc::channel(8);
        let deadlines = Deadlines::new(&transport.runtime.config, false);
        let mut reader = Box::pin(read(
            &transport.runtime,
            &addr,
            stream,
            replies,
            None,
            1,
            &deadlines,
        ));
        assert!(futures::poll!(reader.as_mut()).is_pending());
        let records = || {
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|record| record.get("sender_index") == Some(&index.to_string()))
                .cloned()
                .collect::<Vec<_>>()
        };
        assert_eq!(records().len(), 1);
        assert_eq!(records()[0]["stage"], "read");
        if !cancel {
            tokio::time::sleep(Duration::from_millis(2)).await;
            packet_rx.try_recv().unwrap();
            assert!(futures::poll!(reader.as_mut()).is_pending());
            let admitted = records();
            assert_eq!(admitted.len(), 2);
            assert_eq!(admitted[1]["stage"], "admitted");
            assert!(admitted[1]["queue_wait_us"].parse::<u64>().unwrap() >= 1_000);
        }
        drop(reader);
        let mut delivered = 0;
        while let Ok(packet) = packet_rx.try_recv() {
            if packet.data.as_slice() == msg1(index) {
                delivered += 1;
            }
        }
        assert_eq!(delivered, usize::from(!cancel));
        assert_eq!(records().len(), if cancel { 1 } else { 2 });
    }
    assert!(
        !serde_json::to_string(&*events.lock().unwrap())
            .unwrap()
            .contains("private-carrier")
    );
}
