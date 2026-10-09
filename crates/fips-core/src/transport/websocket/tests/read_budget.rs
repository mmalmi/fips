use super::*;
use std::io::{self, Cursor, Read, Write};
use tokio_tungstenite::tungstenite::{
    Error, WebSocket,
    protocol::{
        Role,
        frame::{
            Frame,
            coding::{Data, OpCode},
        },
    },
};

const READ_BUDGET: usize = 16 * 1024;

struct PartialReader {
    wire: Cursor<Vec<u8>>,
    chunk: usize,
    would_block: bool,
    reads: usize,
}

impl Read for PartialReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        // FrameCodec zero-fills this slice before calling Read, even when the
        // socket is not ready. Bound that work after retained capacity grows.
        assert!(buf.len() <= READ_BUDGET, "read cleared {} bytes", buf.len());
        self.would_block = !self.would_block;
        if self.would_block || self.wire.position() == self.wire.get_ref().len() as u64 {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let count = buf.len().min(self.chunk);
        self.wire.read(&mut buf[..count])
    }
}

impl Write for PartialReader {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn reader(messages: Vec<Message>, limit: usize, chunk: usize) -> WebSocket<PartialReader> {
    let mut sender = WebSocket::from_raw_socket(Cursor::new(Vec::new()), Role::Client, None);
    for message in messages {
        sender.send(message).unwrap();
    }
    let mut transport = test_transport(1);
    transport.runtime.config.max_frame_bytes = Some(limit);
    WebSocket::from_raw_socket(
        PartialReader {
            wire: Cursor::new(sender.get_ref().get_ref().clone()),
            chunk,
            would_block: false,
            reads: 0,
        },
        Role::Server,
        Some(transport.runtime.websocket_config()),
    )
}

fn next_message(socket: &mut WebSocket<PartialReader>) -> Result<Message, Error> {
    for _ in 0..4096 {
        match socket.read() {
            Err(Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {}
            result => return result,
        }
    }
    panic!("WebSocket did not finish a bounded partial read");
}

fn fragment(payload: Vec<u8>, first: bool, last: bool) -> Message {
    Message::Frame(Frame::message(
        payload,
        OpCode::Data(if first { Data::Binary } else { Data::Continue }),
        last,
    ))
}

#[test]
fn websocket_read_work_stays_bounded_after_large_frames() {
    for limit in [WebSocketConfig::default().max_frame_bytes(), 1024 * 1024] {
        let large = vec![0x56; limit];
        let small = vec![0xa7; 256];
        let mut messages = vec![Message::Binary(large.clone().into())];
        messages.extend((0..32).map(|_| Message::Binary(small.clone().into())));
        let mut socket = reader(messages, limit, 1024);
        assert_eq!(
            next_message(&mut socket).unwrap(),
            Message::Binary(large.into())
        );
        for _ in 0..32 {
            assert_eq!(
                next_message(&mut socket).unwrap(),
                Message::Binary(small.clone().into())
            );
        }
        // Idle repolls must retain the same bound after the large frame.
        for _ in 0..16 {
            assert!(
                matches!(socket.read(), Err(Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock)
            );
        }
        assert!(socket.get_ref().reads > 32);
    }
}

#[test]
fn websocket_read_budget_preserves_fragments_and_size_limits() {
    let payload = vec![0x37; 4096];
    let mut socket = reader(
        vec![
            fragment(payload[..1700].to_vec(), true, false),
            fragment(payload[1700..].to_vec(), false, true),
        ],
        4096,
        17,
    );
    assert_eq!(
        next_message(&mut socket).unwrap(),
        Message::Binary(payload.into())
    );

    let mut oversized_frame = reader(vec![Message::Binary(vec![0; 4097].into())], 4096, 17);
    assert!(matches!(
        next_message(&mut oversized_frame),
        Err(Error::Capacity(_))
    ));
    let mut oversized_message = reader(
        vec![
            fragment(vec![0; 3000], true, false),
            fragment(vec![0; 3000], false, true),
        ],
        4096,
        17,
    );
    assert!(matches!(
        next_message(&mut oversized_message),
        Err(Error::Capacity(_))
    ));
}

// A TCP/TLS read can contain many already-framed messages. Those messages do
// not necessarily poll the underlying socket again, so socket cooperation is
// not a bound on a framing task's receive turn.
struct ReadyWire(Cursor<Vec<u8>>);

impl tokio::io::AsyncRead for ReadyWire {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.0.position() == self.0.get_ref().len() as u64 {
            return std::task::Poll::Pending;
        }
        let count = self.0.read(buffer.initialize_unfilled()).unwrap();
        buffer.advance(count);
        std::task::Poll::Ready(Ok(()))
    }
}

impl tokio::io::AsyncWrite for ReadyWire {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::task::Poll::Ready(Ok(bytes.len()))
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn buffered_websocket_burst_gives_priority_receiver_a_turn() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    const MESSAGES: usize = 256;
    let record = build_msg1(
        SessionIndex::new(1),
        &[0; crate::noise::HANDSHAKE_MSG1_SIZE],
    );
    let mut encoder = WebSocket::from_raw_socket(Cursor::new(Vec::new()), Role::Client, None);
    for _ in 0..MESSAGES {
        encoder
            .send(Message::Binary(record.clone().into()))
            .unwrap();
    }
    let identity = Identity::generate();
    let (packet_tx, mut packet_rx) = packet_channel(8);
    let transport = WebSocketTransport::new(
        TransportId::new(7),
        None,
        WebSocketConfig {
            ping_interval_secs: Some(0),
            idle_timeout_secs: Some(0),
            ..Default::default()
        },
        packet_tx,
        &identity,
    );
    let socket = WebSocketStream::from_raw_socket(
        ReadyWire(Cursor::new(encoder.get_ref().get_ref().clone())),
        Role::Server,
        Some(transport.runtime.websocket_config()),
    )
    .await;
    let addr = TransportAddr::from_string("ws://buffered.invalid/fips");
    let mut connection = Box::pin(run_framing_connection(
        transport.runtime.clone(),
        addr.clone(),
        socket,
        transport.runtime.next_generation(),
        Direction::Inbound,
        false,
        0,
    ));
    let mut received = 0;
    for _ in 0..MESSAGES * 2 {
        let before = transport.stats().frames_received;
        poll_fn(|cx| {
            assert!(connection.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        let advanced = transport.stats().frames_received - before;
        assert!(
            advanced < 64,
            "ready WebSocket burst must yield before exhausting priority reserve"
        );
        while let Ok(packet) = packet_rx.try_recv() {
            assert_eq!(packet.data.as_slice(), record);
            received += 1;
        }
        if received == MESSAGES {
            break;
        }
        // Manual polls returning Ready above never yield this parent task.
        // Let the runtime replenish cooperative budgets (including stream
        // admission), while still checking each framing poll's exact bound.
        tokio::task::yield_now().await;
    }
    assert_eq!(received, MESSAGES, "framing fairness must not lose records");
    assert_eq!(transport.stats().frames_received, MESSAGES as u64);
    transport.close_connection_async(&addr).await;
    tokio::time::timeout(Duration::from_secs(1), connection)
        .await
        .expect("closed framing task must finish")
        .unwrap();
    assert!(transport.runtime.connections().is_empty());
}

#[tokio::test]
async fn concurrent_websocket_readers_preserve_control_at_shared_capacity() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    // Each reader has less than one cooperative turn, but their aggregate
    // exceeds the same 64-packet reserve. Yielding per reader is insufficient.
    const READERS: usize = 8;
    const PER_READER: usize = 16;
    let record = build_msg1(
        SessionIndex::new(1),
        &[0; crate::noise::HANDSHAKE_MSG1_SIZE],
    );
    let mut encoder = WebSocket::from_raw_socket(Cursor::new(Vec::new()), Role::Client, None);
    for _ in 0..PER_READER {
        encoder
            .send(Message::Binary(record.clone().into()))
            .unwrap();
    }
    let identity = Identity::generate();
    let (packet_tx, mut packet_rx) = packet_channel(8);
    let transport = WebSocketTransport::new(
        TransportId::new(7),
        None,
        WebSocketConfig {
            ping_interval_secs: Some(0),
            idle_timeout_secs: Some(0),
            ..Default::default()
        },
        packet_tx,
        &identity,
    );
    let mut connections = Vec::new();
    for reader in 0..READERS {
        let socket = WebSocketStream::from_raw_socket(
            ReadyWire(Cursor::new(encoder.get_ref().get_ref().clone())),
            Role::Server,
            Some(transport.runtime.websocket_config()),
        )
        .await;
        let addr = TransportAddr::from_string(&format!("ws://buffered-{reader}.invalid/fips"));
        let connection = Box::pin(run_framing_connection(
            transport.runtime.clone(),
            addr.clone(),
            socket,
            transport.runtime.next_generation(),
            Direction::Inbound,
            false,
            0,
        ));
        connections.push((addr, connection));
    }
    let mut received = 0;
    let mut maximum_queued = 0;
    for _ in 0..READERS * PER_READER {
        poll_fn(|cx| {
            for (_, connection) in &mut connections {
                assert!(connection.as_mut().poll(cx).is_pending());
            }
            Poll::Ready(())
        })
        .await;
        let mut queued = 0;
        while let Ok(packet) = packet_rx.try_recv() {
            assert_eq!(packet.data.as_slice(), record);
            received += 1;
            queued += 1;
        }
        maximum_queued = maximum_queued.max(queued);
        if transport.stats().frames_received == (READERS * PER_READER) as u64 {
            break;
        }
    }
    for (addr, connection) in connections {
        transport.close_connection_async(&addr).await;
        tokio::time::timeout(Duration::from_secs(1), connection)
            .await
            .unwrap()
            .unwrap();
    }
    assert!(transport.runtime.connections().is_empty());
    assert!(
        maximum_queued <= 64,
        "shared priority reserve must remain bounded"
    );
    assert_eq!(
        received,
        READERS * PER_READER,
        "shared capacity must backpressure ready control frames instead of losing them"
    );
}

#[tokio::test(start_paused = true)]
async fn blocked_control_admission_obeys_idle_timeout_and_local_close() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;

    for idle_secs in [0, 1] {
        let record = build_msg1(
            SessionIndex::new(1),
            &[0; crate::noise::HANDSHAKE_MSG1_SIZE],
        );
        let mut encoder = WebSocket::from_raw_socket(Cursor::new(Vec::new()), Role::Client, None);
        encoder.send(Message::Binary(record.into())).unwrap();
        let (packet_tx, mut packet_rx) = packet_channel(8);
        let transport = WebSocketTransport::new(
            TransportId::new(7),
            None,
            WebSocketConfig {
                ping_interval_secs: Some(0),
                idle_timeout_secs: Some(idle_secs),
                ..Default::default()
            },
            packet_tx,
            &Identity::generate(),
        );
        for _ in 0..64 {
            transport
                .runtime
                .packet_tx
                .send(ReceivedPacket::with_timestamp(
                    TransportId::new(7),
                    TransportAddr::from_string("buffered"),
                    PacketBuffer::new(build_msg1(
                        SessionIndex::new(1),
                        &[0; crate::noise::HANDSHAKE_MSG1_SIZE],
                    )),
                    0,
                ))
                .unwrap();
        }
        let socket = WebSocketStream::from_raw_socket(
            ReadyWire(Cursor::new(encoder.get_ref().get_ref().clone())),
            Role::Server,
            Some(transport.runtime.websocket_config()),
        )
        .await;
        let addr = TransportAddr::from_string("ws://blocked.invalid/fips");
        let mut connection = Box::pin(run_framing_connection(
            transport.runtime.clone(),
            addr.clone(),
            socket,
            transport.runtime.next_generation(),
            Direction::Inbound,
            false,
            0,
        ));
        poll_fn(|cx| {
            assert!(connection.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert_eq!(transport.stats().frames_received, 0);
        if idle_secs == 0 {
            transport.close_connection_async(&addr).await;
        } else {
            tokio::time::advance(Duration::from_secs(1)).await;
        }
        let result = tokio::time::timeout(Duration::from_millis(10), connection)
            .await
            .expect("a capacity wait must not suspend connection lifetime");
        if idle_secs == 0 {
            result.unwrap();
        } else {
            assert!(matches!(result, Err(TransportError::Timeout)));
        }
        assert!(transport.runtime.connections().is_empty());
        assert_eq!(packet_rx.drain_ready(128, |_| true), 64);
    }
}
