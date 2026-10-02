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
