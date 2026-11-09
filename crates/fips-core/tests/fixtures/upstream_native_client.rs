//! Test-only driver compiled against the unchanged upstream `fips` library.
//! It exercises upstream-initiated sessions through the public native API.
use fips::native::client::FipsStream;
use std::{env, path::Path, thread, time::Duration};

fn main() {
    let args: Vec<String> = env::args().collect();
    assert_eq!(
        args.len(),
        3,
        "usage: upstream-native-client SOCKET PEER_NPUB"
    );
    let stream =
        FipsStream::connect_at(Path::new(&args[1]), 4602, (args[2].as_str(), 4601)).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(12)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(12)))
        .unwrap();
    let mut received = vec![0; stream.max_payload()];
    for sequence in 0u16..64 {
        let payload = format!("upstream-compatible service datagram {sequence}").into_bytes();
        stream.send(&payload).unwrap();
        let size = stream.recv(&mut received).unwrap();
        assert_eq!(&received[..size], payload);
        thread::sleep(Duration::from_millis(100));
    }
    println!("64 ordered service round trips completed");
}
