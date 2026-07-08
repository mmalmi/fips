use super::*;

pub(super) fn deterministic_identity(seed: u64, index: usize) -> (Identity, String) {
    let mut rng =
        StdRng::seed_from_u64(seed ^ (index as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15));
    loop {
        let mut secret = [0u8; 32];
        rng.fill_bytes(&mut secret);
        if let Ok(identity) = Identity::from_secret_bytes(&secret) {
            return (identity, hex::encode(secret));
        }
    }
}

pub(super) async fn recv_exact(
    endpoint: &FipsEndpoint,
    expected: &[u8],
    timeout: Duration,
) -> bool {
    let deadline = Instant::now() + timeout;
    let mut messages = Vec::new();
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return false;
        };
        let Some(received) = recv_endpoint_batch_into(endpoint, &mut messages, remaining).await
        else {
            return false;
        };
        for message in messages.iter().take(received) {
            if message.data.as_slice() == expected {
                return true;
            }
        }
    }
}

pub(super) async fn recv_payload_set(
    endpoint: &FipsEndpoint,
    expected: &mut HashSet<Vec<u8>>,
    timeout: Duration,
) -> (usize, usize) {
    let deadline = Instant::now() + timeout;
    let mut delivered = 0usize;
    let mut delivered_bytes = 0usize;
    let mut messages = Vec::new();
    while !expected.is_empty() {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        let Some(received) = recv_endpoint_batch_into(endpoint, &mut messages, remaining).await
        else {
            break;
        };
        for message in messages.iter().take(received) {
            let data = message.data.as_slice();
            let len = data.len();
            if expected.remove(data) {
                delivered += 1;
                delivered_bytes += len;
            }
        }
    }
    (delivered, delivered_bytes)
}

pub(super) fn make_stream_payloads(
    label: &str,
    stream: usize,
    src: usize,
    dst: usize,
    stream_size: usize,
    chunk_size: usize,
) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();
    let mut remaining = stream_size;
    let mut chunk = 0usize;
    while remaining > 0 {
        let size = remaining.min(chunk_size);
        let header = format!("fips-sim|stream|{label}|{stream}|{src}|{dst}|{chunk}|");
        payloads.push(fixed_payload(header.as_bytes(), size));
        remaining -= size;
        chunk += 1;
    }
    payloads
}

pub(super) fn fixed_payload(prefix: &[u8], size: usize) -> Vec<u8> {
    let mut payload = Vec::with_capacity(size);
    payload.extend_from_slice(prefix);
    payload.truncate(size);
    while payload.len() < size {
        payload.push((payload.len() % 251) as u8);
    }
    payload
}

pub(super) fn probe_stats(
    attempted: usize,
    failed_send: usize,
    timed_out: usize,
    latencies: Vec<f64>,
) -> ProbeStats {
    let delivered = latencies.len();
    ProbeStats {
        attempted,
        delivered,
        failed_send,
        timed_out,
        success_rate: rate(delivered, attempted),
        avg_latency_ms: mean(&latencies),
        p50_latency_ms: percentile(latencies.clone(), 0.50),
        p95_latency_ms: percentile(latencies, 0.95),
    }
}
