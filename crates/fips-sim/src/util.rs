use super::*;

const SIM_RECV_BATCH_MAX: usize = 128;

pub(super) async fn recv_endpoint_batch_into(
    endpoint: &FipsEndpoint,
    messages: &mut Vec<FipsEndpointMessage>,
    timeout: Duration,
) -> Option<usize> {
    let received = tokio::time::timeout(
        timeout,
        endpoint.recv_batch_into(messages, SIM_RECV_BATCH_MAX),
    )
    .await
    .ok()??;
    if received == 0 { None } else { Some(received) }
}

pub(super) fn pick_pair(indices: &[usize], rng: &mut StdRng) -> (usize, usize) {
    let src_pos = rng.random_range(0..indices.len());
    let mut dst_pos = rng.random_range(0..indices.len() - 1);
    if dst_pos >= src_pos {
        dst_pos += 1;
    }
    (indices[src_pos], indices[dst_pos])
}

pub(super) fn shuffle(values: &mut [usize], rng: &mut StdRng) {
    for i in (1..values.len()).rev() {
        let j = rng.random_range(0..=i);
        values.swap(i, j);
    }
}

pub(super) fn fraction_count(total: usize, fraction: f64) -> usize {
    ((total as f64 * fraction.clamp(0.0, 1.0)).round() as usize).min(total)
}

pub(super) fn rate(numerator: usize, denominator: usize) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

pub(super) fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

pub(super) fn percentile(mut values: Vec<f64>, percentile: f64) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.total_cmp(b));
    let index = ((values.len() - 1) as f64 * percentile.clamp(0.0, 1.0)).round() as usize;
    values[index]
}
