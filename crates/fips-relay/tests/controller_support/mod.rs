use super::*;

pub(super) fn policy(mint_url: &str, automatic_renewal: bool, capacity: u64) -> ControllerPolicy {
    ControllerPolicy {
        mint_url: mint_url.to_string(),
        channel_capacity_sat: capacity,
        max_locked_sat: capacity * 2,
        channel_lifetime_secs: 600,
        renewal: automatic_renewal.then_some(RenewalPolicy {
            at_capacity_percent: 100,
            before_expiry_secs: 30,
        }),
    }
}

#[cfg(unix)]
pub(super) async fn native_control(
    root: &std::path::Path,
    node: usize,
    request: serde_json::Value,
) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut socket = tokio::net::UnixStream::connect(root.join(format!("native-{node}.sock")))
            .await
            .unwrap();
        let mut bytes = serde_json::to_vec(&request).unwrap();
        bytes.push(b'\n');
        socket.write_all(&bytes).await.unwrap();
        let mut reply = String::new();
        BufReader::new(socket).read_line(&mut reply).await.unwrap();
        let reply: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(reply["status"], "ok", "native control failed: {reply}");
    })
    .await
    .expect("native management deadline");
}
