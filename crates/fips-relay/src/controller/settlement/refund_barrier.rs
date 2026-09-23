//! Local process-test seam after wallet completion, before controller completion.
use std::{fs, io::ErrorKind, path::Path};

pub(super) async fn hold(wallet: &Path, channel: &str) -> Result<(), String> {
    let arm = wallet.join("test-refund-handoff.arm");
    let requested = match fs::read_to_string(&arm) {
        Ok(requested) => requested,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.to_string()),
    };
    if requested != channel {
        return Ok(());
    }
    // Consume the exact-channel arm so an ordinary restart cannot pause again.
    // The fixture kills this process after observing the marker; no proofs or
    // mutable financial state are exposed through this test-only handshake.
    fs::remove_file(arm).map_err(|error| error.to_string())?;
    fs::write(
        wallet.join("test-refund-handoff.reached"),
        format!("{}\n{channel}", std::process::id()),
    )
    .map_err(|error| error.to_string())?;
    std::future::pending::<()>().await;
    Ok(())
}
