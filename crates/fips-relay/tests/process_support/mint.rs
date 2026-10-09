//! Hold only the selected channel close, even during concurrent mint operations.
use cashu_service::simulation::MintProxy;
use std::path::Path;

pub fn pause_channel_close(
    proxy: &MintProxy,
    wallet: &Path,
    channel: &str,
) -> (
    tokio::sync::oneshot::Receiver<()>,
    tokio::sync::oneshot::Sender<()>,
) {
    let store: serde_json::Value = serde_json::from_slice(
        &std::fs::read(cashu_service::spilman_client_store_path(wallet)).unwrap(),
    )
    .unwrap();
    let funding: Vec<cashu::nuts::Proof> = serde_json::from_str(
        store["funding"][channel]["funding_proofs_json"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let originals: std::collections::BTreeSet<_> = funding
        .iter()
        .map(|proof| proof.y().unwrap().to_string())
        .collect();
    assert!(!originals.is_empty());
    proxy.state.pause_matching_swap_reply(move |swap| {
        swap.inputs().len() == originals.len()
            && swap
                .inputs()
                .iter()
                .all(|proof| proof.y().is_ok_and(|y| originals.contains(&y.to_string())))
    })
}
