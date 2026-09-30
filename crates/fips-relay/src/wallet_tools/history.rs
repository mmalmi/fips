//! Local custody acknowledgements reuse the SDK's durable sequence floor.
use super::*;
use cashu_service::CashuRequestSequence;

const SCOPE: &str = "fips-exports";
const MAX_FILES: usize = 128;

fn request_id(id: u64) -> Result<String, String> {
    CashuRequestSequence::new(SCOPE, id)
        .map(|s| s.request_id())
        .map_err(|e| e.to_string())
}

async fn floor(wallet: &CashuWalletService, mint: &str) -> Result<u64, String> {
    let history = wallet
        .wallet_send_history()
        .await
        .map_err(|e| e.to_string())?;
    let Some(history) = history.sequences.get(SCOPE) else {
        return Ok(0);
    };
    if history.mint_url != normalize_mint_url(mint).map_err(|e| e.to_string())? {
        return Err("export history belongs to another mint".into());
    }
    Ok(history.through)
}

// Count every entry, including unknown files, but never discard unknown evidence.
// One extra entry permits recovery after interruption of an atomic publication.
fn files(root: &Path) -> Result<Vec<(PathBuf, Option<u64>)>, String> {
    let directory = match std::fs::read_dir(root.join("exports")) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.to_string()),
    };
    let mut files = Vec::new();
    for entry in directory.take(MAX_FILES + 2) {
        let entry = entry.map_err(|e| e.to_string())?;
        if files.len() > MAX_FILES {
            return Err(
                "export directory exceeds its limit; preserve it for reconciliation".into(),
            );
        }
        let name = entry.file_name();
        let id = name
            .to_str()
            .and_then(|s| s.strip_suffix(".json"))
            .and_then(|s| {
                s.parse::<u64>()
                    .ok()
                    .filter(|id| *id > 0 && id.to_string() == s)
            });
        if id.is_some() && !entry.file_type().map_err(|e| e.to_string())?.is_file() {
            return Err("export is not a regular file; preserve it for reconciliation".into());
        }
        files.push((entry.path(), id));
    }
    Ok(files)
}

fn clean(root: &Path, files: &[(PathBuf, Option<u64>)], through: u64) -> Result<usize, String> {
    let mut removed = 0;
    for (path, id) in files {
        if id.is_some_and(|id| id <= through) {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
            removed += 1;
        }
    }
    if removed > 0 {
        File::open(root.join("exports"))
            .and_then(|f| f.sync_all())
            .map_err(|e| e.to_string())?;
    }
    Ok(removed)
}

pub(super) async fn prepare_export(root: &Path, mint: &str, id: u64) -> Result<String, String> {
    let request = request_id(id)?;
    let wallet = CashuWalletService::open_file_backed(&root.join("wallet"))
        .await
        .map_err(|e| e.to_string())?;
    let through = floor(&wallet, mint).await?;
    if id <= through {
        return Err("export request has been acknowledged and cannot be reused".into());
    }
    let files = files(root)?;
    if through > 0 {
        // A prior acknowledgement may have committed its floor before native
        // history pruning or cache deletion failed. Complete that work first.
        wallet
            .retire_send_requests(SCOPE, through)
            .await
            .map_err(|e| e.to_string())?;
    }
    let removed = clean(root, &files, through)?;
    if files.len() - removed >= MAX_FILES && !files.iter().any(|(_, n)| *n == Some(id)) {
        return Err("export file limit reached; collect and acknowledge completed exports".into());
    }
    Ok(request)
}

pub(super) async fn acknowledge(root: &Path, mint: &str, through: u64) -> Result<Value, String> {
    request_id(through)?;
    let wallet = CashuWalletService::open_file_backed(&root.join("wallet"))
        .await
        .map_err(|e| e.to_string())?;
    let previous = floor(&wallet, mint).await?;
    let files = files(root)?;
    for (path, id) in &files {
        if let Some(id) = id.filter(|id| *id > previous && *id <= through) {
            let cached: CashuSentPayment = read_json(path)?;
            check_cached(
                &wallet,
                send_request(
                    normalize_mint_url(mint).map_err(|e| e.to_string())?,
                    request_id(id)?,
                    cached.amount_sat,
                ),
                &cached,
            )
            .await?;
        }
    }
    // The caller has accepted custody of this entire prefix. The SDK refuses
    // unfinished sends, preserves gross costs and closes absent numbers too.
    // Commit that permanent replay barrier before removing any token files.
    let history = wallet
        .retire_send_requests(SCOPE, through)
        .await
        .map_err(|e| e.to_string())?;
    clean(root, &files, history.through)?;
    serde_json::to_value(history).map_err(|e| e.to_string())
}
