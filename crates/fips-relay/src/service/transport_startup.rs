//! Refuse partial deployment before activating payment or forwarding workers.
use super::{ServiceConfig, native_request};
use serde_json::json;
use std::{collections::BTreeSet, io::ErrorKind, time::Duration};
use tokio::net::UnixStream;

async fn wait_for_control(config: &ServiceConfig) -> Result<(), String> {
    let socket = config.state_directory.join("native.sock");
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            match UnixStream::connect(&socket).await {
                Ok(_) => return Ok(()),
                Err(error)
                    if matches!(
                        error.kind(),
                        ErrorKind::NotFound | ErrorKind::ConnectionRefused
                    ) =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => {
                    return Err(format!("native transport startup control failed: {error}"));
                }
            }
        }
    })
    .await
    .map_err(|_| "native transport startup control did not become ready".to_string())?
}

pub(super) async fn verify(config: &ServiceConfig) -> Result<(), String> {
    // Network validation limits the service to these native adapter types.
    // Preserve instance names: one healthy sibling must not mask a failed bind.
    let requested: BTreeSet<_> = config
        .transports
        .udp
        .iter()
        .map(|(name, _)| ("udp".to_owned(), name.map(str::to_owned)))
        .chain(
            config
                .transports
                .tcp
                .iter()
                .map(|(name, _)| ("tcp".to_owned(), name.map(str::to_owned))),
        )
        .chain(
            config
                .transports
                .ethernet
                .iter()
                .map(|(name, _)| ("ethernet".to_owned(), name.map(str::to_owned))),
        )
        .collect();
    // The node binds its operator socket from a task started after endpoint bind.
    wait_for_control(config).await?;
    let report = native_request(config, &json!({"command": "show_transports"})).await?;
    if report["status"] != "ok" {
        let message = report["message"]
            .as_str()
            .unwrap_or("no native error message");
        return Err(format!(
            "native transport startup inspection failed: {message}"
        ));
    }
    let rows = report["data"]["transports"]
        .as_array()
        .ok_or("invalid native transport startup report")?;
    let mut operational = BTreeSet::new();
    for row in rows {
        let kind = row["type"]
            .as_str()
            .ok_or("invalid native transport type")?;
        let name = match row.get("name") {
            None => None,
            Some(name) => Some(
                name.as_str()
                    .ok_or("invalid native transport name")?
                    .to_owned(),
            ),
        };
        if row["state"] != "up" || !operational.insert((kind.to_owned(), name)) {
            return Err("native transport is not operational or has a repeated instance".into());
        }
    }
    if operational != requested {
        return Err(
            "configured native transport instances did not all start exactly as requested".into(),
        );
    }
    Ok(())
}
