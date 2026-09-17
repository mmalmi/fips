//! One acknowledgment after durable refund recovery releases the seller's report.
use super::*;

impl Controller {
    pub(super) async fn release_settlement(&self, id: &str) -> Result<(), String> {
        let snapshot = self.snapshot().await?;
        let saved = snapshot
            .buyer_settlements
            .get(id)
            .ok_or("settlement missing")?;
        if !saved.refunded || saved.report.is_none() {
            return Err("recover refund before releasing settlement".into());
        }
        if saved.released {
            return Ok(());
        }
        let peer = self.neighbor(saved.provider).await?;
        let response = self
            .settlement_request(
                peer,
                ControllerRequest::ReleaseSettlement {
                    channel_id: id.into(),
                },
            )
            .await
            .map_err(|error| {
                format!("refund recovered; settlement report release pending: {error}")
            })?;
        if !matches!(response, ControllerResponse::SettlementReleased { ref channel_id } if channel_id == id)
        {
            return Err("settlement release response changed channel".into());
        }
        let id = id.to_owned();
        self.change(move |j| {
            let current = j
                .buyer_settlements
                .get_mut(&id)
                .ok_or("settlement missing")?;
            if !current.refunded {
                return Err("refund completion changed".into());
            }
            current.released = true;
            Ok(())
        })
        .await
    }

    pub(super) async fn handle_release_settlement(
        &self,
        peer: PeerIdentity,
        id: &str,
    ) -> Result<ControllerResponse, String> {
        if id.is_empty() || id.len() > 128 {
            return Err("invalid release identity".into());
        }
        let Some(_claim) = self.settlement_claim(id) else {
            return Ok(ControllerResponse::Pending);
        };
        let snapshot = self.snapshot().await?;
        let response = ControllerResponse::SettlementReleased {
            channel_id: id.into(),
        };
        if !release_needed(&snapshot, *peer.node_addr(), id)? {
            return Ok(response);
        }
        let id = id.to_owned();
        let buyer = *peer.node_addr();
        self.change(move |j| {
            if !release_needed(j, buyer, &id)? {
                return Ok(());
            }
            let sale = j
                .seller_settlements
                .get_mut(&id)
                .ok_or("settlement missing")?;
            sale.released = true;
            Ok(())
        })
        .await?;
        Ok(response)
    }
}

fn release_needed(j: &Journal, buyer: NodeAddr, id: &str) -> Result<bool, String> {
    let Some(sale) = j.seller_settlements.get(id) else {
        if j.incoming.values().any(|i| i.channel.id == id)
            || j.history
                .as_ref()
                .is_some_and(|h| h.sellers.contains_key(id))
        {
            return Err("settlement has not completed".into());
        }
        // Absence acknowledges a no-op, not channel existence or a payment.
        // No tombstone, future release permission or disk write is created.
        return Ok(false);
    };
    if sale.channel.buyer != buyer || sale.report.is_none() {
        return Err("wrong release buyer or unfinished settlement".into());
    }
    Ok(!sale.released)
}

#[cfg(test)]
mod tests;
