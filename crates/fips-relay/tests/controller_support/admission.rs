//! Real adjacent-node admission without giving discovery spending authority.
use super::*;
use fips_relay::control_transport::{ControlAdmission, NeighborAdmission};

pub(super) fn for_router(
    endpoint: Arc<FipsEndpoint>,
    peers: &[PeerIdentity],
    index: usize,
    route_change: bool,
    dynamic: bool,
) -> Arc<ControlAdmission> {
    let neighbors = if dynamic {
        vec![]
    } else {
        peers
            .iter()
            .enumerate()
            .filter(|(other, _)| {
                index.abs_diff(*other) == 1
                    || (route_change && matches!((index, *other), (1, 3) | (3, 1)))
            })
            .map(|(_, peer)| *peer)
            .collect()
    };
    let mode = if dynamic {
        NeighborAdmission::AuthenticatedAdjacent
    } else {
        NeighborAdmission::ConfiguredOnly
    };
    ControlAdmission::new(endpoint, neighbors, None, mode).unwrap()
}

pub(super) async fn quotes_preserve_financial_authority(
    controllers: &[Arc<Controller>],
    services: &[ControllerServices],
    peers: &[PeerIdentity],
    mint: &str,
) {
    // Link setup is explicit UDP in this harness; native beacon discovery has
    // a separate acceptance gate. All payment control rosters here are empty.
    let offer = services[0].quotes.request_route(peers[4]).await.unwrap();
    assert_eq!(offer.price.msat, 3_072);
    for (controller, service) in controllers.iter().zip(services) {
        assert!(controller.purchases().await.unwrap().is_empty());
        assert_eq!(controller.locked_capital_sat().await.unwrap(), 0);
        assert_eq!(service.buyer.remaining_budget_sat(), Some(64));
        assert_eq!(
            load_mint_balance(&service.wallet_directory, mint)
                .await
                .unwrap()
                .balance_sat,
            128,
            "joining and quoting cannot fund a channel"
        );
    }
}
