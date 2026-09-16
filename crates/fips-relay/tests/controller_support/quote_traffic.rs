//! Actual TCP/FIPS quotes crossing paid relays use ordinary byte accounting.
use super::*;
use fips_relay::{
    controller::Purchase,
    route_quotes::{QuoteRequest, QuoteResponse},
};

pub(super) async fn exercise(
    nodes: &[Arc<FipsEndpoint>],
    peers: &[PeerIdentity],
    services: &[ControllerServices],
    ledgers: &[Arc<DurableRelay>],
    links: &[(usize, usize, Purchase)],
) {
    let (client, _) = ControlTransport::start(nodes[0].clone(), 44_748, vec![peers[4]], 80)
        .await
        .unwrap();
    let (server_transport, incoming) =
        ControlTransport::start(nodes[4].clone(), 44_748, vec![peers[0]], 81)
            .await
            .unwrap();
    let server = QuoteServer::start(services[4].quotes.clone(), incoming);
    let before: Vec<_> = links
        .iter()
        .map(|(_, seller, p)| {
            ledgers[*seller]
                .usage(&p.contract.id)
                .unwrap()
                .submitted_units
        })
        .collect();
    let body = serde_json::to_vec(&QuoteRequest {
        destination: peers[3],
        ancestors: vec![*peers[0].node_addr()],
        deadline_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 10,
        reuse_unchanged: true,
        requested_max_units: None,
    })
    .unwrap();
    let sent_bytes = body.len() as u64;
    let response = client.request(peers[4], body).await.unwrap();
    let QuoteResponse::Offer { offer } = serde_json::from_slice(&response).unwrap() else {
        panic!("remote quote must be served through the paid route");
    };
    assert_eq!(offer.provider, *peers[4].node_addr());
    assert_eq!(offer.buyer, *peers[0].node_addr());
    assert_eq!(offer.price.msat, 1024);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let accounted = links.iter().zip(&before).all(|((buyer, seller, p), old)| {
                let bytes = if buyer < seller {
                    sent_bytes
                } else {
                    response.len() as u64
                };
                ledgers[*seller]
                    .usage(&p.contract.id)
                    .unwrap()
                    .submitted_units
                    >= old + bytes
            });
            if accounted {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("every paid hop must account for request and reply bytes");
    assert_eq!(client.statistics().snapshot().requests_started, 1);
    assert_eq!(
        server_transport.statistics().snapshot().requests_received,
        1
    );
    server.stop().await;
}
