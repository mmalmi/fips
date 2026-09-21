use crate::node::{
    ForwardingAdmission, ForwardingClass, ForwardingOutcome, ForwardingPolicy, ForwardingRequest,
};
use crate::peer::ActivePeer;
use crate::transport::LinkId;

#[derive(Debug)]
struct Admission(Option<ForwardingAdmission>);

impl ForwardingPolicy for Admission {
    fn admit(&self, _: &ForwardingRequest<'_>) -> Option<u64> {
        self.0.as_ref().map(|value| value.token)
    }

    fn admit_classified(&self, _: &ForwardingRequest<'_>) -> Option<ForwardingAdmission> {
        self.0
    }

    fn complete(&self, _: u64, _: ForwardingOutcome) {}
}

fn fixture() -> (Node, crate::PeerIdentity, NodeAddr) {
    let mut node = Node::new(crate::Config::new()).unwrap();
    let identities: Vec<_> = (0..2)
        .map(|_| crate::PeerIdentity::from_pubkey_full(crate::Identity::generate().pubkey_full()))
        .collect();
    for (index, identity) in identities.iter().enumerate() {
        node.peers.insert(
            *identity.node_addr(),
            ActivePeer::new(*identity, LinkId::new(index as u64 + 1), 1),
        );
    }
    (node, identities[0], *identities[1].node_addr())
}

#[tokio::test]
async fn transit_protection_follows_real_admission_equally_across_classes() {
    for admission in [
        None,
        Some(ForwardingAdmission {
            token: 0,
            class: ForwardingClass::Background,
        }),
        Some(ForwardingAdmission {
            token: 7,
            class: ForwardingClass::Normal,
        }),
    ] {
        let (mut node, ingress, next) = fixture();
        node.set_forwarding_policy(Some(std::sync::Arc::new(Admission(admission))));
        let encoded = SessionDatagram::new(*ingress.node_addr(), next, vec![1, 2, 3]).encode();
        let prepared = node
            .prepare_session_datagram(AuthenticatedSessionDatagram::new(
                ingress,
                &encoded[1..],
                false,
            ))
            .await;
        let now = Node::now_ms();
        for peer in [ingress.node_addr(), &next] {
            assert_eq!(
                node.peer_has_application_demand(peer, now, 1_000),
                admission.is_some()
            );
        }
        if admission.is_some() {
            let PreparedSessionDatagram::Forward(route) = prepared else {
                panic!("admitted direct transit must prepare a forward");
            };
            // No transport exists. A local submission failure must not erase
            // admitted demand or misclassify the two active neighbors as idle.
            node.finish_prepared_session_forward(
                route.with_plaintext(PacketBuffer::default()),
                Err(NodeError::SendFailed {
                    node_addr: next,
                    reason: "local overload".into(),
                }),
                false,
            )
            .await;
            for peer in [ingress.node_addr(), &next] {
                assert!(node.peer_has_application_demand(peer, Node::now_ms(), 1_000));
            }
        } else {
            assert!(matches!(prepared, PreparedSessionDatagram::Done));
            assert_eq!(node.stats().forwarding.drop_policy_denied_packets, 1);
        }
    }
}

#[tokio::test]
async fn pending_and_completed_transit_protect_both_neighbors_until_drained() {
    let (mut node, ingress, next) = fixture();
    let encoded = SessionDatagram::new(*ingress.node_addr(), next, vec![1, 2, 3]).encode();
    let PreparedSessionDatagram::Forward(route) = node
        .prepare_session_datagram(AuthenticatedSessionDatagram::new(
            ingress,
            &encoded[1..],
            false,
        ))
        .await
    else {
        panic!("default native transit must prepare a forward");
    };
    let future = Node::now_ms() + 10_000;
    for peer in [ingress.node_addr(), &next] {
        assert!(!node.peer_has_application_demand(peer, future, 1));
    }
    node.deferred_session_forwards.insert(
        1,
        route.with_plaintext(PacketBuffer::default()),
        ForwardingLane::Bulk,
    );
    for peer in [ingress.node_addr(), &next] {
        assert!(node.peer_has_application_demand(peer, future, 1));
    }
    let pending = node.deferred_session_forwards.take_pending(1).unwrap();
    node.deferred_session_forwards
        .push_completed(pending, Ok(()));
    for peer in [ingress.node_addr(), &next] {
        assert!(node.peer_has_application_demand(peer, future, 1));
    }
    drop(node.deferred_session_forwards.pop_completed().unwrap());
    for peer in [ingress.node_addr(), &next] {
        assert!(!node.peer_has_application_demand(peer, future, 1));
    }
}
