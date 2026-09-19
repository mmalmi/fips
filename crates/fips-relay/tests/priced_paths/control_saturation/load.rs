//! Apply the same payment and settlement assertions to both admission boundaries.
use super::{Bench, attack, half_open};
use fips_core::PeerIdentity;
use std::time::Duration;

pub(super) enum Load {
    Records(attack::Attack),
    Handshakes(half_open::Attack),
}

impl Load {
    pub(super) async fn start(bench: &Bench, handshakes: bool) -> Self {
        if handshakes {
            Self::Handshakes(half_open::start(bench).await)
        } else {
            let attack = attack::start(bench).await;
            tokio::time::timeout(Duration::from_secs(3), async {
                while attack.peers().iter().any(|peer| {
                    bench.admissions[1].active_unconfigured_exchanges(*peer.node_addr()) != 4
                }) {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("each record attacker must hold four shared permits");
            Self::Records(attack)
        }
    }

    pub(super) fn peers(&self) -> Vec<PeerIdentity> {
        match self {
            Self::Records(attack) => attack.peers().to_vec(),
            Self::Handshakes(attack) => attack.peers(),
        }
    }

    pub(super) async fn assert_held(&self, bench: &Bench) {
        let expected = match self {
            Self::Records(attack) => {
                attack.assert_live().await;
                4
            }
            Self::Handshakes(attack) => {
                attack.assert_live().await;
                assert!((24..=32).contains(&attack.confirmed_count()));
                eprintln!(
                    "incomplete TCP handshakes: {} confirmed retained tuples, no application permits",
                    attack.confirmed_count()
                );
                0
            }
        };
        for peer in self.peers() {
            assert_eq!(
                bench.admissions[1].active_unconfigured_exchanges(*peer.node_addr()),
                expected
            );
        }
    }

    pub(super) fn assert_reserved_capacity(&self) {
        if let Self::Handshakes(attack) = self {
            assert_eq!(
                attack.confirmed_count(),
                24,
                "ordinary SYNs must leave eight of the 32 TCP slots reserved"
            );
        }
    }

    pub(super) fn hold_age(&self) -> Duration {
        match self {
            Self::Records(attack) => attack.hold_age(),
            Self::Handshakes(attack) => attack.hold_age(),
        }
    }

    pub(super) async fn stop(self) {
        match self {
            Self::Records(attack) => attack.stop().await,
            Self::Handshakes(attack) => attack.stop().await,
        }
    }
}
