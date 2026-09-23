//! Fixed population variants of the same repeated, full-roster acceptance case.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Population {
    pub candidates_per_boundary: usize,
    pub first_scalar: u8,
    pub reversed: bool,
    pub idle_secs: u64,
    pub diagnose_miss: bool,
    pub brief_contact: Option<brief::Kind>,
    pub capacity: CapacityLimits,
}

impl Population {
    pub(super) fn baseline(candidates_per_boundary: usize) -> Self {
        Self {
            candidates_per_boundary,
            first_scalar: 1,
            reversed: false,
            idle_secs: IDLE_SECS,
            diagnose_miss: false,
            brief_contact: None,
            capacity: CapacityLimits::ORIGINAL,
        }
    }

    pub(super) fn scalar(self, index: usize, count: usize) -> u8 {
        let offset = if self.reversed {
            count - 1 - index
        } else {
            index
        };
        self.first_scalar
            .checked_add(offset.try_into().unwrap())
            .unwrap()
    }
}

pub(super) async fn make_nodes(network: &str, population: Population) -> Vec<TestNode> {
    let addresses = &RESPONSIVE_ADDRESSES[..4 + 2 * population.candidates_per_boundary];
    let mut nodes = Vec::new();
    for (i, address) in addresses.iter().enumerate() {
        nodes.push(
            make_node_with(network, address, i < 2, |config| {
                // Public test-only scalars keep identity-based discovery order reproducible.
                config.node.identity.nsec =
                    Some(format!("{:02x}", population.scalar(i, addresses.len())).repeat(32));
                // Keep normal handshake/retry policy, independently from the
                // unanswered-dial fixture's deliberately short timeout.
                config.node.rate_limit = Config::new().node.rate_limit;
                assert_eq!(config.node.rate_limit.handshake_timeout_secs, 30);
                let role = usize::from(i >= 2);
                config.node.limits.max_connections = population.capacity.connections[role];
                config.node.limits.max_links = population.capacity.links[role];
                config.node.neighbor_rotation = (i < 2).then_some(NeighborRotationConfig {
                    idle_secs: population.idle_secs,
                    interval_secs: INTERVAL_SECS,
                });
                config.transports.sim = TransportInstances::Single(SimTransportConfig {
                    network: Some(network.to_owned()),
                    addr: Some(address.to_string()),
                    auto_connect: Some(true),
                    ..Default::default()
                });
            })
            .await,
        );
    }
    nodes
}

fn repeated(population: Population) {
    // Match the existing staggered control: only identities or population change.
    // All candidates keep responding and remain present through both encounters.
    run_population(
        population,
        Duration::from_secs(60),
        true,
        Duration::from_millis(500),
    );
}

#[test]
fn repeated_full_rosters_with_eight_responsive_candidates() {
    repeated(Population::baseline(8));
}

#[test]
fn repeated_full_rosters_with_paid_boundary_capacity() {
    // Match the four-candidate staggered control; only allocation limits change.
    // This is native admission coverage, not the paid topology or RX-loop fixture.
    repeated(Population {
        capacity: CapacityLimits {
            connections: [4, 2],
            links: [4, 2],
        },
        ..Population::baseline(4)
    });
}

#[test]
fn repeated_full_rosters_with_reversed_identity_roles() {
    repeated(Population {
        reversed: true,
        ..Population::baseline(4)
    });
}

#[test]
fn repeated_full_rosters_with_a_different_identity_population() {
    repeated(Population {
        first_scalar: 33,
        ..Population::baseline(4)
    });
}

#[test]
fn eight_candidates_with_five_second_minimum_age() {
    repeated(Population {
        idle_secs: 5,
        ..Population::baseline(8)
    });
}

#[test]
fn eight_candidates_with_two_second_minimum_age() {
    repeated(Population {
        idle_secs: 2,
        ..Population::baseline(8)
    });
}

#[test]
fn two_second_age_with_reversed_identity_roles() {
    repeated(Population {
        idle_secs: 2,
        reversed: true,
        ..Population::baseline(8)
    });
}

#[test]
fn two_second_age_with_a_different_identity_population() {
    repeated(Population {
        idle_secs: 2,
        first_scalar: 33,
        ..Population::baseline(8)
    });
}

mod dense_identities {
    use super::*;

    // Keep the original dense population, timers, limits and traffic. Only the
    // fixed identity assignment changes; no identity is chosen by its outcome.
    #[test]
    fn shifted_population() {
        repeated(Population {
            first_scalar: 33,
            diagnose_miss: true,
            ..Population::baseline(8)
        });
    }

    #[test]
    fn reversed_roles() {
        repeated(Population {
            reversed: true,
            ..Population::baseline(8)
        });
    }
}
