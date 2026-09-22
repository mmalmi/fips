//! Fixed population variants of the same repeated, full-roster acceptance case.
use super::*;

#[derive(Clone, Copy)]
pub(super) struct Population {
    pub candidates_per_boundary: usize,
    pub first_scalar: u8,
    pub reversed: bool,
    pub idle_secs: u64,
    pub diagnose_miss: bool,
}

impl Population {
    pub(super) fn baseline(candidates_per_boundary: usize) -> Self {
        Self {
            candidates_per_boundary,
            first_scalar: 1,
            reversed: false,
            idle_secs: IDLE_SECS,
            diagnose_miss: false,
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
