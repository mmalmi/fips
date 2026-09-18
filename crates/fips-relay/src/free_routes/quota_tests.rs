use super::*;

#[test]
fn source_denial_keeps_positive_remainder_and_exact_grant_identity() {
    let routes = FreeRoutes::default();
    let grant = offer(2, 3, 9);
    let key = (grant.provider, *grant.destination.node_addr());
    routes.accept(&grant).unwrap();
    assert_eq!(routes.prepare_onward(key.0, key.1, 84), Some(true));
    assert_eq!(routes.quota_blocked(&grant), Ok(Some(false)));
    assert_eq!(routes.prepare_onward(key.0, key.1, 20), Some(false));
    assert_eq!(routes.quota_blocked(&grant), Ok(Some(true)));
    assert_eq!(routes.remaining_units(&grant), Some(16));
    routes.accept(&grant).unwrap();
    assert_eq!(
        routes.quota_blocked(&grant),
        Ok(Some(true)),
        "reaccepting cannot clear the demand"
    );
    let changed = RouteOffer {
        max_units: 200,
        ..grant.clone()
    };
    assert_eq!(routes.quota_blocked(&changed), Ok(None));
    let replacement = RouteOffer {
        id: "replacement".into(),
        ..grant.clone()
    };
    routes.accept(&replacement).unwrap();
    assert_eq!(routes.quota_blocked(&grant), Ok(None));
    assert_eq!(routes.quota_blocked(&replacement), Ok(Some(false)));
}

#[test]
fn expiry_zero_bytes_and_failed_admission_are_not_quota_denial() {
    let grant = offer(2, 3, 9);
    let mut lease = Lease {
        offer: grant.clone(),
        used: 0,
        quota_blocked: false,
    };
    assert!(lease.reserve(0, 0, true, || Some(())).is_none());
    assert!(
        lease
            .reserve(101, grant.expires_unix, true, || Some(()))
            .is_none()
    );
    assert!(lease.reserve(20, 0, true, || None::<()>).is_none());
    assert!(!lease.quota_blocked);
    assert_eq!(lease.used, 0);
    lease.offer.max_units = u64::MAX;
    assert!(lease.reserve(1, 0, true, || Some(())).is_some());
    assert!(lease.reserve(u64::MAX, 0, true, || Some(())).is_none());
    assert!(lease.quota_blocked);
    assert_eq!(lease.used, 1);
}

#[test]
fn poisoned_free_admission_evidence_is_an_error() {
    let routes = Arc::new(FreeRoutes::default());
    let poisoned = routes.clone();
    assert!(
        std::thread::spawn(move || {
            let _guard = poisoned.state.lock().unwrap();
            panic!("poison free routes");
        })
        .join()
        .is_err()
    );
    assert!(routes.quota_blocked(&offer(2, 3, 9)).is_err());
}

#[test]
fn unauthorized_transit_cannot_mark_a_source_grant_blocked() {
    let routes = FreeRoutes::default();
    let grant = offer(2, 3, 9);
    let key = (grant.provider, *grant.destination.node_addr());
    routes.accept(&grant).unwrap();
    assert_eq!(routes.prepare_onward(key.0, key.1, 84), Some(true));
    assert!(
        routes
            .onward::<()>(key.0, key.1, 20, || panic!(
                "over-quota transit must not attempt upstream admission"
            ))
            .is_none()
    );
    assert_eq!(routes.quota_blocked(&grant), Ok(Some(false)));
    assert_eq!(routes.remaining_units(&grant), Some(16));
    assert!(routes.onward(key.0, key.1, 10, || None::<()>).is_none());
    assert_eq!(routes.quota_blocked(&grant), Ok(Some(false)));
    assert_eq!(routes.remaining_units(&grant), Some(16));
}
