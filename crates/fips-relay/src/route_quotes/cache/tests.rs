use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

fn fixture() -> (Key, QuoteRequest, RouteOffer) {
    let peer = |n| {
        PeerIdentity::from_pubkey_full(Identity::from_secret_bytes(&[n; 32]).unwrap().pubkey_full())
    };
    let (buyer, provider, destination) = (peer(1), peer(2), peer(3));
    let key = Key {
        provider: *provider.node_addr(),
        destination: *destination.node_addr(),
        ancestors: vec![*buyer.node_addr()],
        max_units: None,
    };
    let request = QuoteRequest {
        destination,
        ancestors: key.ancestors.clone(),
        deadline_unix: unix_now().unwrap() + 10,
        reuse_unchanged: true,
        requested_max_units: None,
    };
    let offer = RouteOffer {
        trial: false,
        billing: Default::default(),
        id: "fixed-agreement".into(),
        buyer: *buyer.node_addr(),
        provider: key.provider,
        destination,
        next_hop: key.destination,
        path: vec![key.provider, key.destination],
        price: BytePrice {
            msat: 1024,
            per_bytes: 1024,
        },
        expires_unix: unix_now().unwrap() + 120,
        max_units: 8192,
        mint_url: "http://test.invalid".into(),
        receiver_pubkey_hex: "02".to_owned() + &"11".repeat(32),
        capacity_sat: 32,
        grace_msat: 1024,
    };
    (key, request, offer)
}

#[tokio::test(start_paused = true)]
async fn cache_preserves_terms_but_not_past_freshness_expiry_or_a_fresh_request() {
    let (key, mut request, offer) = fixture();
    let cache = Cache::default();
    cache
        .get_or_fetch(key.clone(), &request, || async { Ok(offer.clone()) })
        .await
        .unwrap();
    let hit = cache
        .get_or_fetch(key.clone(), &request, || async {
            panic!("unexpected request")
        })
        .await
        .unwrap();
    assert_eq!(
        hit, offer,
        "expiry, identity and quota cannot be refreshed by a hit"
    );
    tokio::time::advance(FRESH_FOR).await;
    let mut fresh = offer.clone();
    fresh.id = "fresh-agreement".into();
    assert_eq!(
        cache
            .get_or_fetch(key.clone(), &request, || async { Ok(fresh.clone()) })
            .await
            .unwrap(),
        fresh
    );
    request.reuse_unchanged = false;
    assert_eq!(
        cache
            .get_or_fetch(key.clone(), &request, || async { Ok(offer.clone()) })
            .await
            .unwrap(),
        offer
    );
    request.reuse_unchanged = true;
    let slot = cache.entry(&key).unwrap();
    slot.lock()
        .await
        .as_mut()
        .unwrap()
        .result
        .as_mut()
        .unwrap()
        .expires_unix = unix_now().unwrap();
    assert_eq!(
        cache
            .get_or_fetch(key.clone(), &request, || async { Ok(fresh.clone()) })
            .await
            .unwrap(),
        fresh
    );
    cache.invalidate(key.provider, key.destination);
    assert_eq!(
        cache
            .get_or_fetch(key, &request, || async { Ok(offer.clone()) })
            .await
            .unwrap(),
        offer
    );
}

#[tokio::test(start_paused = true)]
async fn concurrent_cache_misses_and_short_lived_rejections_share_work() {
    let (key, request, offer) = fixture();
    let cache = Arc::new(Cache::default());
    let started = Arc::new(AtomicUsize::new(0));
    let mut tasks = JoinSet::new();
    for _ in 0..8 {
        let (cache, key, request, offer, started) = (
            cache.clone(),
            key.clone(),
            request.clone(),
            offer.clone(),
            started.clone(),
        );
        tasks.spawn(async move {
            cache
                .get_or_fetch(key, &request, || async {
                    started.fetch_add(1, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Ok(offer)
                })
                .await
                .unwrap()
        });
    }
    while let Some(result) = tasks.join_next().await {
        assert_eq!(result.unwrap(), offer);
    }
    assert_eq!(started.load(Ordering::Relaxed), 1);
    cache.invalidate(key.provider, key.destination);
    assert!(
        cache
            .get_or_fetch(key.clone(), &request, || async { Err("no route".into()) })
            .await
            .is_err()
    );
    assert!(
        cache
            .get_or_fetch(key.clone(), &request, || async {
                panic!("negative hit must not send")
            })
            .await
            .is_err()
    );
    tokio::time::advance(REJECT_FOR).await;
    assert_eq!(
        cache
            .get_or_fetch(key, &request, || async { Ok(offer.clone()) })
            .await
            .unwrap(),
        offer
    );
}

#[tokio::test(start_paused = true)]
async fn caller_cancellation_and_waiter_deadlines_do_not_leave_a_busy_cache_slot() {
    let (key, request, offer) = fixture();
    let cache = Arc::new(Cache::default());
    let (started, ready) = tokio::sync::oneshot::channel();
    let (c, k, r) = (cache.clone(), key.clone(), request.clone());
    let leader = tokio::spawn(async move {
        c.get_or_fetch(k, &r, || async {
            started.send(()).unwrap();
            std::future::pending::<Result<RouteOffer, String>>().await
        })
        .await
    });
    ready.await.unwrap();
    let mut short = request.clone();
    short.deadline_unix = unix_now().unwrap() + 1;
    assert!(
        cache
            .get_or_fetch(key.clone(), &short, || async {
                panic!("waiter cannot fetch yet")
            })
            .await
            .is_err()
    );
    leader.abort();
    assert!(leader.await.unwrap_err().is_cancelled());
    assert_eq!(
        cache
            .get_or_fetch(key, &request, || async { Ok(offer.clone()) })
            .await
            .unwrap(),
        offer
    );
}

#[test]
fn cache_keys_keep_loop_context_and_caps_separate_and_bound_active_and_idle_state() {
    let (key, _, _) = fixture();
    let cache = Cache::default();
    let first = cache.entry(&key).unwrap();
    let mut limited = key.clone();
    limited.max_units = Some(8192);
    assert!(!Arc::ptr_eq(&first, &cache.entry(&limited).unwrap()));
    let mut other_path = key.clone();
    other_path.ancestors.push(key.destination);
    assert!(!Arc::ptr_eq(&first, &cache.entry(&other_path).unwrap()));
    drop(first);
    for cap in 1..=MAX_PER_PROVIDER * 2 {
        let mut next = key.clone();
        next.max_units = Some(cap as u64);
        drop(cache.entry(&next).unwrap());
        assert!(cache.entries.lock().unwrap().len() <= MAX_PER_PROVIDER);
    }
    let cache = Cache::default();
    let mut live = Vec::new();
    for index in 0..MAX_ENTRIES {
        let mut next = key.clone();
        next.provider = *Identity::generate().node_addr();
        next.max_units = Some(index as u64 + 1);
        live.push(cache.entry(&next).unwrap());
    }
    assert!(
        cache.entry(&key).is_err(),
        "cannot evict ongoing coalesced work"
    );
    live.clear();
    assert!(
        cache.entry(&key).is_ok(),
        "idle entries may be evicted without renewing quotes"
    );
    assert_eq!(cache.entries.lock().unwrap().len(), MAX_ENTRIES);
}
