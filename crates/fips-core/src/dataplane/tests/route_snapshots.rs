use super::*;

fn address(index: usize) -> NodeAddr {
    let mut bytes = [0x5a; 16];
    bytes[..8].copy_from_slice(&(index as u64).to_le_bytes());
    NodeAddr::from_bytes(bytes)
}

fn owner_routes(
    index: usize,
    generation: u64,
    protocol: PacketProtocol,
) -> (OwnerId, DataplaneLiveOwnerRoutes) {
    let addr = address(index);
    let owner = match protocol {
        PacketProtocol::Fmp => OwnerId::fmp_node(addr),
        PacketProtocol::Fsp => OwnerId::fsp_node(addr),
    };
    let ingress = DataplaneIngressRoute::new(owner, generation, OutputTarget::Transport)
        .with_class(PacketClass::Bulk);
    let mut routes = DataplaneLiveOwnerRoutes::new();
    match protocol {
        PacketProtocol::Fmp => {
            // Current, pending and previous receive indices. Rotate keys as
            // well as generation so stale route removal stays in the workload.
            for epoch in 0..3 {
                routes.push_fmp_ingress(
                    TransportId::new(1),
                    index as u32 * 8 + (generation as u32 % 2) * 3 + epoch,
                    ingress,
                );
            }
        }
        PacketProtocol::Fsp => {
            routes.push_fsp_ingress(addr, ingress);
            routes.push_tun_destination(
                addr,
                DataplaneTunOutboundRoute::fsp_ipv6_shim(
                    owner,
                    generation,
                    PacketClass::Bulk,
                    0,
                    0,
                ),
            );
            routes.push_endpoint_destination(
                addr,
                DataplaneEndpointDataRoute::fsp(owner, generation, 0, 0),
            );
        }
    }
    (owner, routes)
}

fn populated_routes(peers: usize) -> DataplaneLiveRouteTable {
    let mut table = DataplaneLiveRouteTable::default();
    for index in 0..peers {
        for protocol in [PacketProtocol::Fmp, PacketProtocol::Fsp] {
            owner_routes(index, 1, protocol).1.apply_to(&mut table);
        }
    }
    table
}

fn assert_route_counts(table: &DataplaneLiveRouteTable, peers: usize) {
    assert_eq!(table.fmp.len(), peers * 3);
    assert_eq!(table.fsp.len(), peers);
    assert_eq!(table.tun_outbound.len(), peers);
    assert_eq!(table.endpoint.len(), peers);
}

#[test]
fn unique_route_snapshots_update_without_replacing_map_storage() {
    let snapshot = DataplaneEstablishedFastIngressSnapshot::default();
    let fmp_owner = OwnerId::fmp_node(address(1));
    let fsp_owner = OwnerId::fsp_node(address(1));
    let fmp_route = DataplaneIngressRoute::new(fmp_owner, 1, OutputTarget::Transport);
    let fsp_route = DataplaneIngressRoute::new(fsp_owner, 1, OutputTarget::Transport);
    snapshot.register_fmp(TransportId::new(1), 7, fmp_route);
    snapshot.register_fsp(address(1), fsp_route);
    // Keep only raw identity values, never an extra Arc which would require a
    // copy. The live reader test below exercises the shared-ownership case.
    let fmp_storage = Arc::as_ptr(&*snapshot.fmp.read().unwrap());
    let fsp_storage = Arc::as_ptr(&*snapshot.fsp.read().unwrap());
    snapshot.register_fmp(TransportId::new(1), 8, fmp_route);
    snapshot.register_fsp(address(2), fsp_route);
    snapshot.unregister_owner(fmp_owner);
    snapshot.unregister_owner(fsp_owner);
    assert_eq!(Arc::as_ptr(&*snapshot.fmp.read().unwrap()), fmp_storage);
    assert_eq!(Arc::as_ptr(&*snapshot.fsp.read().unwrap()), fsp_storage);
    assert!(snapshot.fmp_routes().is_empty());
    assert!(snapshot.fsp_routes().is_empty());
}

#[test]
fn held_route_snapshots_keep_values_across_updates_and_removal() {
    let snapshot = DataplaneEstablishedFastIngressSnapshot::default();
    let fmp_owner = OwnerId::fmp_node(address(1));
    let fsp_owner = OwnerId::fsp_node(address(1));
    let old_fmp = DataplaneIngressRoute::new(fmp_owner, 1, OutputTarget::Transport);
    let old_fsp = DataplaneIngressRoute::new(fsp_owner, 1, OutputTarget::Transport);
    let new_fmp = DataplaneIngressRoute::new(fmp_owner, 2, OutputTarget::Transport);
    let new_fsp = DataplaneIngressRoute::new(fsp_owner, 2, OutputTarget::Transport);
    snapshot.register_fmp(TransportId::new(1), 7, old_fmp);
    snapshot.register_fsp(address(1), old_fsp);
    let held_fmp = snapshot.fmp_routes();
    let held_fsp = snapshot.fsp_routes();
    snapshot.register_fmp(TransportId::new(1), 7, new_fmp);
    snapshot.register_fsp(address(1), new_fsp);
    assert_eq!(
        held_fmp.get(&FmpIngressRouteKey::new(TransportId::new(1), 7)),
        Some(&old_fmp)
    );
    assert_eq!(held_fsp.get(&address(1)), Some(&old_fsp));
    assert_eq!(
        snapshot
            .fmp_routes()
            .get(&FmpIngressRouteKey::new(TransportId::new(1), 7)),
        Some(&new_fmp)
    );
    assert_eq!(snapshot.fsp_routes().get(&address(1)), Some(&new_fsp));
    let updated_fmp = snapshot.fmp_routes();
    let updated_fsp = snapshot.fsp_routes();
    snapshot.unregister_owner(fmp_owner);
    snapshot.unregister_owner(fsp_owner);
    assert!(snapshot.fmp_routes().is_empty());
    assert!(snapshot.fsp_routes().is_empty());
    assert_eq!(held_fmp.len(), 1);
    assert_eq!(held_fsp.len(), 1);
    assert_eq!(updated_fmp.values().next(), Some(&new_fmp));
    assert_eq!(updated_fsp.values().next(), Some(&new_fsp));
}

#[test]
fn owner_route_replacement_keeps_unrelated_routes_and_held_snapshots() {
    let mut table = populated_routes(3);
    let snapshot = table.established_fast_ingress_snapshot();
    let held_fmp = snapshot.fmp_routes();
    let held_fsp = snapshot.fsp_routes();
    for protocol in [PacketProtocol::Fmp, PacketProtocol::Fsp] {
        let (owner, routes) = owner_routes(1, 2, protocol);
        // These are the exact operations in replace_registered_owner_routes;
        // no worker runtime is needed to validate the route-table transition.
        assert_eq!(table.unregister_owner(owner), 3);
        routes.apply_to(&mut table);
    }
    assert_route_counts(&table, 3);
    assert_eq!(held_fmp.len(), 9);
    assert_eq!(held_fsp.len(), 3);
    assert!(held_fmp.values().all(|route| route.generation == 1));
    assert!(held_fsp.values().all(|route| route.generation == 1));
    for epoch in 0..3 {
        let stale = FmpIngressRouteKey::new(TransportId::new(1), 8 + 3 + epoch);
        let current = FmpIngressRouteKey::new(TransportId::new(1), 8 + epoch);
        assert!(!table.fmp.contains_key(&stale));
        assert_eq!(table.fmp[&current].generation, 2);
    }
    for index in 0..3 {
        let expected = if index == 1 { 2 } else { 1 };
        assert_eq!(table.fsp[&address(index)].generation, expected);
        assert_eq!(
            table.tun_outbound[&FipsTunDestinationPrefix::from_node_addr(address(index))]
                .generation,
            expected
        );
        assert_eq!(table.endpoint[&address(index)].generation, expected);
    }
    assert_eq!(*snapshot.fmp_routes(), table.fmp);
    assert_eq!(*snapshot.fsp_routes(), table.fsp);
}

#[test]
#[ignore = "manual bounded baseline/candidate comparison; run only after build-owner admission"]
fn route_snapshot_maintenance_benchmark() {
    use std::hint::black_box;
    use std::time::Instant;
    const OPERATIONS: usize = 256;
    for peers in [128, 1024] {
        for shared in [false, true] {
            let mut table = populated_routes(peers);
            let snapshot = table.established_fast_ingress_snapshot();
            for round in 0..5 {
                let started = Instant::now();
                for operation in 0..OPERATIONS {
                    let index = (operation / 2) % peers;
                    let protocol = if operation % 2 == 0 {
                        PacketProtocol::Fmp
                    } else {
                        PacketProtocol::Fsp
                    };
                    let held = shared.then(|| (snapshot.fmp_routes(), snapshot.fsp_routes()));
                    let generation = (round * OPERATIONS.div_ceil(2 * peers)
                        + operation / (2 * peers)) as u64
                        + 2;
                    let (owner, routes) = owner_routes(index, generation, protocol);
                    // Retain all four full-table scans and actual snapshot
                    // updates; only the two production mutation helpers differ.
                    table.unregister_owner(owner);
                    routes.apply_to(&mut table);
                    black_box(&held);
                    drop(held);
                }
                let elapsed_ns = started.elapsed().as_nanos() as u64;
                black_box(&table);
                assert_route_counts(&table, peers);
                if round > 0 {
                    println!(
                        "route_snapshot_benchmark {}",
                        serde_json::json!({
                            "peers": peers, "shared_snapshot": shared, "round": round,
                            "operations": OPERATIONS, "elapsed_ns": elapsed_ns,
                            "fmp_routes": table.fmp.len(), "fsp_routes": table.fsp.len(),
                            "tun_routes": table.tun_outbound.len(), "endpoint_routes": table.endpoint.len(),
                            "fmp_capacity": table.fmp.capacity(), "fsp_capacity": table.fsp.capacity(),
                            "retained_full_table_scans": true
                        })
                    );
                }
            }
        }
    }
}
