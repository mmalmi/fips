#[test]
fn fips_core_does_not_depend_on_nostr_pubsub() {
    let manifest = include_str!("../Cargo.toml");
    let endpoint = include_str!("../src/endpoint.rs");
    assert!(
        !manifest
            .lines()
            .any(|line| line.trim_start().starts_with("nostr-pubsub =")),
        "pubsub adapters belong above fips-core"
    );
    assert!(
        !endpoint.contains("nostr_pubsub"),
        "pubsub-named endpoint adapters belong above fips-core"
    );
}
