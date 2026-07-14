#[test]
fn fips_core_does_not_depend_on_nostr_pubsub() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest
            .lines()
            .any(|line| line.trim_start().starts_with("nostr-pubsub =")),
        "pubsub adapters belong above fips-core"
    );
}
