use fips_core::NostrRelayAdapter;

#[test]
fn relay_adapter_is_a_public_sendable_embedding_handle() {
    fn assert_send<T: Send>() {}

    assert_send::<NostrRelayAdapter>();
    let _ = NostrRelayAdapter::start;
    let _ = NostrRelayAdapter::start_for_node;
}
