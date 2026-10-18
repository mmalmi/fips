use super::*;

#[test]
fn signed_declarations_keep_key_and_message_validation_with_shared_context() {
    let identities = [
        crate::Identity::from_secret_bytes(&[1; 32]).unwrap(),
        crate::Identity::from_secret_bytes(&[2; 32]).unwrap(),
    ];
    for (index, identity) in identities.iter().enumerate() {
        let mut declaration =
            ParentDeclaration::new(*identity.node_addr(), make_node_addr(3), 1, 1000);
        assert!(declaration.verify(&identity.pubkey()).is_err());
        declaration.sign(identity).unwrap();
        assert!(declaration.verify(&identity.pubkey()).is_ok());
        assert!(declaration.verify(&identities[1 - index].pubkey()).is_err());
        let altered = ParentDeclaration::with_signature(
            *identity.node_addr(),
            make_node_addr(3),
            2,
            1000,
            *declaration.signature().unwrap(),
        );
        assert!(altered.verify(&identity.pubkey()).is_err());
    }
}

#[test]
fn test_parent_declaration_new() {
    let node = make_node_addr(1);
    let parent = make_node_addr(2);

    let decl = ParentDeclaration::new(node, parent, 1, 1000);

    assert_eq!(decl.node_addr(), &node);
    assert_eq!(decl.parent_id(), &parent);
    assert_eq!(decl.sequence(), 1);
    assert_eq!(decl.timestamp(), 1000);
    assert!(!decl.is_root());
    assert!(!decl.is_signed());
}

#[test]
fn test_parent_declaration_self_root() {
    let node = make_node_addr(1);

    let decl = ParentDeclaration::self_root(node, 5, 2000);

    assert!(decl.is_root());
    assert_eq!(decl.node_addr(), decl.parent_id());
}

#[test]
fn test_parent_declaration_freshness() {
    let node = make_node_addr(1);
    let parent = make_node_addr(2);

    let old_decl = ParentDeclaration::new(node, parent, 1, 1000);
    let new_decl = ParentDeclaration::new(node, parent, 2, 2000);

    assert!(new_decl.is_fresher_than(&old_decl));
    assert!(!old_decl.is_fresher_than(&new_decl));
    assert!(!old_decl.is_fresher_than(&old_decl));
}

#[test]
fn test_parent_declaration_signing_bytes() {
    let node = make_node_addr(1);
    let parent = make_node_addr(2);

    let decl = ParentDeclaration::new(node, parent, 100, 1234567890);
    let bytes = decl.signing_bytes();

    // Should be 48 bytes: 16 + 16 + 8 + 8
    assert_eq!(bytes.len(), 48);

    // Verify structure
    assert_eq!(&bytes[0..16], node.as_bytes());
    assert_eq!(&bytes[16..32], parent.as_bytes());
    assert_eq!(&bytes[32..40], &100u64.to_le_bytes());
    assert_eq!(&bytes[40..48], &1234567890u64.to_le_bytes());
}

#[test]
fn test_parent_declaration_equality() {
    let node = make_node_addr(1);
    let parent = make_node_addr(2);

    let decl1 = ParentDeclaration::new(node, parent, 1, 1000);
    let decl2 = ParentDeclaration::new(node, parent, 1, 1000);
    let decl3 = ParentDeclaration::new(node, parent, 2, 1000);

    assert_eq!(decl1, decl2);
    assert_ne!(decl1, decl3);
}

// ===== TreeState Tests =====
