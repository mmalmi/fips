use super::*;

#[test]
fn test_key_file_write_read_roundtrip() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");

    let identity = crate::Identity::generate();
    let nsec = crate::encode_nsec(&identity.keypair().secret_key());

    write_key_file(&key_path, &nsec).unwrap();

    let loaded_nsec = read_key_file(&key_path).unwrap();
    assert_eq!(loaded_nsec, nsec);

    // Verify the loaded nsec produces the same identity
    let loaded_identity = crate::Identity::from_secret_str(&loaded_nsec).unwrap();
    assert_eq!(loaded_identity.npub(), identity.npub());
}

#[cfg(unix)]
#[test]
fn test_key_file_permissions() {
    use std::os::unix::fs::MetadataExt;

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");

    write_key_file(&key_path, "nsec1test").unwrap();

    let metadata = fs::metadata(&key_path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
}

#[cfg(unix)]
#[test]
fn test_key_file_permissions_are_tightened_on_overwrite() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");
    fs::write(&key_path, "old\n").unwrap();
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644)).unwrap();

    write_key_file(&key_path, "nsec1test").unwrap();

    let metadata = fs::metadata(&key_path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(read_key_file(&key_path).unwrap(), "nsec1test");
}

#[cfg(unix)]
#[test]
fn test_pub_file_permissions() {
    use std::os::unix::fs::MetadataExt;

    let temp_dir = TempDir::new().unwrap();
    let pub_path = temp_dir.path().join("fips.pub");

    write_pub_file(&pub_path, "npub1test").unwrap();

    let metadata = fs::metadata(&pub_path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o644);
}

#[cfg(unix)]
#[test]
fn test_write_key_file_refuses_symlink() {
    let temp_dir = TempDir::new().unwrap();
    let victim = temp_dir.path().join("victim");
    let key_path = temp_dir.path().join("fips.key");
    fs::write(&victim, "victim contents\n").unwrap();
    std::os::unix::fs::symlink(&victim, &key_path).unwrap();

    let error = write_key_file(&key_path, "nsec1secret").unwrap_err();
    assert!(matches!(error, ConfigError::KeyPathIsSymlink { .. }));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "victim contents\n");
}

#[cfg(unix)]
#[test]
fn test_write_pub_file_refuses_symlink() {
    let temp_dir = TempDir::new().unwrap();
    let victim = temp_dir.path().join("victim");
    let pub_path = temp_dir.path().join("fips.pub");
    fs::write(&victim, "victim contents\n").unwrap();
    std::os::unix::fs::symlink(&victim, &pub_path).unwrap();

    let error = write_pub_file(&pub_path, "npub1public").unwrap_err();
    assert!(matches!(error, ConfigError::KeyPathIsSymlink { .. }));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "victim contents\n");
}

#[test]
fn test_key_file_empty_error() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");

    fs::write(&key_path, "").unwrap();

    let result = read_key_file(&key_path);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("empty"));
}

#[test]
fn test_key_file_whitespace_trimmed() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");

    fs::write(&key_path, "  nsec1test  \n").unwrap();

    let nsec = read_key_file(&key_path).unwrap();
    assert_eq!(nsec, "nsec1test");
}

#[test]
fn test_key_file_path_derivation() {
    let config_path = PathBuf::from("/etc/fips/fips.yaml");
    assert_eq!(
        key_file_path(&config_path),
        PathBuf::from("/etc/fips/fips.key")
    );
    assert_eq!(
        pub_file_path(&config_path),
        PathBuf::from("/etc/fips/fips.pub")
    );
}

#[cfg(windows)]
#[test]
fn test_key_file_write_read_roundtrip_windows() {
    let temp_dir = TempDir::new().unwrap();
    let key_path = temp_dir.path().join("fips.key");

    let identity = crate::Identity::generate();
    let nsec = crate::encode_nsec(&identity.keypair().secret_key());

    write_key_file(&key_path, &nsec).unwrap();

    // Verify file was created and can be read back
    let loaded_nsec = read_key_file(&key_path).unwrap();
    assert_eq!(loaded_nsec, nsec);

    // Verify the loaded nsec produces the same identity
    let loaded_identity = crate::Identity::from_secret_str(&loaded_nsec).unwrap();
    assert_eq!(loaded_identity.npub(), identity.npub());
}

#[test]
fn test_resolve_identity_from_config() {
    let mut config = Config::new();
    config.node.identity.nsec =
        Some("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20".to_string());

    let resolved = resolve_identity(&config, &[]).unwrap();
    assert!(matches!(resolved.source, IdentitySource::Config));
}

#[test]
fn test_resolve_identity_ephemeral_by_default() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("fips.yaml");

    fs::write(&config_path, "node:\n  identity: {}\n").unwrap();

    let config = Config::load_file(&config_path).unwrap();
    assert!(!config.node.identity.persistent);

    let resolved = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
    assert!(matches!(resolved.source, IdentitySource::Ephemeral));

    // Only the public identity belongs on disk in ephemeral mode.
    let key_path = temp_dir.path().join("fips.key");
    let pub_path = temp_dir.path().join("fips.pub");
    assert!(!key_path.exists());
    assert!(pub_path.exists());
    let identity = crate::Identity::from_secret_str(&resolved.nsec).unwrap();
    assert_eq!(read_key_file(&pub_path).unwrap(), identity.npub());
}

#[test]
fn test_resolve_identity_ephemeral_preserves_saved_key() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("fips.yaml");
    let key_path = dir.path().join("fips.key");
    let saved = crate::Identity::generate();
    let saved_nsec = crate::encode_nsec(&saved.keypair().secret_key());
    write_key_file(&key_path, &saved_nsec).unwrap();
    let original = fs::read(&key_path).unwrap();

    let mut config = Config::new();
    let ephemeral = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
    assert!(matches!(ephemeral.source, IdentitySource::Ephemeral));
    assert_ne!(ephemeral.nsec, saved_nsec);
    assert_eq!(fs::read(&key_path).unwrap(), original);

    config.node.identity.persistent = true;
    let restored = resolve_identity(&config, &[config_path]).unwrap();
    assert!(matches!(restored.source, IdentitySource::KeyFile(_)));
    assert_eq!(restored.nsec, saved_nsec);
    assert_eq!(
        read_key_file(&dir.path().join("fips.pub")).unwrap(),
        saved.npub()
    );
}

#[test]
fn test_resolve_identity_persistent_rejects_uninspectable_path() {
    let dir = TempDir::new().unwrap();
    let blocked_parent = dir.path().join("not-a-directory");
    fs::write(&blocked_parent, "keep this file").unwrap();
    let mut config = Config::new();
    config.node.identity.persistent = true;

    assert!(resolve_identity(&config, &[blocked_parent.join("fips.yaml")]).is_err());
    assert_eq!(
        fs::read_to_string(blocked_parent).unwrap(),
        "keep this file"
    );
}

#[test]
fn test_resolve_identity_persistent_creates_missing_directory() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("new").join("nested").join("fips.yaml");
    let mut config = Config::new();
    config.node.identity.persistent = true;

    let generated = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
    assert!(matches!(generated.source, IdentitySource::Generated(_)));
    let restored = resolve_identity(&config, &[config_path]).unwrap();
    assert!(matches!(restored.source, IdentitySource::KeyFile(_)));
    assert_eq!(generated.nsec, restored.nsec);
}

#[test]
#[cfg(unix)]
fn test_resolve_identity_preserves_dangling_key_symlink() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("fips.yaml");
    let key_path = dir.path().join("fips.key");
    let target = dir.path().join("missing-key");
    std::os::unix::fs::symlink(&target, &key_path).unwrap();
    let mut config = Config::new();

    let resolved = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
    assert!(matches!(resolved.source, IdentitySource::Ephemeral));
    assert_eq!(fs::read_link(&key_path).unwrap(), target);
    assert!(!target.exists());

    config.node.identity.persistent = true;
    assert!(resolve_identity(&config, &[config_path]).is_err());
    assert_eq!(fs::read_link(&key_path).unwrap(), target);
    assert!(!target.exists());
}

#[test]
fn test_resolve_identity_ephemeral_changes_each_call() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("fips.yaml");

    fs::write(&config_path, "node:\n  identity: {}\n").unwrap();

    let config = Config::load_file(&config_path).unwrap();
    let first = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
    let second = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();

    // Each call generates a different key
    assert_ne!(first.nsec, second.nsec);
}

#[test]
fn test_resolve_identity_persistent_from_key_file() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("fips.yaml");
    let key_path = temp_dir.path().join("fips.key");

    fs::write(&config_path, "node:\n  identity:\n    persistent: true\n").unwrap();

    // Write a key file
    let identity = crate::Identity::generate();
    let nsec = crate::encode_nsec(&identity.keypair().secret_key());
    write_key_file(&key_path, &nsec).unwrap();

    let config = Config::load_file(&config_path).unwrap();
    assert!(config.node.identity.persistent);

    let resolved = resolve_identity(&config, &[config_path]).unwrap();
    assert!(matches!(resolved.source, IdentitySource::KeyFile(_)));
    assert_eq!(resolved.nsec, nsec);
}

#[test]
fn test_resolve_identity_persistent_generates_and_persists() {
    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("fips.yaml");

    fs::write(&config_path, "node:\n  identity:\n    persistent: true\n").unwrap();

    let config = Config::load_file(&config_path).unwrap();
    let resolved = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();

    assert!(matches!(resolved.source, IdentitySource::Generated(_)));

    // Key file and pub file should now exist
    let key_path = temp_dir.path().join("fips.key");
    let pub_path = temp_dir.path().join("fips.pub");
    assert!(key_path.exists());
    assert!(pub_path.exists());

    // Second resolve should load from key file (not generate new)
    let resolved2 = resolve_identity(&config, std::slice::from_ref(&config_path)).unwrap();
    assert!(matches!(resolved2.source, IdentitySource::KeyFile(_)));
    assert_eq!(resolved.nsec, resolved2.nsec);
}
