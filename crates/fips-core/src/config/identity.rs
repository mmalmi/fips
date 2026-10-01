use super::{
    Config, ConfigError, key_file_path, pub_file_path, read_key_file, warn_unmanaged_key_file,
    write_key_file, write_pub_file,
};
use crate::Identity;
use std::path::PathBuf;
use zeroize::Zeroizing;

/// Resolve identity from config and key file.
///
/// Behavior depends on `node.identity.persistent`:
///
/// - **`persistent: false`** (default): generate a fresh ephemeral keypair
///   every start. Only `fips.pub` is written for operator visibility. Any saved
///   private key is left untouched and is not used.
///
/// - **`persistent: true`**: use three-tier resolution:
///   1. Explicit nsec in config — highest priority
///   2. Persistent key file (`fips.key`) — reused across restarts
///   3. Generate new — creates keypair, writes `fips.key` and `fips.pub`
///
/// - **`nsec` set explicitly**: always uses that, regardless of `persistent`.
///
/// Returns the nsec string (bech32 or hex) to be used for identity creation.
pub fn resolve_identity(
    config: &Config,
    loaded_paths: &[PathBuf],
) -> Result<ResolvedIdentity, ConfigError> {
    use crate::encode_nsec;

    // Explicit nsec in config always wins
    if let Some(nsec) = &config.node.identity.nsec {
        return Ok(ResolvedIdentity {
            nsec: nsec.clone(),
            source: IdentitySource::Config,
        });
    }

    // Determine key file directory from loaded config paths
    let config_ref = if let Some(path) = loaded_paths.last() {
        path.clone()
    } else {
        Config::search_paths()
            .first()
            .cloned()
            .unwrap_or_else(|| PathBuf::from("./fips.yaml"))
    };
    let key_path = key_file_path(&config_ref);
    let pub_path = pub_file_path(&config_ref);

    if config.node.identity.persistent {
        // Persistent mode: load existing key file or generate-and-persist
        let key_present = match key_path.symlink_metadata() {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(source) => {
                return Err(ConfigError::KeyPathUnreadable {
                    path: key_path,
                    source,
                });
            }
        };
        if key_present {
            let nsec = Zeroizing::new(read_key_file(&key_path)?);
            let identity = Identity::from_secret_str(&nsec)?;
            warn_unmanaged_key_file(&key_path);
            if let Err(error) = write_pub_file(&pub_path, &identity.npub()) {
                tracing::warn!(path = %pub_path.display(), %error, "Failed to write public identity file");
            }
            return Ok(ResolvedIdentity {
                nsec: nsec.to_string(),
                source: IdentitySource::KeyFile(key_path),
            });
        }

        // Windows can report NotFound when an ancestor is a file. Confirm the
        // directory is usable before treating a missing key as a new identity.
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ConfigError::WriteKeyFile {
                path: key_path.clone(),
                source,
            })?;
        }

        // No key file yet — generate and persist
        let identity = Identity::generate();
        let mut our_keypair = identity.keypair();
        let mut secret_key = our_keypair.secret_key();
        let nsec = Zeroizing::new(encode_nsec(&secret_key));
        secret_key.non_secure_erase();
        our_keypair.non_secure_erase();
        let npub = identity.npub();

        match write_key_file(&key_path, &nsec) {
            Ok(()) => {
                if let Err(error) = write_pub_file(&pub_path, &npub) {
                    tracing::warn!(path = %pub_path.display(), %error, "Failed to write public identity file");
                }
                Ok(ResolvedIdentity {
                    nsec: nsec.to_string(),
                    source: IdentitySource::Generated(key_path),
                })
            }
            Err(error) => {
                tracing::warn!(
                    path = %key_path.display(),
                    %error,
                    "Failed to persist generated identity; the npub will change on restart"
                );
                Ok(ResolvedIdentity {
                    nsec: nsec.to_string(),
                    source: IdentitySource::Ephemeral,
                })
            }
        }
    } else {
        // Ephemeral mode keeps the private key in memory. Publish only the npub.
        let identity = Identity::generate();
        let mut our_keypair = identity.keypair();
        let mut secret_key = our_keypair.secret_key();
        let nsec = Zeroizing::new(encode_nsec(&secret_key));
        secret_key.non_secure_erase();
        our_keypair.non_secure_erase();
        let npub = identity.npub();

        if let Some(parent) = key_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        if key_path.symlink_metadata().is_ok() {
            tracing::warn!(
                path = %key_path.display(),
                config_key = "node.identity.persistent",
                "Saved identity key is not used in ephemeral mode; set node.identity.persistent: true to use it"
            );
        }
        if let Err(error) = write_pub_file(&pub_path, &npub) {
            tracing::warn!(path = %pub_path.display(), %error, "Failed to write public identity file");
        }

        Ok(ResolvedIdentity {
            nsec: nsec.to_string(),
            source: IdentitySource::Ephemeral,
        })
    }
}

/// Result of identity resolution.
///
/// The returned `nsec` is caller-owned secret material. Callers should move it
/// into the long-lived identity configuration promptly and clear it before
/// replacing or discarding it.
pub struct ResolvedIdentity {
    /// The nsec string (bech32 or hex) for creating an Identity.
    pub nsec: String,
    /// Where the identity came from.
    pub source: IdentitySource,
}

/// Where a resolved identity originated.
pub enum IdentitySource {
    /// From explicit nsec in config file.
    Config,
    /// Loaded from a persistent key file.
    KeyFile(PathBuf),
    /// Generated and saved to a new key file.
    Generated(PathBuf),
    /// Generated for this run, either by policy or because persistence failed.
    Ephemeral,
}
