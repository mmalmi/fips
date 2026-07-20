use crate::{RecentPeers, RecentPeersError};
use std::error::Error;
use std::ffi::OsString;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// A caller-scoped native file store for recently authenticated FIPS peers.
///
/// This type only handles persistence. The caller chooses the path and remains
/// responsible for cache pruning, peer authorization, and deciding when to
/// load or save the cache.
#[derive(Debug, Clone)]
pub struct RecentPeersFileStore {
    path: PathBuf,
    expected_local_npub: String,
    expected_scope: String,
}

impl RecentPeersFileStore {
    /// Bind a file path to one local identity and application scope.
    pub fn new(
        path: impl Into<PathBuf>,
        expected_local_npub: impl Into<String>,
        expected_scope: impl Into<String>,
    ) -> Result<Self, RecentPeersFileError> {
        let path = path.into();
        let expected = RecentPeers::new(expected_local_npub, expected_scope).map_err(|source| {
            RecentPeersFileError::Model {
                operation: "initialize",
                path: path.clone(),
                source,
            }
        })?;

        Ok(Self {
            path,
            expected_local_npub: expected.local_npub,
            expected_scope: expected.scope,
        })
    }

    /// Path supplied by the caller for this store.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Local identity to which loaded and saved documents must be bound.
    pub fn local_npub(&self) -> &str {
        &self.expected_local_npub
    }

    /// Application scope to which loaded and saved documents must be bound.
    pub fn scope(&self) -> &str {
        &self.expected_scope
    }

    /// Load and strictly validate the cache.
    ///
    /// A missing file produces a new empty cache for the expected identity and
    /// scope. Malformed or mismatched existing files are returned as errors.
    pub fn load(&self) -> Result<RecentPeers, RecentPeersFileError> {
        let json = match fs::read_to_string(&self.path) {
            Ok(json) => json,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                return RecentPeers::new(
                    self.expected_local_npub.clone(),
                    self.expected_scope.clone(),
                )
                .map_err(|source| RecentPeersFileError::Model {
                    operation: "create missing cache",
                    path: self.path.clone(),
                    source,
                });
            }
            Err(source) => {
                return Err(RecentPeersFileError::Io {
                    operation: "read",
                    path: self.path.clone(),
                    source,
                });
            }
        };

        RecentPeers::from_json(&json, &self.expected_local_npub, &self.expected_scope).map_err(
            |source| RecentPeersFileError::Model {
                operation: "decode",
                path: self.path.clone(),
                source,
            },
        )
    }

    /// Strictly validate and replace the cache using a same-directory
    /// temporary file.
    pub fn save(&self, recent_peers: &RecentPeers) -> Result<(), RecentPeersFileError> {
        let json = recent_peers
            .to_json_pretty()
            .map_err(|source| RecentPeersFileError::Model {
                operation: "encode",
                path: self.path.clone(),
                source,
            })?;

        // Validate the store binding as well as the document itself. This
        // prevents accidentally writing another identity or app scope through
        // a store that points at this cache file.
        RecentPeers::from_json(&json, &self.expected_local_npub, &self.expected_scope).map_err(
            |source| RecentPeersFileError::Model {
                operation: "validate store binding",
                path: self.path.clone(),
                source,
            },
        )?;

        let parent = self
            .path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).map_err(|source| RecentPeersFileError::Io {
            operation: "create parent directory",
            path: parent.to_path_buf(),
            source,
        })?;

        let (temp_path, mut temp_file) =
            create_temp_file(parent, &self.path).map_err(|source| RecentPeersFileError::Io {
                operation: "create temporary file",
                path: self.path.clone(),
                source,
            })?;
        let mut cleanup = TempPath::new(temp_path.clone());

        set_private_permissions(&temp_file).map_err(|source| RecentPeersFileError::Io {
            operation: "set temporary file permissions",
            path: temp_path.clone(),
            source,
        })?;
        temp_file
            .write_all(json.as_bytes())
            .and_then(|()| temp_file.write_all(b"\n"))
            .map_err(|source| RecentPeersFileError::Io {
                operation: "write temporary file",
                path: temp_path.clone(),
                source,
            })?;
        temp_file
            .sync_all()
            .map_err(|source| RecentPeersFileError::Io {
                operation: "sync temporary file",
                path: temp_path.clone(),
                source,
            })?;
        drop(temp_file);

        replace_file(&temp_path, &self.path).map_err(|source| RecentPeersFileError::Io {
            operation: "replace cache file",
            path: self.path.clone(),
            source,
        })?;
        cleanup.keep();
        Ok(())
    }
}

/// Error loading or saving a [`RecentPeers`] file.
#[derive(Debug)]
pub enum RecentPeersFileError {
    /// Filesystem operation failed.
    Io {
        operation: &'static str,
        path: PathBuf,
        source: io::Error,
    },
    /// The document or expected identity/scope failed model validation.
    Model {
        operation: &'static str,
        path: PathBuf,
        source: RecentPeersError,
    },
}

impl fmt::Display for RecentPeersFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} recent-peers file '{}': {source}",
                path.display()
            ),
            Self::Model {
                operation,
                path,
                source,
            } => write!(
                formatter,
                "failed to {operation} recent-peers file '{}': {source}",
                path.display()
            ),
        }
    }
}

impl Error for RecentPeersFileError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Model { source, .. } => Some(source),
        }
    }
}

fn create_temp_file(parent: &Path, target: &Path) -> io::Result<(PathBuf, File)> {
    let target_name = target.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "recent-peers path must name a file",
        )
    })?;

    for _ in 0..32 {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let mut temp_name = OsString::from(".");
        temp_name.push(target_name);
        temp_name.push(format!(".{}.{}.tmp", std::process::id(), sequence));
        let temp_path = parent.join(temp_name);

        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(source) => return Err(source),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not allocate a unique same-directory temporary file",
    ))
}

#[cfg(unix)]
fn set_private_permissions(file: &File) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn set_private_permissions(_file: &File) -> io::Result<()> {
    Ok(())
}

#[cfg(not(windows))]
fn replace_file(temp_path: &Path, target_path: &Path) -> io::Result<()> {
    fs::rename(temp_path, target_path)
}

#[cfg(windows)]
fn replace_file(temp_path: &Path, target_path: &Path) -> io::Result<()> {
    if target_path.try_exists()? {
        fs::remove_file(target_path)?;
    }
    fs::rename(temp_path, target_path)
}

struct TempPath {
    path: PathBuf,
    keep: bool,
}

impl TempPath {
    fn new(path: PathBuf) -> Self {
        Self { path, keep: false }
    }

    fn keep(&mut self) {
        self.keep = true;
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Identity, RecentPeer, RecentPeerEndpoint, RecentPeerTransport};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_DIR_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn missing_file_returns_empty_cache_for_expected_context() {
        let scratch = ScratchDir::new();
        let path = scratch.path().join("nested/recent-peers.json");
        let local_npub = Identity::generate().npub();
        let store = RecentPeersFileStore::new(&path, &local_npub, "iris-drive").unwrap();

        let loaded = store.load().unwrap();

        assert_eq!(loaded.local_npub(), local_npub);
        assert_eq!(loaded.scope(), "iris-drive");
        assert!(loaded.peers.is_empty());
        assert!(!path.exists());
    }

    #[test]
    fn round_trip_creates_parent_and_replaces_file() {
        let scratch = ScratchDir::new();
        let path = scratch.path().join("nested/recent-peers.json");
        let local_npub = Identity::generate().npub();
        let remote_npub = Identity::generate().npub();
        let store = RecentPeersFileStore::new(&path, &local_npub, "nostr-vpn").unwrap();
        let mut expected = RecentPeers::new(&local_npub, "nostr-vpn").unwrap();
        expected.peers.insert(
            remote_npub,
            RecentPeer {
                last_authenticated_at_ms: 123,
                endpoints: vec![RecentPeerEndpoint {
                    transport: RecentPeerTransport::Udp,
                    addr: "198.51.100.42:2121".to_string(),
                    last_authenticated_at_ms: 123,
                }],
            },
        );

        store.save(&expected).unwrap();
        assert_eq!(store.load().unwrap(), expected);
        assert!(path.parent().unwrap().is_dir());

        expected
            .peers
            .values_mut()
            .next()
            .unwrap()
            .last_authenticated_at_ms = 456;
        store.save(&expected).unwrap();
        assert_eq!(store.load().unwrap(), expected);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn load_rejects_wrong_scope() {
        let scratch = ScratchDir::new();
        let path = scratch.path().join("recent-peers.json");
        let local_npub = Identity::generate().npub();
        let original = RecentPeersFileStore::new(&path, &local_npub, "iris-chat").unwrap();
        original
            .save(&RecentPeers::new(&local_npub, "iris-chat").unwrap())
            .unwrap();
        let wrong_scope = RecentPeersFileStore::new(&path, &local_npub, "iris-drive").unwrap();

        let error = wrong_scope.load().unwrap_err();

        assert!(matches!(
            error,
            RecentPeersFileError::Model {
                source: RecentPeersError::ScopeMismatch { .. },
                ..
            }
        ));
    }

    struct ScratchDir {
        path: PathBuf,
    }

    impl ScratchDir {
        fn new() -> Self {
            let sequence = TEST_DIR_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock should be after the Unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "fips-endpoint-recent-peers-{}-{timestamp}-{sequence}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for ScratchDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
