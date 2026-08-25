//! Permission-safe Unix control-socket creation.

use std::path::Path;
use tokio::net::UnixListener;

const SOCKET_DIR_MODE: u32 = 0o750;
const BIND_UMASK: libc::mode_t = 0o007;

struct UmaskGuard(libc::mode_t);

impl UmaskGuard {
    fn tighten(mask: libc::mode_t) -> Self {
        // SAFETY: umask(2) cannot fail. The previous mask is restored by Drop.
        Self(unsafe { libc::umask(mask) })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: restores the process mask saved by `tighten`.
        unsafe {
            libc::umask(self.0);
        }
    }
}

/// Create a socket directory and missing ancestors without granting access to
/// other users, even when the process starts with a permissive umask.
pub fn make_parent(parent: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(SOCKET_DIR_MODE)
        .create(parent)
}

/// Bind a Unix listener whose inode is restrictive from its first instant.
pub fn bind(path: &Path) -> Result<UnixListener, std::io::Error> {
    let _umask = UmaskGuard::tighten(BIND_UMASK);
    UnixListener::bind(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Mutex;

    static UMASK_LOCK: Mutex<()> = Mutex::new(());

    fn lock_umask() -> std::sync::MutexGuard<'static, ()> {
        UMASK_LOCK.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn current_umask() -> libc::mode_t {
        // SAFETY: the observed mask is restored immediately.
        unsafe {
            let old = libc::umask(0o022);
            libc::umask(old);
            old
        }
    }

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
    }

    #[tokio::test]
    async fn socket_is_never_created_with_other_access() {
        let _lock = lock_umask();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let restore = UmaskGuard::tighten(0);
        let listener = bind(&path).unwrap();
        drop(restore);

        assert_eq!(mode(&path) & 0o007, 0);
        drop(listener);
    }

    #[tokio::test]
    async fn socket_bind_restores_the_callers_umask() {
        let _lock = lock_umask();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("control.sock");
        let restore = UmaskGuard::tighten(0o022);
        let listener = bind(&path).unwrap();
        let after = current_umask();
        drop(restore);

        assert_eq!(after, 0o022);
        drop(listener);
    }

    #[test]
    fn socket_parent_and_missing_ancestors_exclude_other_users() {
        let _lock = lock_umask();
        let dir = tempfile::tempdir().unwrap();
        let intermediate = dir.path().join("run");
        let parent = intermediate.join("fips");
        let restore = UmaskGuard::tighten(0);
        make_parent(&parent).unwrap();
        drop(restore);

        assert_eq!(mode(&intermediate) & 0o007, 0);
        assert_eq!(mode(&parent) & 0o007, 0);
    }
}
