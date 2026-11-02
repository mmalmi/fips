//! Permission-safe Unix control-socket creation.

use std::path::Path;
use tokio::net::UnixListener;

const SOCKET_DIR_MODE: u32 = 0o750;
/// Create a socket directory and missing ancestors without granting access to
/// other users, even when the process starts with a permissive umask.
pub fn make_parent(parent: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::DirBuilderExt;

    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(SOCKET_DIR_MODE)
        .create(parent)
}

/// Bind a Unix listener at `path` without changing file creation permissions
/// for threads in the embedding application.
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    use socket2::{Domain, SockAddr, Socket, Type};
    use std::os::fd::AsRawFd;

    let addr = SockAddr::unix(path)?;
    let socket = Socket::new(Domain::UNIX, Type::STREAM, None)?;
    // Linux derives the new filesystem socket's permissions from the socket
    // descriptor's mode, further restricted by the caller's umask.
    // SAFETY: the owned socket descriptor is valid throughout fchmod.
    if unsafe { libc::fchmod(socket.as_raw_fd(), 0o770) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    socket.set_nonblocking(true)?;
    socket.bind(&addr)?;
    socket.listen(1024)?;
    UnixListener::from_std(socket.into())
}

/// Bind a Unix listener without exposing its inode or changing the process
/// umask. On BSD systems the listener's kernel address is its staging name.
/// Clients reach the same socket inode at the requested path.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn bind(path: &Path) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::{PermissionsExt, symlink};

    socket2::SockAddr::unix(path)?;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    // Hard-link publication needs the staging inode on the destination filesystem.
    let mut private_dir = tempfile::Builder::new();
    private_dir
        .prefix(".fips-")
        .permissions(std::fs::Permissions::from_mode(0o700));
    let staging = private_dir.tempdir_in(parent)?;
    let staged = staging.path().join("s");
    let alias;
    let bind_path = if socket2::SockAddr::unix(&staged).is_ok() {
        staged.clone()
    } else {
        // The requested address may fit sun_path even though the extra private
        // directory does not. Bind through a shorter, private directory alias.
        alias = private_dir.tempdir()?;
        symlink(staging.path().canonicalize()?, alias.path().join("d"))?;
        alias.path().join("d/s")
    };
    let listener = UnixListener::bind(bind_path)?;
    let mode = std::fs::symlink_metadata(&staged)?.permissions().mode() & 0o770;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(mode))?;
    // Never replace an existing listener, file or symlink in the destination.
    std::fs::hard_link(&staged, path)?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    fn mode(path: &Path) -> u32 {
        std::fs::symlink_metadata(path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    #[tokio::test]
    async fn a_valid_long_control_path_can_be_published_without_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let mut parent = dir.path().join("p");
        while socket2::SockAddr::unix(parent.join("s")).is_ok() {
            parent = parent.with_file_name(format!(
                "{}x",
                parent.file_name().unwrap().to_string_lossy()
            ));
        }
        let mut name = parent.file_name().unwrap().to_string_lossy().into_owned();
        name.pop();
        parent.set_file_name(name);
        make_parent(&parent).unwrap();
        let path = parent.join("s");
        let _listener = bind(&path).unwrap();
        let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();
        assert!(bind(&path).is_err());
    }

    #[tokio::test]
    async fn concurrent_control_socket_and_wallet_creation_preserve_permissions() {
        const MASK: &str = "FIPS_SOCKPERM_TEST_UMASK";
        let Some(mask) = std::env::var_os(MASK) else {
            // umask belongs to the entire process. Use a child for each mask
            // so these fixtures cannot change permissions in unrelated tests.
            for mask in ["000", "022", "077"] {
                let status = std::process::Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", "utils::sockperm::tests::concurrent_control_socket_and_wallet_creation_preserve_permissions"])
                    .env(MASK, mask)
                    .status().unwrap();
                assert!(status.success());
            }
            return;
        };
        let mask = u32::from_str_radix(mask.to_str().unwrap(), 8).unwrap();
        // SAFETY: this is a dedicated child process, with no other test running.
        unsafe { libc::umask(mask as libc::mode_t) };
        let dir = tempfile::tempdir().unwrap();
        let parent = dir.path().join("run/fips");
        make_parent(&parent).unwrap();
        assert_eq!(mode(parent.parent().unwrap()), SOCKET_DIR_MODE & !mask);
        assert_eq!(mode(&parent), SOCKET_DIR_MODE & !mask);
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                barrier.wait();
                for index in 0..128 {
                    let wallet = parent.join(format!("wallet-{index}"));
                    std::fs::DirBuilder::new()
                        .mode(0o777)
                        .create(&wallet)
                        .unwrap();
                    assert_eq!(mode(&wallet), 0o777 & !mask);
                }
            });
            barrier.wait();
            let path = parent.join("control.sock");
            for _ in 0..32 {
                let listener = bind(&path).unwrap();
                assert_eq!(mode(&path), 0o770 & !mask);
                assert!(bind(&path).is_err());
                let _client = std::os::unix::net::UnixStream::connect(&path).unwrap();
                drop(listener);
                std::fs::remove_file(&path).unwrap();
            }
        });
        // SAFETY: all fixture workers have exited and this process now terminates.
        assert_eq!(unsafe { libc::umask(0o077) } as u32, mask);
    }
}
