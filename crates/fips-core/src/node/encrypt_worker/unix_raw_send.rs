/// Direct `sendto(2)` for non-Linux unix (macOS / BSD). Windows
/// doesn't reach this — encrypt_worker is gated to `unix` in
/// `lifecycle.rs` (the per-worker raw-fd send loop only applies on
/// unix; on Windows the rx_loop fallback path takes outbound packets
/// through tokio's `AsyncUdpSocket::send_to`).
#[cfg(all(unix, not(target_os = "linux")))]
fn send_connected_raw(fd: std::os::unix::io::RawFd, data: &[u8]) -> std::io::Result<usize> {
    let r = unsafe { libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), 0) };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}

#[cfg(all(unix, not(target_os = "linux")))]
fn send_one_raw(
    fd: std::os::unix::io::RawFd,
    data: &[u8],
    dest: &SocketAddr,
) -> std::io::Result<usize> {
    let sa: socket2::SockAddr = (*dest).into();
    let r = unsafe {
        libc::sendto(
            fd,
            data.as_ptr() as *const libc::c_void,
            data.len(),
            0,
            sa.as_ptr() as *const libc::sockaddr,
            sa.len(),
        )
    };
    if r < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(r as usize)
    }
}
