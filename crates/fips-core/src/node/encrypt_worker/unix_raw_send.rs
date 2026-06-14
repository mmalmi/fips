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

#[cfg(target_os = "macos")]
fn send_one_with_backpressure(
    fd: std::os::unix::io::RawFd,
    connected: bool,
    dest: &SocketAddr,
    data: &[u8],
    backpressure: &mut SendBackpressurePacer,
    bulk_endpoint_data: bool,
    drop_on_backpressure: bool,
) -> std::io::Result<()> {
    loop {
        let result = if connected {
            send_connected_raw(fd, data)
        } else {
            send_one_raw(fd, data, dest)
        };
        match result {
            Ok(_) => {
                backpressure.record_success();
                record_udp_send_path(connected, 1);
                return Ok(());
            }
            Err(err) if is_send_backpressure(&err) => {
                match send_backpressure_decision_for_lane(
                    backpressure.pause(&err),
                    drop_on_backpressure,
                    bulk_endpoint_data,
                ) {
                    SendBackpressureDecision::DropCurrentBulk => {
                        record_udp_send_backpressure_drop(&err);
                        return Err(err);
                    }
                    SendBackpressureDecision::Retry => {}
                }
            }
            Err(err) => return Err(err),
        }
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
