use socket2::Socket;
use std::io;
use std::net::SocketAddr;

#[cfg(any(target_os = "macos", target_os = "ios"))]
pub(crate) fn bind_socket_to_interface(
    socket: &Socket,
    bind_addr: SocketAddr,
    interface: Option<&str>,
) -> io::Result<()> {
    use std::ffi::CString;
    use std::num::NonZeroU32;

    let Some(interface) = interface else {
        return Ok(());
    };
    let interface = CString::new(interface).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "interface contains a NUL byte")
    })?;
    let index = unsafe { libc::if_nametoindex(interface.as_ptr()) };
    let Some(index) = NonZeroU32::new(index) else {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("interface {:?} does not exist", interface.to_string_lossy()),
        ));
    };
    if bind_addr.is_ipv4() {
        socket.bind_device_by_index_v4(Some(index))
    } else {
        socket.bind_device_by_index_v6(Some(index))
    }
}

#[cfg(any(target_os = "android", target_os = "linux"))]
pub(crate) fn bind_socket_to_interface(
    socket: &Socket,
    _bind_addr: SocketAddr,
    interface: Option<&str>,
) -> io::Result<()> {
    match interface {
        None => Ok(()),
        Some(interface) => socket
            .bind_device(Some(interface.as_bytes()))
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("bind to interface {interface:?}: {error}"),
                )
            }),
    }
}
