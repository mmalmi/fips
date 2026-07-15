#[cfg(windows)]
mod platform {
    use super::*;

    fn set_windows_exclusive_addr_use(sock: &Socket) -> Result<(), TransportError> {
        use std::os::windows::io::AsRawSocket;
        use windows_sys::Win32::Networking::WinSock::{
            SO_EXCLUSIVEADDRUSE, SOL_SOCKET, SOCKET, setsockopt,
        };

        let enabled: i32 = 1;
        let result = unsafe {
            setsockopt(
                sock.as_raw_socket() as SOCKET,
                SOL_SOCKET,
                SO_EXCLUSIVEADDRUSE,
                (&enabled as *const i32).cast(),
                std::mem::size_of::<i32>() as i32,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(TransportError::StartFailed(format!(
                "set SO_EXCLUSIVEADDRUSE failed: {}",
                std::io::Error::last_os_error()
            )))
        }
    }

    const UDP_CONTROL_SEND_TIMEOUT: std::time::Duration =
        std::time::Duration::from_millis(100);

    /// UDP socket wrapper (Windows).
    ///
    /// Uses `socket2::Socket` for configuration and `tokio::net::UdpSocket`
    /// for async I/O. Kernel drop counting is not available on Windows;
    /// the drops field always returns 0.
    pub struct UdpRawSocket {
        inner: Socket,
        local_addr: SocketAddr,
    }

    impl UdpRawSocket {
        /// Create, bind, and configure a UDP socket.
        ///
        /// Sets non-blocking mode and configures buffer sizes. The socket
        /// is bound immediately so `local_addr()` returns the actual
        /// assigned address (important when binding to port 0).
        pub fn open(
            bind_addr: SocketAddr,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            Self::open_inner(bind_addr, recv_buf_size, send_buf_size, false)
        }

        /// Create an exclusive UDP socket for same-host rendezvous ownership.
        pub fn open_exclusive(
            bind_addr: SocketAddr,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            Self::open_inner(bind_addr, recv_buf_size, send_buf_size, true)
        }

        fn open_inner(
            bind_addr: SocketAddr,
            recv_buf_size: usize,
            send_buf_size: usize,
            exclusive: bool,
        ) -> Result<Self, TransportError> {
            let domain = if bind_addr.is_ipv4() {
                Domain::IPV4
            } else {
                Domain::IPV6
            };
            let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))
                .map_err(|e| TransportError::StartFailed(format!("socket create failed: {}", e)))?;

            sock.set_nonblocking(true).map_err(|e| {
                TransportError::StartFailed(format!("set nonblocking failed: {}", e))
            })?;

            if exclusive {
                set_windows_exclusive_addr_use(&sock)?;
            } else {
                // Windows: `socket2::Socket::set_reuse_port` doesn't exist.
                let _ = sock.set_reuse_address(true);
            }

            sock.bind(&bind_addr.into()).map_err(|error| {
                if exclusive {
                    TransportError::exclusive_bind_failed(bind_addr, error)
                } else {
                    TransportError::bind_failed(bind_addr, error)
                }
            })?;

            // Set socket buffer sizes
            sock.set_recv_buffer_size(recv_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
            sock.set_send_buffer_size(send_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

            let local_addr = sock
                .local_addr()
                .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?
                .as_socket()
                .ok_or_else(|| {
                    TransportError::StartFailed("local address is not an IP socket".into())
                })?;

            Ok(Self {
                inner: sock,
                local_addr,
            })
        }

        /// Adopt an existing bound UDP socket.
        pub fn adopt(
            socket: std::net::UdpSocket,
            recv_buf_size: usize,
            send_buf_size: usize,
        ) -> Result<Self, TransportError> {
            let sock = Socket::from(socket);

            sock.set_nonblocking(true).map_err(|e| {
                TransportError::StartFailed(format!("set nonblocking failed: {}", e))
            })?;

            sock.set_recv_buffer_size(recv_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set recv buffer: {}", e)))?;
            sock.set_send_buffer_size(send_buf_size)
                .map_err(|e| TransportError::StartFailed(format!("set send buffer: {}", e)))?;

            let local_addr = sock
                .local_addr()
                .map_err(|e| TransportError::StartFailed(format!("get local addr: {}", e)))?
                .as_socket()
                .ok_or_else(|| {
                    TransportError::StartFailed("local address is not an IP socket".into())
                })?;

            Ok(Self {
                inner: sock,
                local_addr,
            })
        }

        /// Get the local bound address.
        pub fn local_addr(&self) -> SocketAddr {
            self.local_addr
        }

        /// Get the actual receive buffer size.
        pub fn recv_buffer_size(&self) -> Result<usize, TransportError> {
            self.inner
                .recv_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get recv buffer: {}", e)))
        }

        /// Get the actual send buffer size.
        pub fn send_buffer_size(&self) -> Result<usize, TransportError> {
            self.inner
                .send_buffer_size()
                .map_err(|e| TransportError::StartFailed(format!("get send buffer: {}", e)))
        }

        /// Wrap this socket in an async wrapper for tokio I/O.
        pub fn into_async(self) -> Result<AsyncUdpSocket, TransportError> {
            let std_socket: std::net::UdpSocket = self.inner.into();
            let tokio_socket = tokio::net::UdpSocket::from_std(std_socket)
                .map_err(|e| TransportError::StartFailed(format!("tokio socket failed: {}", e)))?;

            Ok(AsyncUdpSocket {
                inner: Arc::new(tokio_socket),
            })
        }
    }

    /// Async UDP socket wrapper (Windows).
    ///
    /// Uses `tokio::net::UdpSocket` directly. Kernel drop counting
    /// is not available; the drops field always returns 0.
    #[derive(Clone)]
    pub struct AsyncUdpSocket {
        inner: Arc<tokio::net::UdpSocket>,
    }

    impl AsyncUdpSocket {
        /// Send a payload to a destination address.
        pub async fn send_to(
            &self,
            data: &[u8],
            dest: &SocketAddr,
        ) -> Result<usize, TransportError> {
            match tokio::time::timeout(UDP_CONTROL_SEND_TIMEOUT, self.inner.send_to(data, dest))
                .await
            {
                Ok(result) => {
                    result.map_err(|e| TransportError::SendFailed(format!("{}", e)))
                }
                Err(_) => Err(TransportError::Timeout),
            }
        }

        /// Receive a payload, source address, kernel drop counter, and
        /// Linux UDP_GRO segment size.
        ///
        /// Returns `(bytes_read, source_addr, 0, 0)`. The drops and GRO fields
        /// are always 0 on Windows since kernel receive ancillary metadata is
        /// not available here.
        pub async fn recv_from(
            &self,
            buf: &mut [u8],
        ) -> Result<(usize, SocketAddr, u32, usize), TransportError> {
            let (n, addr) = self
                .inner
                .recv_from(buf)
                .await
                .map_err(|e| TransportError::RecvFailed(format!("{}", e)))?;
            Ok((n, addr, 0, 0))
        }
    }
}

pub use platform::{AsyncUdpSocket, UdpRawSocket};

#[cfg(test)]
#[path = "socket/tests.rs"]
mod tests;
