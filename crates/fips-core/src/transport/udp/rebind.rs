use super::*;

pub(crate) struct UdpNetworkRebindProbe {
    transport_id: TransportId,
    bind_addr: SocketAddr,
    bind_interface: Option<String>,
    recv_buf_size: usize,
    send_buf_size: usize,
}

impl UdpNetworkRebindProbe {
    pub(crate) async fn prepare(self) -> Result<(), TransportError> {
        for (attempt, retry_delay) in CONFIGURED_SOCKET_REBIND_RETRY_DELAYS
            .iter()
            .copied()
            .enumerate()
        {
            match self.open() {
                Ok(()) => return Ok(()),
                Err(error) => {
                    warn!(
                        transport_id = %self.transport_id,
                        attempt = attempt + 1,
                        retry_delay_ms = retry_delay.as_millis(),
                        bind_interface = self.bind_interface.as_deref(),
                        %error,
                        "UDP network rebind preparation failed; retrying"
                    );
                    tokio::time::sleep(retry_delay).await;
                }
            }
        }
        self.open()
    }

    fn open(&self) -> Result<(), TransportError> {
        UdpRawSocket::open_on_interface(
            self.bind_addr,
            self.recv_buf_size,
            self.send_buf_size,
            self.bind_interface.as_deref(),
        )
        .map(drop)
    }
}

impl UdpTransport {
    pub(crate) fn network_rebind_probe(
        &self,
        bind_interface: Option<String>,
    ) -> Result<Option<UdpNetworkRebindProbe>, TransportError> {
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "ios"))]
        let bind_addr =
            if self.socket_origin == UdpSocketOrigin::Adopted && self.state.is_operational() {
                self.local_addr.ok_or(TransportError::NotStarted)?
            } else if self.socket_origin == UdpSocketOrigin::Configured
                && (self.state.is_operational() || self.state.can_start())
            {
                self.config.bind_addr().parse().map_err(|error| {
                    TransportError::StartFailed(format!("invalid bind address: {error}"))
                })?
            } else {
                return Ok(None);
            };

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "ios")))]
        let bind_addr = if self.socket_origin == UdpSocketOrigin::Configured
            && (self.state.is_operational() || self.state.can_start())
        {
            self.config.bind_addr().parse().map_err(|error| {
                TransportError::StartFailed(format!("invalid bind address: {error}"))
            })?
        } else {
            return Ok(None);
        };

        // A live carrier owns its configured/adopted port, so preparation can
        // only validate the target address and interface on an ephemeral port;
        // the apply path has proven rollback if the real-port bind then races.
        // A stopped/failed configured carrier owns no socket, so probe its
        // actual configured port and wait for that resource to become usable.
        let bind_addr = if self.state.is_operational() {
            SocketAddr::new(bind_addr.ip(), 0)
        } else {
            bind_addr
        };
        Ok(Some(UdpNetworkRebindProbe {
            transport_id: self.transport_id,
            bind_addr,
            bind_interface,
            recv_buf_size: self.config.recv_buf_size(),
            send_buf_size: self.config.send_buf_size(),
        }))
    }
}
