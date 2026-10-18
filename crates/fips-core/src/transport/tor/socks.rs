async fn connect_socks(
    host_network: Option<&dyn crate::host_network::HostNetwork>,
    proxy_addr: &str,
    target: &TorAddr,
    isolation_key: &str,
) -> Result<Socks5Stream<TcpStream>, tokio_socks::Error> {
    let socket = crate::host_network::connect_tcp_host(host_network, proxy_addr).await?;
    match target {
        TorAddr::Onion(host, port) | TorAddr::ClearnetHostname(host, port) => {
            Socks5Stream::connect_with_password_and_socket(
                socket,
                (host.as_str(), *port),
                "fips",
                isolation_key,
            )
            .await
        }
        TorAddr::Clearnet(address) => {
            Socks5Stream::connect_with_password_and_socket(socket, *address, "fips", isolation_key)
                .await
        }
    }
}
