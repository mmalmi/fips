use async_trait::async_trait;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use igd_next::{
    aio::{
        tokio::{self as igd_tokio, SearchProvider},
        RequestFuture, RequestProvider,
    },
    PortMappingProtocol, RequestError, SearchError, SearchOptions,
};
use std::{
    io,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, UdpSocket},
    task::JoinHandle,
    time::timeout,
};

#[derive(Clone, Default, Debug)]
struct HostProvider {
    steps: Arc<AtomicUsize>,
    deny: Arc<AtomicUsize>,
}
impl HostProvider {
    fn protect(&self) -> io::Result<()> {
        let step = self.steps.fetch_add(1, Ordering::SeqCst) + 1;
        if self.deny.load(Ordering::SeqCst) == step {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "test host policy",
            ))
        } else {
            Ok(())
        }
    }
    async fn http(
        &self,
        url: &str,
        action: Option<&str>,
        body: &str,
    ) -> Result<Vec<u8>, RequestError> {
        let url = url::Url::parse(url).unwrap();
        let addr = SocketAddr::new(
            url.host_str().unwrap().parse().unwrap(),
            url.port_or_known_default().unwrap(),
        );
        let socket = TcpSocket::new_v4()?;
        self.protect()?;
        let stream = socket.connect(addr).await?;
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream)).await?;
        let task = tokio::spawn(connection);
        let mut request = hyper::Request::builder()
            .uri(url.path())
            .method(if action.is_some() { "POST" } else { "GET" })
            .header("Host", addr.to_string());
        if let Some(action) = action {
            request = request
                .header("SOAPAction", action)
                .header("Content-Type", "text/xml");
        }
        let request = request.body(Full::new(Bytes::copy_from_slice(body.as_bytes())))?;
        let response = sender.send_request(request).await?;
        let result = response.into_body().collect().await?.to_bytes().to_vec();
        drop(sender);
        task.abort();
        let _ = task.await;
        Ok(result)
    }
}
impl RequestProvider for HostProvider {
    fn send_request<'a>(
        &'a self,
        url: &'a str,
        action: &'a str,
        body: &'a str,
    ) -> RequestFuture<'a> {
        Box::pin(async move {
            Ok(String::from_utf8(
                self.http(url, Some(action), body).await?,
            )?)
        })
    }
}
#[async_trait]
impl SearchProvider for HostProvider {
    fn prepare_socket(&self, socket: &UdpSocket) -> io::Result<()> {
        assert_ne!(socket.local_addr()?.port(), 0);
        assert!(socket.peer_addr().is_err());
        self.protect()
    }
    async fn get(&self, url: &str) -> Result<Vec<u8>, SearchError> {
        self.http(url, None, "").await.map_err(|e| match e {
            RequestError::IoError(e) => SearchError::IoError(e),
            other => SearchError::IoError(io::Error::other(other.to_string())),
        })
    }
}
struct GatewayFixture {
    address: SocketAddr,
    ssdp: Arc<AtomicUsize>,
    http: Arc<Mutex<Vec<String>>>,
    tasks: Vec<JoinHandle<()>>,
}
impl Drop for GatewayFixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
impl GatewayFixture {
    async fn start() -> Self {
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = udp.local_addr().unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let http_addr = tcp.local_addr().unwrap();
        let ssdp = Arc::new(AtomicUsize::new(0));
        let http = Arc::new(Mutex::new(Vec::new()));
        let udp_task = tokio::spawn({
            let count = ssdp.clone();
            async move {
                let mut data = [0; 1500];
                loop {
                    let (n, source) = udp.recv_from(&mut data).await.unwrap();
                    assert!(std::str::from_utf8(&data[..n])
                        .unwrap()
                        .starts_with("M-SEARCH"));
                    count.fetch_add(1, Ordering::SeqCst);
                    udp.send_to(format!("HTTP/1.1 200 OK\r\nLOCATION: http://{http_addr}/description.xml\r\n\r\n").as_bytes(),source).await.unwrap();
                }
            }
        });
        let http_task = tokio::spawn({
            let requests = http.clone();
            async move {
                loop {
                    let (mut stream, _) = tcp.accept().await.unwrap();
                    let mut data = Vec::new();
                    let mut chunk = [0; 4096];
                    loop {
                        let n = stream.read(&mut chunk).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        data.extend_from_slice(&chunk[..n]);
                        assert!(data.len() < 32768);
                        if let Some(end) = data.windows(4).position(|s| s == b"\r\n\r\n") {
                            let headers = String::from_utf8_lossy(&data[..end]);
                            let length = headers
                                .lines()
                                .find_map(|line| {
                                    line.to_ascii_lowercase()
                                        .strip_prefix("content-length:")
                                        .map(|s| s.trim().parse::<usize>().unwrap())
                                })
                                .unwrap_or(0);
                            if data.len() >= end + 4 + length {
                                break;
                            }
                        }
                    }
                    let request = String::from_utf8(data).unwrap();
                    requests.lock().unwrap().push(request.clone());
                    let body = if request.starts_with("GET /description.xml ") {
                        "<root><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><SCPDURL>/schema.xml</SCPDURL><controlURL>/control</controlURL></service></serviceList></device></root>".to_owned()
                    } else if request.starts_with("GET /schema.xml ") {
                        let args = [
                            "NewRemoteHost",
                            "NewExternalPort",
                            "NewProtocol",
                            "NewInternalPort",
                            "NewInternalClient",
                            "NewEnabled",
                            "NewPortMappingDescription",
                            "NewLeaseDuration",
                        ]
                        .into_iter()
                        .map(|name| {
                            format!(
                                "<argument><name>{name}</name><direction>in</direction></argument>"
                            )
                        })
                        .collect::<String>();
                        format!("<scpd><actionList><action><name>AddPortMapping</name><argumentList>{args}</argumentList></action><action><name>DeletePortMapping</name><argumentList><argument><name>NewRemoteHost</name><direction>in</direction></argument><argument><name>NewExternalPort</name><direction>in</direction></argument><argument><name>NewProtocol</name><direction>in</direction></argument></argumentList></action></actionList></scpd>")
                    } else {
                        let (action, value) = if request.contains("#GetExternalIPAddress") {
                            (
                                "GetExternalIPAddressResponse",
                                "<NewExternalIPAddress>203.0.113.5</NewExternalIPAddress>",
                            )
                        } else if request.contains("#AddPortMapping") {
                            assert!(request.contains("<NewInternalPort>8080</NewInternalPort>"));
                            ("AddPortMappingResponse", "")
                        } else {
                            assert!(request.contains("#DeletePortMapping"));
                            ("DeletePortMappingResponse", "")
                        };
                        format!("<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"><s:Body><u:{action} xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">{value}</u:{action}></s:Body></s:Envelope>")
                    };
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    );
                    stream.write_all(response.as_bytes()).await.unwrap();
                }
            }
        });
        Self {
            address,
            ssdp,
            http,
            tasks: vec![udp_task, http_task],
        }
    }
    fn options(&self) -> SearchOptions {
        SearchOptions {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            broadcast_address: self.address,
            timeout: Some(Duration::from_millis(500)),
            single_search_timeout: Some(Duration::from_millis(50)),
        }
    }
}

#[tokio::test]
async fn discovery_and_all_soap_requests_retain_the_host_provider() {
    timeout(Duration::from_secs(5), async {
        let fixture = GatewayFixture::start().await;
        let provider = HostProvider::default();
        let gateway = igd_tokio::search_gateway_with_provider(fixture.options(), provider.clone())
            .await
            .unwrap();
        assert_eq!(provider.steps.load(Ordering::SeqCst), 3);
        assert_eq!(
            gateway.get_external_ip().await.unwrap(),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
        provider.deny.store(5, Ordering::SeqCst);
        assert!(gateway
            .add_port(
                PortMappingProtocol::UDP,
                45000,
                "127.0.0.1:8080".parse().unwrap(),
                60,
                "test"
            )
            .await
            .is_err());
        assert_eq!(fixture.http.lock().unwrap().len(), 3);
        provider.deny.store(0, Ordering::SeqCst);
        for _ in 0..2 {
            gateway
                .add_port(
                    PortMappingProtocol::UDP,
                    45000,
                    "127.0.0.1:8080".parse().unwrap(),
                    60,
                    "test",
                )
                .await
                .unwrap();
        }
        let clone = gateway.clone();
        clone
            .remove_port(PortMappingProtocol::UDP, 45000)
            .await
            .unwrap();
        assert_eq!(provider.steps.load(Ordering::SeqCst), 8);
        assert_eq!(fixture.http.lock().unwrap().len(), 6);
        assert_eq!(fixture.ssdp.load(Ordering::SeqCst), 1);
        // The public native wrapper and static Provider continue to work unchanged.
        let native = igd_tokio::search_gateway(fixture.options()).await.unwrap();
        assert_eq!(
            native.get_external_ip().await.unwrap(),
            "203.0.113.5".parse::<IpAddr>().unwrap()
        );
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn denied_discovery_sockets_and_each_http_bootstrap_never_fall_back() {
    timeout(Duration::from_secs(5), async {
        for deny in 1..=3 {
            let fixture = GatewayFixture::start().await;
            let provider = HostProvider::default();
            provider.deny.store(deny, Ordering::SeqCst);
            assert!(
                igd_tokio::search_gateway_with_provider(fixture.options(), provider)
                    .await
                    .is_err()
            );
            assert_eq!(fixture.ssdp.load(Ordering::SeqCst), usize::from(deny > 1));
            assert_eq!(fixture.http.lock().unwrap().len(), deny.saturating_sub(2));
        }
    })
    .await
    .unwrap();
}
