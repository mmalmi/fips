//! A loopback TLS terminator in front of the relay's ordinary WS listener.
//! Only the child client trusts the generated CA; system trust stays untouched.

use fips_core::config::{TransportInstances, WebSocketConfig};
use fips_relay::service::{AdminRequest, ServiceConfig, request};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::{
    ffi::OsStr,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    process::Child,
    task::{JoinHandle, JoinSet},
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{ServerConfig, pki_types::PrivatePkcs8KeyDer},
};

use crate::process_support::{start_with_env, stop};

pub struct TlsProxy {
    pub url: String,
    wrong_name_url: String,
    trusted_ca: PathBuf,
    unrelated_ca: PathBuf,
    empty_cert_dir: PathBuf,
    connections: Arc<AtomicUsize>,
    tasks: Vec<JoinHandle<()>>,
}

impl TlsProxy {
    pub async fn start(root: &Path, backend: SocketAddr) -> Self {
        let (ca, key) = authority("trusted test CA");
        let (unrelated, _) = authority("unrelated test CA");
        let trusted_ca = root.join("trusted-ca.pem");
        let unrelated_ca = root.join("unrelated-ca.pem");
        let empty_cert_dir = root.join("empty-cert-dir");
        std::fs::write(&trusted_ca, ca.pem()).unwrap();
        std::fs::write(&unrelated_ca, unrelated.pem()).unwrap();
        std::fs::create_dir(&empty_cert_dir).unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();
        let mut urls = Vec::new();
        for name in ["127.0.0.1", "wrong.invalid"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            urls.push(format!("wss://{}/fips", listener.local_addr().unwrap()));
            tasks.push(tokio::spawn(serve(
                listener,
                backend,
                acceptor(&ca, &key, name),
                connections.clone(),
            )));
        }
        Self {
            url: urls.remove(0),
            wrong_name_url: urls.remove(0),
            trusted_ca,
            unrelated_ca,
            empty_cert_dir,
            connections,
            tasks,
        }
    }

    pub fn connections(&self) -> usize {
        self.connections.load(Ordering::SeqCst)
    }

    async fn client_with_ca(&self, path: &Path, ca: &Path) -> Child {
        start_with_env(
            path,
            &[
                ("SSL_CERT_FILE", ca.as_os_str()),
                ("SSL_CERT_DIR", self.empty_cert_dir.as_os_str()),
                (
                    "RUST_LOG",
                    OsStr::new("fips_core::transport::websocket=debug"),
                ),
            ],
        )
        .await
    }

    pub async fn start_client(&self, path: &Path) -> Child {
        self.client_with_ca(path, &self.trusted_ca).await
    }

    pub async fn assert_rejections(&self, config: &ServiceConfig, path: &Path) {
        for (url, ca, expected) in [
            (&self.url, &self.unrelated_ca, "UnknownIssuer"),
            (
                &self.wrong_name_url,
                &self.trusted_ca,
                "certificate not valid for name",
            ),
        ] {
            let mut rejected = config.clone();
            rejected.transports.websocket = TransportInstances::Single(WebSocketConfig {
                bind_addr: None,
                seed_urls: vec![url.clone()],
                ..Default::default()
            });
            std::fs::write(path, serde_json::to_vec(&rejected).unwrap()).unwrap();
            let mut child = self.client_with_ca(path, ca).await;
            let result = tokio::time::timeout(Duration::from_secs(15), async {
                loop {
                    assert!(child.try_wait().unwrap().is_none(), "TLS client exited");
                    let log = std::fs::read_to_string(path.with_extension("log")).unwrap();
                    if log.contains(expected)
                        && let Ok(status) = request(config, &AdminRequest::Status).await
                    {
                        assert!(
                            status["peers"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .all(|p| p["connected"] != true)
                        );
                        assert_eq!(status["funding_budget"]["wallet_debited_sat"], 0);
                        assert_eq!(status["remaining_budget_sat"], 64);
                        assert!(status["history"].as_array().unwrap().is_empty());
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            })
            .await;
            assert!(
                result.is_ok(),
                "missing TLS rejection {expected}: {}",
                std::fs::read_to_string(path.with_extension("log")).unwrap()
            );
            stop(&mut child).await;
            assert_eq!(
                self.connections(),
                0,
                "invalid TLS must never reach the WS backend"
            );
            eprintln!("TLS client rejected {expected}; no peers or wallet debit");
        }
        std::fs::write(path, serde_json::to_vec(config).unwrap()).unwrap();
    }
}

impl Drop for TlsProxy {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

fn authority(name: &str) -> (Certificate, KeyPair) {
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
    ];
    let key = KeyPair::generate().unwrap();
    (params.self_signed(&key).unwrap(), key)
}

fn acceptor(ca: &Certificate, ca_key: &KeyPair, name: &str) -> TlsAcceptor {
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key, ca, ca_key).unwrap();
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    TlsAcceptor::from(Arc::new(server))
}

async fn serve(
    listener: TcpListener,
    backend: SocketAddr,
    acceptor: TlsAcceptor,
    connections: Arc<AtomicUsize>,
) {
    let mut sessions = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept(), if sessions.len() < 16 => {
                let (stream, _) = accepted.unwrap();
                let acceptor = acceptor.clone();
                let connections = connections.clone();
                sessions.spawn(async move {
                    let Ok(Ok(mut tls)) = tokio::time::timeout(
                        Duration::from_secs(5), acceptor.accept(stream),
                    ).await else { return };
                    let Ok(mut upstream) = TcpStream::connect(backend).await else { return };
                    connections.fetch_add(1, Ordering::SeqCst);
                    let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
                });
            }
            finished = sessions.join_next(), if !sessions.is_empty() => {
                finished.unwrap().unwrap();
            }
        }
    }
}
