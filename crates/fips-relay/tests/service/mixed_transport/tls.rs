//! A loopback TLS terminator in front of the relay's ordinary WS listener.
//! Only the child client trusts the generated CA; system trust stays untouched.

use fips_core::config::{TransportInstances, WebSocketConfig, WebSocketTlsVerification};
use fips_relay::service::{AdminRequest, ServiceConfig, request};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use std::{
    ffi::OsStr,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::process::Child;
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::PrivatePkcs8KeyDer,
        server::{ClientHello, ResolvesServerCert},
        sign::CertifiedKey,
    },
};

use super::proxy::StreamProxy;
use crate::process_support::{start_with_env, stop};

pub struct TlsProxy {
    pub url: String,
    wrong_name_url: String,
    trusted_ca: PathBuf,
    unrelated_ca: PathBuf,
    empty_cert_dir: PathBuf,
    proxies: Vec<StreamProxy>,
    self_signed: bool,
}

impl TlsProxy {
    pub async fn start(root: &Path, backend: SocketAddr, self_signed: bool) -> Self {
        let (ca, key) = authority("trusted test CA");
        let (unrelated, _) = authority("unrelated test CA");
        let trusted_ca = root.join("trusted-ca.pem");
        let unrelated_ca = root.join("unrelated-ca.pem");
        let empty_cert_dir = root.join("empty-cert-dir");
        std::fs::write(&trusted_ca, ca.pem()).unwrap();
        std::fs::write(&unrelated_ca, unrelated.pem()).unwrap();
        std::fs::create_dir(&empty_cert_dir).unwrap();
        let mut proxies = Vec::new();
        let mut urls = Vec::new();
        for (index, name) in ["127.0.0.1", "wrong.invalid"].into_iter().enumerate() {
            let proxy = StreamProxy::start(
                backend,
                Some(acceptor(
                    &ca,
                    &key,
                    name,
                    self_signed,
                    self_signed && index == 1,
                )),
            )
            .await;
            urls.push(format!("wss://{}/fips", proxy.address));
            proxies.push(proxy);
        }
        Self {
            url: urls.remove(0),
            wrong_name_url: urls.remove(0),
            trusted_ca,
            unrelated_ca,
            empty_cert_dir,
            proxies,
            self_signed,
        }
    }

    pub fn connections(&self) -> usize {
        self.proxies.iter().map(StreamProxy::connections).sum()
    }

    pub fn carrier(&self) -> &StreamProxy {
        &self.proxies[0]
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
        // The self-signed leaf has no relationship to this unrelated root.
        let ca = if self.self_signed {
            &self.unrelated_ca
        } else {
            &self.trusted_ca
        };
        self.client_with_ca(path, ca).await
    }

    pub async fn assert_rejections(&self, config: &ServiceConfig, path: &Path) {
        let second_mode = if self.self_signed {
            WebSocketTlsVerification::Fips
        } else {
            WebSocketTlsVerification::WebPki
        };
        let second_error = if self.self_signed {
            "BadSignature"
        } else {
            "certificate not valid for name"
        };
        for (url, ca, mode, expected) in [
            (
                &self.url,
                &self.unrelated_ca,
                WebSocketTlsVerification::WebPki,
                "UnknownIssuer",
            ),
            (
                &self.wrong_name_url,
                &self.trusted_ca,
                second_mode,
                second_error,
            ),
        ] {
            let mut rejected = config.clone();
            rejected.transports.websocket = TransportInstances::Single(WebSocketConfig {
                bind_addr: None,
                seed_urls: vec![url.clone()],
                tls_verification: Some(mode),
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

fn acceptor(
    ca: &Certificate,
    ca_key: &KeyPair,
    name: &str,
    self_signed: bool,
    invalid_signature: bool,
) -> TlsAcceptor {
    let name = if self_signed {
        "self-signed.invalid"
    } else {
        name
    };
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let cert = if self_signed {
        params.self_signed(&key).unwrap()
    } else {
        params.signed_by(&key, ca, ca_key).unwrap()
    };
    if invalid_signature {
        // A custom resolver bypasses the server builder's key-match check so
        // the actual client must reject a forged TLS handshake signature.
        let other_key =
            PrivatePkcs8KeyDer::from(KeyPair::generate().unwrap().serialize_der()).into();
        let signer =
            tokio_rustls::rustls::crypto::ring::sign::any_supported_type(&other_key).unwrap();
        let server = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(FixedCertificate(Arc::new(CertifiedKey::new(
                vec![cert.der().clone()],
                signer,
            )))));
        return TlsAcceptor::from(Arc::new(server));
    }
    let server = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
        )
        .unwrap();
    TlsAcceptor::from(Arc::new(server))
}

#[derive(Debug)]
struct FixedCertificate(Arc<CertifiedKey>);

impl ResolvesServerCert for FixedCertificate {
    fn resolve(&self, _: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}
