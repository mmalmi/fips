//! Native WSS trust policy. FIPS authenticates peers independently of TLS.

use crate::config::WebSocketTlsVerification;
use crate::transport::TransportError;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error, SignatureScheme};
use std::sync::Arc;
use tokio_tungstenite::Connector;

pub(super) fn connector(
    policy: WebSocketTlsVerification,
) -> Result<Option<Connector>, TransportError> {
    if policy == WebSocketTlsVerification::WebPki {
        return Ok(None);
    }
    let provider = rustls::crypto::ring::default_provider();
    let verifier = FipsAuthenticatedPeer(provider.signature_verification_algorithms);
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|error| TransportError::StartFailed(error.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth();
    Ok(Some(Connector::Rustls(Arc::new(config))))
}

#[derive(Debug)]
struct FipsAuthenticatedPeer(WebPkiSupportedAlgorithms);

impl ServerCertVerifier for FipsAuthenticatedPeer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        // The certificate supplies the TLS key, not the peer's identity. FIPS
        // Noise authentication and admission still run after this handshake.
        rustls::server::ParsedCertificate::try_from(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(message, cert, dss, &self.0)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(message, cert, dss, &self.0)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_schemes()
    }
}
