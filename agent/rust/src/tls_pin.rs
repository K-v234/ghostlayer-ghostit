//! Certificate-pinned TLS connector for agent -> pipeline traffic.
//! We trust exactly one server key (ours), not any public CA chain.

use anyhow::{Context, Result};
use rustls::client::danger::{ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::{client::TlsStream, TlsConnector};

const PINNED_FINGERPRINT: &str =
    "649c8d857e4d5b7a6ca09cb016d73a5be9dee08f485f67b194a1d9377a5c57e9";

#[derive(Debug)]
struct PinnedCertVerifier;

impl ServerCertVerifier for PinnedCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut hasher = Sha256::new();
        hasher.update(end_entity.as_ref());
        let hex: String = hasher.finalize().iter().map(|b| format!("{:02x}", b)).collect();
        if hex == PINNED_FINGERPRINT {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "pipeline cert fingerprint mismatch — expected {}, got {}",
                PINNED_FINGERPRINT, hex
            )))
        }
    }

    fn verify_tls12_signature(
        &self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message, cert, dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self, message: &[u8], cert: &CertificateDer<'_>, dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message, cert, dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
    }
}

/// Drop-in replacement for `TcpStream::connect(format!("{host}:{port}"))`
/// that wraps the connection in pinned TLS. Callers change one line.
pub async fn connect(host: &str, port: u16) -> Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect((host, port))
        .await
        .with_context(|| format!("TCP connect to {host}:{port} failed"))?;

    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedCertVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));
    let server_name = ServerName::try_from("ghostit-pipeline")
        .context("invalid server name")?
        .to_owned();

    let tls_stream = connector
        .connect(server_name, tcp)
        .await
        .context("TLS handshake failed")?;

    Ok(tls_stream)
}
