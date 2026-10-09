//! Tokio QUIC under strict ALPN "ark-pqc/v1" (no downgrade allowed).

use ark_core::constants::ALPN_ARK_PQC_V1;
use ark_core::error::{ArkError, Result};
use quinn::{ClientConfig, Endpoint, ServerConfig};
use std::net::SocketAddr;
use std::sync::Arc;

pub struct ArkQuicEndpoint {
    pub endpoint: Endpoint,
}

impl ArkQuicEndpoint {
    /// Creates a QUIC client endpoint locked strictly to ALPN "ark-pqc/v1"
    pub fn new_client(bind_addr: SocketAddr) -> Result<Self> {
        let mut endpoint = Endpoint::client(bind_addr).map_err(ArkError::IoError)?;

        let mut crypto_cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| ArkError::CryptoError(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(DangerousVerifier))
        .with_no_client_auth();

        crypto_cfg.alpn_protocols = vec![ALPN_ARK_PQC_V1.to_vec()];

        let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(crypto_cfg)
            .map_err(|e| ArkError::CryptoError(e.to_string()))?;
        endpoint.set_default_client_config(ClientConfig::new(Arc::new(quic_client_config)));

        Ok(Self { endpoint })
    }

    /// Creates a QUIC server endpoint locked strictly to ALPN "ark-pqc/v1"
    pub fn new_server(bind_addr: SocketAddr, cert_der: Vec<u8>, key_der: Vec<u8>) -> Result<Self> {
        let certs = vec![rustls::pki_types::CertificateDer::from(cert_der)];
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_der),
        );

        let mut crypto_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| ArkError::CryptoError(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ArkError::CryptoError(e.to_string()))?;

        crypto_cfg.alpn_protocols = vec![ALPN_ARK_PQC_V1.to_vec()];

        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(crypto_cfg)
            .map_err(|e| ArkError::CryptoError(e.to_string()))?;
        let server_config = ServerConfig::with_crypto(Arc::new(quic_server_config));

        let endpoint = Endpoint::server(server_config, bind_addr).map_err(ArkError::IoError)?;

        Ok(Self { endpoint })
    }

    /// Creates a QUIC server endpoint with an auto-generated self-signed certificate
    pub fn new_server_self_signed(bind_addr: SocketAddr) -> Result<Self> {
        let rcgen_cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| ArkError::CryptoError(e.to_string()))?;
        let cert_der = rcgen_cert.cert.der().to_vec();
        let key_der = rcgen_cert.key_pair.serialize_der();
        Self::new_server(bind_addr, cert_der, key_der)
    }
}

/// Verification helper for P2P identity handshake
#[derive(Debug)]
struct DangerousVerifier;

impl rustls::client::danger::ServerCertVerifier for DangerousVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // P2P authentication is validated at the ArkEnvelope / FN-DSA-512 layer
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}
