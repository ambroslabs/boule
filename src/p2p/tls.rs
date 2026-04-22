use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Context as _;
use rcgen::{CertificateParams, KeyPair, PKCS_ED25519};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, DistinguishedName, Error, ServerConfig, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_rustls::TlsAcceptor;

pub type NodeId = [u8; 32];

pub fn node_id_to_base58(id: &NodeId) -> String {
    bs58::encode(id).into_string()
}

pub fn base58_to_node_id(s: &str) -> anyhow::Result<NodeId> {
    let bytes = bs58::decode(s).into_vec().context("invalid base58")?;
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("node ID must be 32 bytes"))
}

/// Unified stream type covering both inbound and outbound TLS connections.
pub enum TlsStream {
    Client(tokio_rustls::client::TlsStream<tokio::net::TcpStream>),
    Server(tokio_rustls::server::TlsStream<tokio::net::TcpStream>),
}

impl AsyncRead for TlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Client(s) => Pin::new(s).poll_read(cx, buf),
            Self::Server(s) => Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for TlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match self.get_mut() {
            Self::Client(s) => Pin::new(s).poll_write(cx, buf),
            Self::Server(s) => Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Client(s) => Pin::new(s).poll_flush(cx),
            Self::Server(s) => Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self.get_mut() {
            Self::Client(s) => Pin::new(s).poll_shutdown(cx),
            Self::Server(s) => Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Node TLS identity: Ed25519 key pair + self-signed certificate.
/// The public key bytes *are* the node ID.
pub struct TlsIdentity {
    pub node_id: NodeId,
    pub acceptor: TlsAcceptor,
    pub client_config: Arc<ClientConfig>,
}

impl TlsIdentity {
    /// Load existing key from `key_file`, or generate a new one and persist it.
    pub fn load_or_generate(key_file: &Path) -> anyhow::Result<Self> {
        let crypto = Arc::new(rustls::crypto::ring::default_provider());

        let key_pair = if key_file.exists() {
            let der_bytes = std::fs::read(key_file).context("reading node key")?;
            let pkcs8 = rustls::pki_types::PrivatePkcs8KeyDer::from(der_bytes);
            KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
                .context("parsing node key DER")?
        } else {
            let kp = KeyPair::generate_for(&PKCS_ED25519).context("generating Ed25519 key")?;
            if let Some(parent) = key_file.parent() {
                std::fs::create_dir_all(parent).context("creating key directory")?;
            }
            std::fs::write(key_file, kp.serialize_der()).context("writing node key")?;
            kp
        };

        Self::from_key_pair(key_pair, crypto)
    }

    fn from_key_pair(
        key_pair: KeyPair,
        crypto: Arc<rustls::crypto::CryptoProvider>,
    ) -> anyhow::Result<Self> {
        let pubkey_raw = key_pair.public_key_raw();
        let node_id: NodeId = pubkey_raw
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32-byte Ed25519 public key"))?;

        let params = CertificateParams::new(vec!["ambros-p2p".to_string()])
            .context("building cert params")?;
        let cert = params
            .self_signed(&key_pair)
            .context("self-signing certificate")?;

        let cert_der = CertificateDer::from(cert.der().to_vec());

        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        );

        // Server config: request (and accept any) client certificate for identity.
        let server_config = ServerConfig::builder_with_provider(Arc::clone(&crypto))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("setting TLS version")?
            .with_client_cert_verifier(Arc::new(AnyCertVerifier {
                crypto: Arc::clone(&crypto),
            }))
            .with_single_cert(vec![cert_der.clone()], key_der.clone_key())
            .context("building server TLS config")?;

        // Client config: present our cert; accept self-signed peer certs (pubkey check is done
        // in application code after the handshake, not inside the TLS verifier).
        let client_config = ClientConfig::builder_with_provider(Arc::clone(&crypto))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .context("setting TLS version")?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnyCertVerifier {
                crypto: Arc::clone(&crypto),
            }))
            .with_client_auth_cert(vec![cert_der], key_der)
            .context("building client TLS config")?;

        Ok(Self {
            node_id,
            acceptor: TlsAcceptor::from(Arc::new(server_config)),
            client_config: Arc::new(client_config),
        })
    }
}

/// Extract the 32-byte Ed25519 public key from a DER-encoded certificate.
///
/// Ed25519 SubjectPublicKeyInfo has a fixed 12-byte DER prefix followed by
/// the 32-byte key, so we locate it by searching for the known OID pattern.
pub fn extract_node_id(cert: &CertificateDer<'_>) -> anyhow::Result<NodeId> {
    // DER encoding of Ed25519 SubjectPublicKeyInfo:
    //   30 2a               SEQUENCE
    //     30 05             SEQUENCE
    //       06 03 2b 65 70  OID 1.3.101.112 (Ed25519)
    //     03 21             BIT STRING, 33 bytes
    //       00              no unused bits
    //       <32 bytes>      public key
    const SPKI_PREFIX: &[u8] = &[
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    let bytes = cert.as_ref();
    for w in bytes.windows(SPKI_PREFIX.len() + 32) {
        if w.starts_with(SPKI_PREFIX) {
            let key = &w[SPKI_PREFIX.len()..];
            return Ok(key.try_into().unwrap());
        }
    }
    anyhow::bail!("Ed25519 public key not found in certificate DER")
}

// ── Verifiers ────────────────────────────────────────────────────────────────

/// Accepts any certificate (both client and server sides).
/// Actual node ID verification is done in application code after the handshake.
#[derive(Debug)]
struct AnyCertVerifier {
    crypto: Arc<rustls::crypto::CryptoProvider>,
}

impl ServerCertVerifier for AnyCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto.signature_verification_algorithms.supported_schemes()
    }
}

impl ClientCertVerifier for AnyCertVerifier {
    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, Error> {
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.crypto.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.crypto.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.crypto.signature_verification_algorithms.supported_schemes()
    }
}
