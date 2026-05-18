use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};
use x25519_dalek::{PublicKey, StaticSecret};

/// A `SupportedKxGroup` that performs X25519 using a caller-supplied private
/// key rather than generating one internally.
///
/// This is how `epk_client` (generated in phase 1) is injected into the
/// TLS handshake without rustls generating its own ephemeral key. The host
/// legitimately participates in the handshake; it just uses an externally
/// generated key so the same `esk_client` can be handed to the SP1 guest.
pub struct ExternalKxGroup {
    /// The ephemeral private key from phase 1.
    pub esk_client: [u8; 32],
}

impl fmt::Debug for ExternalKxGroup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExternalKxGroup(X25519)")
    }
}

impl SupportedKxGroup for ExternalKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = StaticSecret::from(self.esk_client);
        let public = PublicKey::from(&secret);
        Ok(Box::new(ExternalActiveKx { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct ExternalActiveKx {
    secret: StaticSecret,
    public: PublicKey,
}

impl ActiveKeyExchange for ExternalActiveKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let server_pub_bytes = <[u8; 32]>::try_from(peer_pub_key)
            .map_err(|_| Error::General("X25519: peer key must be 32 bytes".into()))?;
        let server_pub = PublicKey::from(server_pub_bytes);
        let shared = self.secret.diffie_hellman(&server_pub);
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// Build a `CryptoProvider` that uses `esk_client` for X25519 key exchange
/// and falls back to ring for everything else.
pub fn make_provider(esk_client: [u8; 32]) -> rustls::crypto::CryptoProvider {
    let kx: &'static dyn SupportedKxGroup =
        Box::leak(Box::new(ExternalKxGroup { esk_client }));
    rustls::crypto::CryptoProvider {
        kx_groups: vec![kx],
        ..rustls::crypto::ring::default_provider()
    }
}

// ---------------------------------------------------------------------------
// CapturingStream
// ---------------------------------------------------------------------------

/// Wraps a `TcpStream` and records every raw byte in both directions.
///
/// `inbound`  — bytes received from the server (server → client TLS records)
/// `outbound` — bytes sent to the server   (client → server TLS records)
pub struct CapturingStream {
    inner: TcpStream,
    pub inbound: Vec<u8>,
    pub outbound: Vec<u8>,
}

impl CapturingStream {
    pub fn new(stream: TcpStream) -> Self {
        Self {
            inner: stream,
            inbound: Vec::new(),
            outbound: Vec::new(),
        }
    }
}

impl Read for CapturingStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.inbound.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl Write for CapturingStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.outbound.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
