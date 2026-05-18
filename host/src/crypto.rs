use std::fmt;

use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup};
use x25519_dalek::{PublicKey, StaticSecret};

/// A `SupportedKxGroup` that performs X25519 using a caller-supplied private
/// key rather than generating one internally.
///
/// This injects `epk_client` (from phase 1) into the TLS handshake. The host
/// completes the handshake normally — it knows `esk_client` and can derive
/// `server_write_key` from the ServerHello. See the trust note in main.rs.
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
