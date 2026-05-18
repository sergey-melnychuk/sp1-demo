use x25519_dalek::{PublicKey, StaticSecret};

/// Generate a fresh ephemeral X25519 key pair.
///
/// Returns `(esk_client, epk_client)`:
/// - `esk_client` — 32-byte private scalar; passed to the SP1 guest as witness.
/// - `epk_client` — 32-byte public key (esk_client * G); injected into
///   the ClientHello key_share extension during phase 2.
///
/// The guest proves `epk_client == esk_client * G` and verifies that
/// `epk_client` appears in the ClientHello transcript covered by the
/// server's CertificateVerify, closing the authorship gap.
pub fn generate() -> ([u8; 32], [u8; 32]) {
    let esk = StaticSecret::random_from_rng(rand::thread_rng());
    let epk = PublicKey::from(&esk);
    (esk.to_bytes(), *epk.as_bytes())
}
