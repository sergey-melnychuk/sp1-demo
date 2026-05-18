use serde::{Deserialize, Serialize};

/// The full TLS 1.3 witness passed from host → guest via SP1 stdin.
///
/// The host is a dumb relay: it supplies esk_client (generated in phase 1)
/// and raw wire bytes only. The guest independently derives all keys,
/// decrypts handshake records, verifies the certificate chain and
/// CertificateVerify, then decrypts application data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsWitness {
    /// Client ephemeral X25519 private key (32 bytes), generated in phase 1.
    /// Never derived by the host from the TLS handshake.
    pub esk_client: [u8; 32],

    /// All raw bytes received from the server over TCP.
    /// Includes: ServerHello (plaintext), then encrypted handshake records,
    /// then encrypted application data records.
    pub raw_inbound: Vec<u8>,

    /// All raw bytes sent to the server over TCP.
    /// Includes: ClientHello (plaintext), then ClientFinished (encrypted).
    /// The guest uses this to verify epk_client in the ClientHello transcript.
    pub raw_outbound: Vec<u8>,

    pub hostname: String,
    pub json_field: String,
    pub threshold: f64,
    pub now_unix: i64,
}

/// What the guest commits as public output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicClaim {
    /// The server hostname that was verified.
    pub host: String,

    /// The JSON Pointer that was checked (e.g. "/data/amount").
    pub field: String,

    /// The threshold value.
    pub threshold: f64,

    /// The actual field value extracted from the verified response.
    pub value: f64,
}
