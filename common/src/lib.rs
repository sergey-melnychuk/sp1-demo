use serde::{Deserialize, Serialize};

// ── Notary attestation types ──────────────────────────────────────────────────
//
// These are mirrored by `notary::tls::{NotaryBundle, RecordCommit}` — the
// notary crate re-exports them so there's a single source of truth. Fields
// must stay byte-compatible (same names, same order, same types) because
// the bundle is bincode-serialized over the wire from notary → host →
// SP1 guest stdin.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordCommit {
    pub op: u8,
    pub seq: u64,
    pub aad: Vec<u8>,
    pub commit_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotaryBundle {
    pub notary_pubkey: [u8; 32],
    pub timestamp_unix: u64,
    pub session_id: String,
    pub server_name: String,
    pub records: Vec<RecordCommit>,
    pub k_n_tx: [u8; 16],
    pub iv_tx: [u8; 12],
    pub k_n_rx: [u8; 16],
    pub iv_rx: [u8; 12],
    pub signature: Vec<u8>,
}

impl NotaryBundle {
    /// Canonical byte encoding for signing (deterministic across host/notary/guest).
    #[allow(clippy::too_many_arguments)]
    pub fn canonical_signing_bytes(
        notary_pubkey: &[u8; 32],
        timestamp_unix: u64,
        session_id: &str,
        server_name: &str,
        records: &[RecordCommit],
        k_n_tx: &[u8; 16],
        iv_tx: &[u8; 12],
        k_n_rx: &[u8; 16],
        iv_rx: &[u8; 12],
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(notary_pubkey);
        buf.extend_from_slice(&timestamp_unix.to_be_bytes());
        buf.extend_from_slice(&(session_id.len() as u16).to_be_bytes());
        buf.extend_from_slice(session_id.as_bytes());
        buf.extend_from_slice(&(server_name.len() as u16).to_be_bytes());
        buf.extend_from_slice(server_name.as_bytes());
        buf.extend_from_slice(&(records.len() as u32).to_be_bytes());
        for r in records {
            buf.push(r.op);
            buf.extend_from_slice(&r.seq.to_be_bytes());
            buf.extend_from_slice(&(r.aad.len() as u16).to_be_bytes());
            buf.extend_from_slice(&r.aad);
            buf.extend_from_slice(&r.commit_hash);
        }
        buf.extend_from_slice(k_n_tx);
        buf.extend_from_slice(iv_tx);
        buf.extend_from_slice(k_n_rx);
        buf.extend_from_slice(iv_rx);
        buf
    }

    /// Build and sign a bundle. Used on the notary side after OP_FINISH.
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        signing_key: &ed25519_dalek::SigningKey,
        session_id: String,
        server_name: String,
        records: Vec<RecordCommit>,
        k_n_tx: [u8; 16],
        iv_tx: [u8; 12],
        k_n_rx: [u8; 16],
        iv_rx: [u8; 12],
    ) -> Self {
        use ed25519_dalek::Signer;
        let notary_pubkey = signing_key.verifying_key().to_bytes();
        // Note: SystemTime::now() doesn't exist in `no_std` (SP1 guest). On the
        // notary side this is called with std, so it's fine. The guest never
        // calls sign() — it only verifies.
        #[cfg(not(target_os = "zkvm"))]
        let timestamp_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        #[cfg(target_os = "zkvm")]
        let timestamp_unix: u64 = 0;
        let bytes = Self::canonical_signing_bytes(
            &notary_pubkey,
            timestamp_unix,
            &session_id,
            &server_name,
            &records,
            &k_n_tx,
            &iv_tx,
            &k_n_rx,
            &iv_rx,
        );
        let signature = signing_key.sign(&bytes).to_bytes().to_vec();
        NotaryBundle {
            notary_pubkey,
            timestamp_unix,
            session_id,
            server_name,
            records,
            k_n_tx,
            iv_tx,
            k_n_rx,
            iv_rx,
            signature,
        }
    }

    /// Verify the Ed25519 signature in this bundle. Returns `true` iff the
    /// signature is well-formed and verifies against `self.notary_pubkey`.
    /// Used on both the host (sanity check) and the guest (zk constraint).
    pub fn verify(&self) -> bool {
        use ed25519_dalek::Verifier;
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.notary_pubkey) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(self.signature.as_slice()) else {
            return false;
        };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        let bytes = Self::canonical_signing_bytes(
            &self.notary_pubkey,
            self.timestamp_unix,
            &self.session_id,
            &self.server_name,
            &self.records,
            &self.k_n_tx,
            &self.iv_tx,
            &self.k_n_rx,
            &self.iv_rx,
        );
        vk.verify(&bytes, &sig).is_ok()
    }
}

/// What the host passes to the guest when `--notary` is used. The bundle is
/// what the notary signed; `k_c_tx`/`k_c_rx` are the host's own share of the
/// TLS write keys (it never gave these to the notary). Combined, the guest
/// reconstructs `K = K_N XOR K_C` and decrypts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotaryAttestation {
    pub bundle: NotaryBundle,
    pub k_c_tx: [u8; 16],
    pub k_c_rx: [u8; 16],
}

/// The full TLS 1.3 witness passed from host → guest via SP1 stdin.
///
/// The host supplies esk_client (generated in phase 1) and the raw wire bytes
/// captured during the TLS session. The guest independently re-derives all
/// keys, decrypts handshake records, verifies the certificate chain and
/// CertificateVerify, and decrypts application data.
///
/// Trust boundary: the host holds both esk_client and raw_inbound (which
/// contains epk_server in the ServerHello). It can therefore derive
/// shared_secret and server_write_key — meaning a malicious host can forge
/// application-data records. This is acceptable for self-proving (the user IS
/// the host). Delegated proving requires MPC-TLS or a TEE; see NEXT.md §6.5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsWitness {
    /// Client ephemeral X25519 private key (32 bytes). Only used in
    /// self-proving mode (`notary == None`). When `notary` is `Some`, this
    /// field is ignored by the guest — keys are derived from the bundle
    /// instead.
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

    /// If `Some`, the witness was produced via a 2PC session with a notary.
    /// The guest verifies the bundle's Ed25519 signature and uses the bundle's
    /// `K_N` (plus the attestation's `K_C`) to reconstruct the TLS keys —
    /// `esk_client` above is ignored in that case.
    #[serde(default)]
    pub notary: Option<NotaryAttestation>,
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
