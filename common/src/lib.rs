use serde::{Deserialize, Serialize};

// ── Notary attestation types ──────────────────────────────────────────────────
//
// These are mirrored by `notary::tls::{NotaryBundle, RecordCommit}` — the
// notary crate re-exports them so there's a single source of truth. Fields
// must stay byte-compatible (same names, same order, same types) because
// the bundle is bincode-serialized over the wire from notary → host →
// SP1 guest stdin.

/// Witness-path session binding committed in the Ed25519 signature (bundle v2).
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct SessionBinding {
    /// ServerHello X25519 key_share (32 B).
    pub server_epk: [u8; 32],
    /// SHA-256 of length-prefixed peer certificate DER chain.
    pub cert_chain_hash: [u8; 32],
    /// SHA-256 of length-prefixed raw outbound || inbound handshake bytes.
    pub handshake_transcript_hash: [u8; 32],
    /// SHA-256(`after_server_hello || after_server_finished`).
    pub key_schedule_context_hash: [u8; 32],
    /// SHA-256 of bundled `AES-non-expanded.txt`.
    pub circuit_aes_sha256: [u8; 32],
    /// SHA-256 of bundled `sha-256-compress.txt`.
    pub circuit_sha256_compress_sha256: [u8; 32],
    /// `0` = semi-honest twopac (legacy), `3` = full WRK17 record layer (`GARBLING_FULL_AUTH`).
    pub garbling_mode: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordCommit {
    pub op: u8,
    pub seq: u64,
    pub aad: Vec<u8>,
    pub commit_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotaryBundle {
    /// `1` = includes [`SessionBinding`] in signature; `0` = legacy (pre-binding).
    #[serde(default)]
    pub bundle_version: u8,
    pub notary_pubkey: [u8; 32],
    pub timestamp_unix: u64,
    pub session_id: String,
    pub server_name: String,
    pub records: Vec<RecordCommit>,
    pub k_n_tx: [u8; 16],
    pub iv_tx: [u8; 12],
    pub k_n_rx: [u8; 16],
    pub iv_rx: [u8; 12],
    #[serde(default)]
    pub binding: SessionBinding,
    pub signature: Vec<u8>,
}

impl NotaryBundle {
    pub const BUNDLE_VERSION_LEGACY: u8 = 0;
    pub const BUNDLE_VERSION_BINDING: u8 = 1;

    /// Canonical byte encoding for signing (deterministic across host/notary/guest).
    #[allow(clippy::too_many_arguments)]
    pub fn canonical_signing_bytes(
        bundle_version: u8,
        notary_pubkey: &[u8; 32],
        timestamp_unix: u64,
        session_id: &str,
        server_name: &str,
        records: &[RecordCommit],
        k_n_tx: &[u8; 16],
        iv_tx: &[u8; 12],
        k_n_rx: &[u8; 16],
        iv_rx: &[u8; 12],
        binding: &SessionBinding,
    ) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(bundle_version);
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
        if bundle_version >= Self::BUNDLE_VERSION_BINDING {
            buf.extend_from_slice(&binding.server_epk);
            buf.extend_from_slice(&binding.cert_chain_hash);
            buf.extend_from_slice(&binding.handshake_transcript_hash);
            buf.extend_from_slice(&binding.key_schedule_context_hash);
            buf.extend_from_slice(&binding.circuit_aes_sha256);
            buf.extend_from_slice(&binding.circuit_sha256_compress_sha256);
            buf.push(binding.garbling_mode);
        }
        buf
    }

    /// Pre-binding (v0) signing bytes — no version prefix, no [`SessionBinding`].
    #[allow(clippy::too_many_arguments)]
    pub fn legacy_signing_bytes_pre_binding(
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
        binding: SessionBinding,
    ) -> Self {
        Self::sign_with_version(
            signing_key,
            Self::BUNDLE_VERSION_BINDING,
            session_id,
            server_name,
            records,
            k_n_tx,
            iv_tx,
            k_n_rx,
            iv_rx,
            binding,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_with_version(
        signing_key: &ed25519_dalek::SigningKey,
        bundle_version: u8,
        session_id: String,
        server_name: String,
        records: Vec<RecordCommit>,
        k_n_tx: [u8; 16],
        iv_tx: [u8; 12],
        k_n_rx: [u8; 16],
        iv_rx: [u8; 12],
        binding: SessionBinding,
    ) -> Self {
        use ed25519_dalek::Signer;
        let notary_pubkey = signing_key.verifying_key().to_bytes();
        #[cfg(not(target_os = "zkvm"))]
        let timestamp_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        #[cfg(target_os = "zkvm")]
        let timestamp_unix: u64 = 0;
        let bytes = Self::canonical_signing_bytes(
            bundle_version,
            &notary_pubkey,
            timestamp_unix,
            &session_id,
            &server_name,
            &records,
            &k_n_tx,
            &iv_tx,
            &k_n_rx,
            &iv_rx,
            &binding,
        );
        let signature = signing_key.sign(&bytes).to_bytes().to_vec();
        NotaryBundle {
            bundle_version,
            notary_pubkey,
            timestamp_unix,
            session_id,
            server_name,
            records,
            k_n_tx,
            iv_tx,
            k_n_rx,
            iv_rx,
            binding,
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
        let bytes = if self.bundle_version >= Self::BUNDLE_VERSION_BINDING {
            Self::canonical_signing_bytes(
                self.bundle_version,
                &self.notary_pubkey,
                self.timestamp_unix,
                &self.session_id,
                &self.server_name,
                &self.records,
                &self.k_n_tx,
                &self.iv_tx,
                &self.k_n_rx,
                &self.iv_rx,
                &self.binding,
            )
        } else {
            Self::legacy_signing_bytes_pre_binding(
                &self.notary_pubkey,
                self.timestamp_unix,
                &self.session_id,
                &self.server_name,
                &self.records,
                &self.k_n_tx,
                &self.iv_tx,
                &self.k_n_rx,
                &self.iv_rx,
            )
        };
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
/// Trust boundary (self-prove): the host holds both `esk_client` and `raw_inbound` (which
/// contains `epk_server` in the ServerHello). It can therefore derive `shared_secret` and
/// `server_write_key` — a malicious host could forge application-data records. That is
/// acceptable when the prover is the same party that fetched (`notary == None`).
///
/// Delegated proving uses the notary witness path (`notary: Some(_)`): the guest checks the
/// signed bundle and record commits instead of re-running full TLS verification. The MPC/2PC
/// code that produces the bundle is replaceable — see `PROD.md` §2.1.
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

    /// If `Some`, the witness was attested by a notary backend (any producer of
    /// [`NotaryAttestation`]). The guest verifies the bundle's Ed25519 signature and uses the
    /// bundle's `K_N` (plus the attestation's `K_C`) to reconstruct the TLS keys —
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
