//! High-level notary-side TLS session glue.
//!
//! This is the entry point the `host` crate uses when acting as the
//! prover/notary pair during a zkTLS session. It composes:
//!
//! - [`ecdh`]: X25519 additives + XOR-split IKM helpers + `OtX25519Placeholder`.
//! - [`hkdf`]: 2PC HKDF-SHA256 — yields each party's share of the AES traffic
//!   key (`K = K_N XOR K_C`) without either party seeing the full key.
//! - [`aes`]: split-key AES-128-GCM (encrypt + decrypt) over a swanky channel.
//!
//! Two layers of API live here:
//!
//! 1. **Standalone primitives** — [`TwoPartyGcmEncrypter`] / [`NotaryTlsSession`]
//!    let you drive one 2PC record at a time with a `&mut Channel`. Useful
//!    when you control your own I/O loop.
//!
//! 2. **rustls hookup** — [`ClientWorker`] spawns a worker thread that owns the
//!    swanky channel, exposes [`MessageEncrypter`] / [`MessageDecrypter`]
//!    (`Send + Sync`) so it plugs into rustls' record layer. The
//!    counterpart on the notary side is [`run_notary_worker`].

use std::io::{Read, Write};
use std::sync::Mutex;
use std::sync::mpsc;
use std::thread;

use ed25519_dalek::SigningKey;
use rustls::crypto::cipher::{
    InboundOpaqueMessage, InboundPlainMessage, MessageDecrypter, MessageEncrypter,
    OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, make_tls13_aad,
};
use rustls::{ContentType, Error, ProtocolVersion};
use sha2::{Digest, Sha256};
use swanky_channel::Channel;
use swanky_error::Result as SwankyResult;

// NotaryBundle / RecordCommit are defined in `sp1-demo-common` so the SP1
// guest can verify the same struct without depending on this crate.
pub use sp1_demo_common::{NotaryBundle, RecordCommit};

use crate::aes::{
    NotaryCommit, client_decrypt_gcm_2pc, client_encrypt_gcm, notary_decrypt_gcm,
    notary_encrypt_gcm,
};

// ── TLS 1.3 per-record nonce / AAD (RFC 8446 §5.2, §5.3) ──────────────────────

/// Build the AEAD nonce for record `seq`: `base_iv XOR (0^32 || seq_be)`.
pub fn tls13_nonce(base_iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *base_iv;
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= *b;
    }
    nonce
}

/// Build the AAD for a TLS 1.3 record header given the *encrypted* payload
/// length (= inner plaintext + 1 type byte + 16 tag bytes).
pub fn tls13_aad(payload_len_after_enc: usize) -> [u8; 5] {
    let mut aad = [0u8; 5];
    aad[0] = 0x17; // application_data (RFC 8446 §5.2)
    aad[1] = 0x03;
    aad[2] = 0x03;
    let len = (payload_len_after_enc as u16).to_be_bytes();
    aad[3] = len[0];
    aad[4] = len[1];
    aad
}

// ── Standalone primitives ─────────────────────────────────────────────────────

/// Prover (client) holds its share of the TLS write key and IV.
/// Drives 2PC AES-GCM with the notary for each outbound TLS 1.3 record.
pub struct TwoPartyGcmEncrypter {
    k_c: [u8; 16],
    base_iv: [u8; 12],
}

impl TwoPartyGcmEncrypter {
    pub fn new(k_c: [u8; 16], base_iv: [u8; 12]) -> Self {
        Self { k_c, base_iv }
    }

    /// Encrypt one TLS 1.3 application_data record under split-key AES-GCM.
    /// `plaintext` is the inner TLS payload **without** the trailing 1-byte
    /// content-type marker (caller appends the type byte before calling).
    /// Returns `(ciphertext, tag)`.
    pub fn encrypt_record(
        &self,
        channel: &mut Channel,
        seq: u64,
        plaintext: &[u8],
        aad: &[u8],
    ) -> SwankyResult<(Vec<u8>, [u8; 16])> {
        let nonce = tls13_nonce(&self.base_iv, seq);
        client_encrypt_gcm(channel, self.k_c, plaintext, aad, nonce)
    }
}

/// Notary holds its share of the TLS write key and IV; it never sees plaintext.
pub struct NotaryTlsSession {
    k_n: [u8; 16],
    base_iv: [u8; 12],
}

impl NotaryTlsSession {
    pub fn new(k_n: [u8; 16], base_iv: [u8; 12]) -> Self {
        Self { k_n, base_iv }
    }

    /// Co-encrypt one record with the prover. `plaintext_len` and `aad` must
    /// match what the prover passes; the notary never sees the actual plaintext.
    pub fn encrypt_record(
        &self,
        channel: &mut Channel,
        seq: u64,
        plaintext_len: usize,
        aad: &[u8],
    ) -> SwankyResult<()> {
        let nonce = tls13_nonce(&self.base_iv, seq);
        notary_encrypt_gcm(channel, self.k_n, nonce, aad, plaintext_len)
    }

    /// Commit-before-reveal: notary signs `H(ciphertext, nonce, session_id)`
    /// BEFORE revealing `K_N` to the prover.
    pub fn commit_response(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        session_id: &[u8],
        signing_key: &[u8],
    ) -> NotaryCommit {
        NotaryCommit::new(ciphertext, nonce, session_id, signing_key)
    }

    /// Reveal step — call AFTER `commit_response`.
    pub fn reveal_key_share(&self) -> [u8; 16] {
        self.k_n
    }
}

// ── rustls hookup ─────────────────────────────────────────────────────────────
//
// rustls' `MessageEncrypter`/`MessageDecrypter` traits require `Send + Sync`,
// but swanky's `Channel` is `?Send` (it borrows a `dyn ReadWrite`). We bridge
// the two with a worker-thread + `mpsc::SyncSender` pattern:
//
//   ┌────────────────┐  encrypt/decrypt job ┌──────────────────────┐
//   │ rustls (sync)  │ ──── mpsc ─────────▶ │ 2PC worker thread    │
//   │ MessageEnc/Dec │ ◀─── mpsc ────────── │ owns swanky Channel  │
//   └────────────────┘  result               └──────────────────────┘
//                                                       │
//                                                       ▼ swanky 2PC
//                                              ┌──────────────────────┐
//                                              │ notary worker        │
//                                              └──────────────────────┘
//
// Wire protocol on the swanky channel — one frame per TLS record:
//
//     op (1 byte)         0x01 = encrypt, 0x02 = decrypt
//     seq (8 bytes BE)
//     aad_len (2 bytes BE)
//     aad (aad_len bytes)
//     payload_len (4 bytes BE)
//     <then 2PC encrypt/decrypt runs in lockstep on the channel>

const OP_ENCRYPT: u8 = 0x01;
const OP_DECRYPT: u8 = 0x02;
const OP_FINISH: u8 = 0x03;

struct Header {
    op: u8,
    seq: u64,
    aad: Vec<u8>,
    payload_len: u32,
}

fn write_header(ch: &mut Channel, h: &Header) -> SwankyResult<()> {
    ch.write_bytes(&[h.op])?;
    ch.write_bytes(&h.seq.to_be_bytes())?;
    ch.write_bytes(&(h.aad.len() as u16).to_be_bytes())?;
    ch.write_bytes(&h.aad)?;
    ch.write_bytes(&h.payload_len.to_be_bytes())?;
    ch.force_flush().map_err(|e| {
        swanky_error::swanky_error!(swanky_error::ErrorKind::NetworkError, "flush: {e}")
    })?;
    Ok(())
}

fn read_header(ch: &mut Channel) -> SwankyResult<Header> {
    let mut op = [0u8; 1];
    ch.read_bytes(&mut op)?;
    let mut seq_buf = [0u8; 8];
    ch.read_bytes(&mut seq_buf)?;
    let seq = u64::from_be_bytes(seq_buf);
    let mut aad_len_buf = [0u8; 2];
    ch.read_bytes(&mut aad_len_buf)?;
    let aad_len = u16::from_be_bytes(aad_len_buf) as usize;
    let mut aad = vec![0u8; aad_len];
    ch.read_bytes(&mut aad)?;
    let mut pl_buf = [0u8; 4];
    ch.read_bytes(&mut pl_buf)?;
    let payload_len = u32::from_be_bytes(pl_buf);
    Ok(Header { op: op[0], seq, aad, payload_len })
}

/// Drive the notary side of 2PC AES-GCM. See [`run_notary_worker_attested`]
/// for the variant that signs a session bundle at OP_FINISH.
pub fn run_notary_worker(
    channel: &mut Channel,
    k_n_tx: [u8; 16],
    iv_tx: [u8; 12],
    k_n_rx: [u8; 16],
    iv_rx: [u8; 12],
) -> SwankyResult<()> {
    run_notary_worker_inner(channel, None, k_n_tx, iv_tx, k_n_rx, iv_rx).map(|_| ())
}

/// Like [`run_notary_worker`] but also tracks a session log and signs a
/// [`NotaryBundle`] when the prover sends OP_FINISH.
///
/// Returns the bundle that was signed (and already written to the channel).
pub fn run_notary_worker_attested(
    channel: &mut Channel,
    signing_key: &SigningKey,
    k_n_tx: [u8; 16],
    iv_tx: [u8; 12],
    k_n_rx: [u8; 16],
    iv_rx: [u8; 12],
) -> SwankyResult<Option<NotaryBundle>> {
    run_notary_worker_inner(channel, Some(signing_key), k_n_tx, iv_tx, k_n_rx, iv_rx)
}

fn run_notary_worker_inner(
    channel: &mut Channel,
    signing_key: Option<&SigningKey>,
    k_n_tx: [u8; 16],
    iv_tx: [u8; 12],
    k_n_rx: [u8; 16],
    iv_rx: [u8; 12],
) -> SwankyResult<Option<NotaryBundle>> {
    let mut records: Vec<RecordCommit> = Vec::new();
    loop {
        let header = match read_header(channel) {
            Ok(h) => h,
            Err(_) => return Ok(None), // peer closed
        };
        match header.op {
            OP_ENCRYPT => {
                let nonce = tls13_nonce(&iv_tx, header.seq);
                notary_encrypt_gcm(
                    channel,
                    k_n_tx,
                    nonce,
                    &header.aad,
                    header.payload_len as usize,
                )?;
                let commit_hash = read_commit(channel, header.payload_len as usize)?;
                records.push(RecordCommit {
                    op: header.op,
                    seq: header.seq,
                    aad: header.aad.clone(),
                    commit_hash,
                });
            }
            OP_DECRYPT => {
                let nonce = tls13_nonce(&iv_rx, header.seq);
                notary_decrypt_gcm(
                    channel,
                    k_n_rx,
                    nonce,
                    header.aad.len(),
                    header.payload_len as usize,
                )?;
                let commit_hash = read_commit(channel, header.payload_len as usize)?;
                records.push(RecordCommit {
                    op: header.op,
                    seq: header.seq,
                    aad: header.aad.clone(),
                    commit_hash,
                });
            }
            OP_FINISH => {
                // session_id_len (2 BE) || session_id || server_name_len (2 BE) || server_name
                let mut sid_len = [0u8; 2];
                channel.read_bytes(&mut sid_len)?;
                let mut sid_buf = vec![0u8; u16::from_be_bytes(sid_len) as usize];
                channel.read_bytes(&mut sid_buf)?;
                let session_id = String::from_utf8(sid_buf).map_err(|_| {
                    swanky_error::swanky_error!(
                        swanky_error::ErrorKind::OtherError,
                        "session_id is not valid UTF-8"
                    )
                })?;
                let mut sn_len = [0u8; 2];
                channel.read_bytes(&mut sn_len)?;
                let mut sn_buf = vec![0u8; u16::from_be_bytes(sn_len) as usize];
                channel.read_bytes(&mut sn_buf)?;
                let server_name = String::from_utf8(sn_buf).map_err(|_| {
                    swanky_error::swanky_error!(
                        swanky_error::ErrorKind::OtherError,
                        "server_name is not valid UTF-8"
                    )
                })?;

                let Some(sk) = signing_key else {
                    swanky_error::bail!(
                        swanky_error::ErrorKind::OtherError,
                        "received OP_FINISH but the notary was not configured with a signing key"
                    );
                };

                let bundle = NotaryBundle::sign(
                    sk,
                    session_id,
                    server_name,
                    records,
                    k_n_tx,
                    iv_tx,
                    k_n_rx,
                    iv_rx,
                );
                let serialized = bincode::serialize(&bundle).map_err(|e| {
                    swanky_error::swanky_error!(
                        swanky_error::ErrorKind::OtherError,
                        "bincode serialize bundle: {e}"
                    )
                })?;
                channel.write_bytes(&(serialized.len() as u32).to_be_bytes())?;
                channel.write_bytes(&serialized)?;
                channel.force_flush().map_err(|e| {
                    swanky_error::swanky_error!(
                        swanky_error::ErrorKind::NetworkError,
                        "flush: {e}"
                    )
                })?;
                return Ok(Some(bundle));
            }
            other => {
                swanky_error::bail!(
                    swanky_error::ErrorKind::OtherError,
                    "rustls bridge: unknown op byte 0x{:02x}",
                    other
                );
            }
        }
    }
}

/// Read `payload_len` bytes of ciphertext + 16 bytes of tag from the channel
/// and return `SHA-256(ct || tag)`.
fn read_commit(channel: &mut Channel, payload_len: usize) -> SwankyResult<[u8; 32]> {
    let mut ct = vec![0u8; payload_len];
    channel.read_bytes(&mut ct)?;
    let mut tag = [0u8; 16];
    channel.read_bytes(&mut tag)?;
    let mut h = Sha256::new();
    h.update(&ct);
    h.update(tag);
    Ok(h.finalize().into())
}

enum ClientJob {
    Encrypt {
        plaintext: Vec<u8>,
        aad: Vec<u8>,
        seq: u64,
        respond: mpsc::SyncSender<Result<(Vec<u8>, [u8; 16]), String>>,
    },
    Decrypt {
        ciphertext: Vec<u8>,
        tag: [u8; 16],
        aad: Vec<u8>,
        seq: u64,
        respond: mpsc::SyncSender<Result<Vec<u8>, String>>,
    },
    Shutdown,
}

/// Owns the swanky channel + 2PC state on a worker thread. Drains [`ClientJob`]s
/// from an internal mpsc and dispatches to the 2PC AEAD functions.
pub struct ClientWorker {
    jobs: mpsc::SyncSender<ClientJob>,
    handle: Option<thread::JoinHandle<SwankyResult<()>>>,
}

impl ClientWorker {
    /// Spawn the worker thread. Takes ownership of a `Read + Write + Send`
    /// stream to the notary (typically `TcpStream`).
    ///
    /// `k_c_tx`/`iv_tx` are used for outbound (encrypt) records;
    /// `k_c_rx`/`iv_rx` for inbound (decrypt). TLS 1.3 derives separate
    /// keys per direction (RFC 8446 §7.3) — for unit tests where direction
    /// doesn't matter, pass the same key twice.
    pub fn spawn<S>(
        stream: S,
        k_c_tx: [u8; 16],
        iv_tx: [u8; 12],
        k_c_rx: [u8; 16],
        iv_rx: [u8; 12],
    ) -> Self
    where
        S: Read + Write + Send + 'static,
    {
        let (tx, rx) = mpsc::sync_channel::<ClientJob>(1);
        let handle = thread::spawn(move || -> SwankyResult<()> {
            Channel::with(stream, |ch| -> SwankyResult<()> {
                while let Ok(job) = rx.recv() {
                    match job {
                        ClientJob::Encrypt { plaintext, aad, seq, respond } => {
                            let result =
                                encrypt_one(ch, k_c_tx, iv_tx, &plaintext, &aad, seq);
                            let _ = respond.send(result.map_err(|e| format!("{e:?}")));
                        }
                        ClientJob::Decrypt {
                            ciphertext,
                            tag,
                            aad,
                            seq,
                            respond,
                        } => {
                            let result =
                                decrypt_one(ch, k_c_rx, iv_rx, &ciphertext, tag, &aad, seq);
                            let _ = respond.send(result.map_err(|e| format!("{e:?}")));
                        }
                        ClientJob::Shutdown => return Ok(()),
                    }
                }
                Ok(())
            })
        });
        ClientWorker { jobs: tx, handle: Some(handle) }
    }

    /// Boxed rustls `MessageEncrypter`. Safe to plug into a rustls cipher suite.
    pub fn make_encrypter(&self) -> Box<dyn MessageEncrypter> {
        Box::new(TwoPartyEncrypter { jobs: Mutex::new(self.jobs.clone()) })
    }

    pub fn make_decrypter(&self) -> Box<dyn MessageDecrypter> {
        Box::new(TwoPartyDecrypter { jobs: Mutex::new(self.jobs.clone()) })
    }

    pub fn shutdown(mut self) -> SwankyResult<()> {
        let _ = self.jobs.send(ClientJob::Shutdown);
        if let Some(h) = self.handle.take() {
            h.join().map_err(|_| {
                swanky_error::swanky_error!(
                    swanky_error::ErrorKind::OtherError,
                    "worker thread panicked"
                )
            })?
        } else {
            Ok(())
        }
    }
}

/// Encrypt one TLS record over a swanky channel paired with [`run_notary_worker`]
/// on the other side. Writes the bridge header (op=encrypt + seq + aad +
/// payload_len), then runs the 2PC encrypt.
pub fn client_encrypt_record(
    ch: &mut Channel,
    k_c: [u8; 16],
    base_iv: [u8; 12],
    plaintext: &[u8],
    aad: &[u8],
    seq: u64,
) -> SwankyResult<(Vec<u8>, [u8; 16])> {
    encrypt_one(ch, k_c, base_iv, plaintext, aad, seq)
}

/// Decrypt one TLS record over a swanky channel paired with [`run_notary_worker`].
pub fn client_decrypt_record(
    ch: &mut Channel,
    k_c: [u8; 16],
    base_iv: [u8; 12],
    ciphertext: &[u8],
    tag: [u8; 16],
    aad: &[u8],
    seq: u64,
) -> SwankyResult<Vec<u8>> {
    decrypt_one(ch, k_c, base_iv, ciphertext, tag, aad, seq)
}

fn encrypt_one(
    ch: &mut Channel,
    k_c: [u8; 16],
    base_iv: [u8; 12],
    plaintext: &[u8],
    aad: &[u8],
    seq: u64,
) -> SwankyResult<(Vec<u8>, [u8; 16])> {
    write_header(
        ch,
        &Header {
            op: OP_ENCRYPT,
            seq,
            aad: aad.to_vec(),
            payload_len: plaintext.len() as u32,
        },
    )?;
    let nonce = tls13_nonce(&base_iv, seq);
    let (ct, tag) = client_encrypt_gcm(ch, k_c, plaintext, aad, nonce)?;
    // Send ciphertext + tag so the notary can commit to them in its log.
    ch.write_bytes(&ct)?;
    ch.write_bytes(&tag)?;
    ch.force_flush().map_err(|e| {
        swanky_error::swanky_error!(swanky_error::ErrorKind::NetworkError, "flush: {e}")
    })?;
    Ok((ct, tag))
}

fn decrypt_one(
    ch: &mut Channel,
    k_c: [u8; 16],
    base_iv: [u8; 12],
    ciphertext: &[u8],
    tag: [u8; 16],
    aad: &[u8],
    seq: u64,
) -> SwankyResult<Vec<u8>> {
    write_header(
        ch,
        &Header {
            op: OP_DECRYPT,
            seq,
            aad: aad.to_vec(),
            payload_len: ciphertext.len() as u32,
        },
    )?;
    let nonce = tls13_nonce(&base_iv, seq);
    let plaintext = client_decrypt_gcm_2pc(ch, k_c, ciphertext, aad, tag, nonce)?;
    // Same commit: notary needs the same ct+tag bytes to compute the hash.
    ch.write_bytes(ciphertext)?;
    ch.write_bytes(&tag)?;
    ch.force_flush().map_err(|e| {
        swanky_error::swanky_error!(swanky_error::ErrorKind::NetworkError, "flush: {e}")
    })?;
    Ok(plaintext)
}

/// Send OP_FINISH and read back the signed [`NotaryBundle`] from the notary.
/// Must be called on the same channel that ran the session's 2PC operations.
pub fn client_finish_session(
    ch: &mut Channel,
    session_id: &str,
    server_name: &str,
) -> SwankyResult<NotaryBundle> {
    write_header(
        ch,
        &Header { op: OP_FINISH, seq: 0, aad: Vec::new(), payload_len: 0 },
    )?;
    ch.write_bytes(&(session_id.len() as u16).to_be_bytes())?;
    ch.write_bytes(session_id.as_bytes())?;
    ch.write_bytes(&(server_name.len() as u16).to_be_bytes())?;
    ch.write_bytes(server_name.as_bytes())?;
    ch.force_flush().map_err(|e| {
        swanky_error::swanky_error!(swanky_error::ErrorKind::NetworkError, "flush: {e}")
    })?;
    let mut len_buf = [0u8; 4];
    ch.read_bytes(&mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        swanky_error::bail!(
            swanky_error::ErrorKind::OtherError,
            "notary bundle suspiciously large: {len} bytes"
        );
    }
    let mut buf = vec![0u8; len];
    ch.read_bytes(&mut buf)?;
    bincode::deserialize(&buf).map_err(|e| {
        swanky_error::swanky_error!(
            swanky_error::ErrorKind::OtherError,
            "bincode deserialize bundle: {e}"
        )
    })
}

struct TwoPartyEncrypter {
    jobs: Mutex<mpsc::SyncSender<ClientJob>>,
}

impl MessageEncrypter for TwoPartyEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let aad = make_tls13_aad(total_len);
        let mut plaintext = Vec::with_capacity(msg.payload.len() + 1);
        msg.payload.copy_to_vec(&mut plaintext);
        plaintext.extend_from_slice(&msg.typ.to_array());

        let (resp_tx, resp_rx) = mpsc::sync_channel(1);
        self.jobs
            .lock()
            .unwrap()
            .send(ClientJob::Encrypt {
                plaintext,
                aad: aad.to_vec(),
                seq,
                respond: resp_tx,
            })
            .map_err(|_| Error::General("2PC worker channel closed".into()))?;
        let (ct, tag) = resp_rx
            .recv()
            .map_err(|_| Error::General("2PC response channel closed".into()))?
            .map_err(|e| Error::General(format!("2PC encrypt: {e}")))?;

        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_slice(&ct);
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + 16
    }
}

struct TwoPartyDecrypter {
    jobs: Mutex<mpsc::SyncSender<ClientJob>>,
}

impl MessageDecrypter for TwoPartyDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < 16 {
            return Err(Error::DecryptError);
        }
        let tag_start = payload.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&payload[tag_start..]);
        let ciphertext: Vec<u8> = payload[..tag_start].to_vec();
        let aad = make_tls13_aad(payload.len());

        let (resp_tx, resp_rx) = mpsc::sync_channel(1);
        self.jobs
            .lock()
            .unwrap()
            .send(ClientJob::Decrypt {
                ciphertext,
                tag,
                aad: aad.to_vec(),
                seq,
                respond: resp_tx,
            })
            .map_err(|_| Error::General("2PC worker channel closed".into()))?;
        let plaintext = resp_rx
            .recv()
            .map_err(|_| Error::General("2PC response channel closed".into()))?
            .map_err(|_| Error::DecryptError)?;

        let inner_buf: &mut [u8] = &mut *payload;
        inner_buf[..plaintext.len()].copy_from_slice(&plaintext);
        payload.truncate(plaintext.len());
        msg.into_tls13_unpadded_message()
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes;
    use std::net::{TcpListener, TcpStream};
    use swanky_channel::local::local_channel_pair;

    fn xor_keys(k_n: [u8; 16], k_c: [u8; 16]) -> [u8; 16] {
        std::array::from_fn(|i| k_n[i] ^ k_c[i])
    }

    /// End-to-end demo of the standalone prover/notary primitives.
    #[test]
    fn split_key_record_round_trip() {
        let k_c = [0x60u8; 16];
        let k_n = [0x2bu8; 16];
        let k = xor_keys(k_n, k_c);
        let base_iv = [0xcau8; 12];
        let seq: u64 = 7;
        let plaintext = b"POST /api HTTP/1.1\r\n\r\nhello";
        let aad = b"some-AAD";

        let prover = TwoPartyGcmEncrypter::new(k_c, base_iv);
        let notary = NotaryTlsSession::new(k_n, base_iv);

        let ((), (ct, tag)) = local_channel_pair(
            |ch| notary.encrypt_record(ch, seq, plaintext.len(), aad),
            |ch| prover.encrypt_record(ch, seq, plaintext, aad),
        )
        .expect("2PC record encryption");

        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes128Gcm, Key, Nonce,
        };
        let nonce = tls13_nonce(&base_iv, seq);
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&k));
        let reference = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
            .unwrap();
        assert_eq!(ct, &reference[..plaintext.len()]);
        assert_eq!(tag.as_slice(), &reference[plaintext.len()..]);
    }

    #[test]
    fn commit_before_reveal_flow() {
        let k_c = [0x11u8; 16];
        let k_n = [0x22u8; 16];
        let k = xor_keys(k_n, k_c);
        let nonce = [0xaau8; 12];
        let plaintext = b"server response body";

        use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Key, Nonce};
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&k));
        let server_ct = cipher.encrypt(Nonce::from_slice(&nonce), plaintext.as_ref()).unwrap();

        let notary = NotaryTlsSession::new(k_n, [0u8; 12]);
        let signing_key = b"notary-long-term-ed25519-or-hmac";
        let commit = notary.commit_response(&server_ct, &nonce, b"session-42", signing_key);
        assert!(commit.verify(&server_ct, &nonce, b"session-42", signing_key));

        let revealed = notary.reveal_key_share();
        assert_eq!(revealed, k_n);
        let plain = aes::client_decrypt(k_c, revealed, &server_ct, &nonce).expect("decrypt OK");
        assert_eq!(plain, plaintext);
    }

    /// End-to-end rustls bridge test: spawn the notary worker on a TCP socket,
    /// spawn the client worker, drive `MessageEncrypter`/`MessageDecrypter`
    /// directly (without a real rustls stack), and check the output matches
    /// the `aes-gcm` crate's TLS 1.3 record encryption.
    #[test]
    fn rustls_bridge_encrypt_decrypt_round_trip() {
        let k_n = [0x2bu8; 16];
        let k_c = [0x60u8; 16];
        let base_iv = [0xcau8; 12];

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let notary_handle = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let _ =
                Channel::with(stream, |ch| run_notary_worker(ch, k_n, base_iv, k_n, base_iv));
        });

        let stream = TcpStream::connect(addr).unwrap();
        stream.set_nodelay(true).unwrap();
        let worker = ClientWorker::spawn(stream, k_c, base_iv, k_c, base_iv);

        let mut encrypter = worker.make_encrypter();
        let mut decrypter = worker.make_decrypter();

        let inner_plaintext: &[u8] = b"GET /api/v1/balance HTTP/1.1\r\n";
        let seq: u64 = 7;

        // Encrypt one record through the rustls trait
        let outbound = OutboundPlainMessage {
            typ: ContentType::ApplicationData,
            version: ProtocolVersion::TLSv1_3,
            payload: inner_plaintext.into(),
        };
        let opaque = encrypter.encrypt(outbound, seq).expect("encrypt");
        let record_payload = opaque.payload.as_ref();
        assert_eq!(opaque.typ, ContentType::ApplicationData);
        assert_eq!(record_payload.len(), inner_plaintext.len() + 1 + 16);

        // Independent reference: AES-128-GCM with K = K_N XOR K_C
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes128Gcm, Key, Nonce,
        };
        let k = xor_keys(k_n, k_c);
        let nonce = tls13_nonce(&base_iv, seq);
        let aad = make_tls13_aad(record_payload.len());
        let mut inner_to_encrypt = inner_plaintext.to_vec();
        inner_to_encrypt.push(u8::from(ContentType::ApplicationData));
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&k));
        let reference = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload { msg: &inner_to_encrypt, aad: &aad },
            )
            .unwrap();
        assert_eq!(record_payload, &reference[..]);

        // Decrypt the same record through the bridge
        let mut buf = record_payload.to_vec();
        let inbound = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut buf,
        );
        let plain = decrypter.decrypt(inbound, seq).expect("decrypt");
        assert_eq!(plain.typ, ContentType::ApplicationData);
        assert_eq!(plain.payload, inner_plaintext);

        // Cleanly shut down
        drop(encrypter);
        drop(decrypter);
        worker.shutdown().expect("worker shutdown clean");
        notary_handle.join().expect("notary thread join");
    }

    /// Run an attested session over a local channel pair, then verify the
    /// signed bundle. Exercises:
    ///   - per-record commit frames being sent + read by the notary
    ///   - OP_FINISH frame + bincode bundle round-trip
    ///   - Ed25519 signature verification
    #[test]
    fn notary_bundle_round_trip() {
        use ed25519_dalek::SigningKey;
        use rand::RngCore;

        let k_n = [0xaau8; 16];
        let k_c = [0xbbu8; 16];
        let iv = [0xccu8; 12];

        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let signing_key = SigningKey::from_bytes(&seed);
        let expected_pubkey = signing_key.verifying_key().to_bytes();

        let (notary_bundle_opt, client_bundle) = local_channel_pair(
            |ch| {
                // Notary: drive worker; expect bundle returned at OP_FINISH
                run_notary_worker_attested(ch, &signing_key, k_n, iv, k_n, iv)
            },
            |ch| -> SwankyResult<NotaryBundle> {
                // Client: do one encrypt + one decrypt + finish.
                // For a round-trip with the SAME k/iv we must use the SAME
                // seq for both directions (real TLS uses separate keys
                // per direction so seqs are independent; this test isn't TLS).
                let pt = b"hello, attested world";
                let aad = b"record-aad";
                let (ct, tag) = encrypt_one(ch, k_c, iv, pt, aad, 0)?;
                let plain = decrypt_one(ch, k_c, iv, &ct, tag, aad, 0)?;
                assert_eq!(plain, pt);
                client_finish_session(ch, "test-session-1", "test.example.com")
            },
        )
        .expect("attested 2PC session");

        let notary_bundle = notary_bundle_opt.expect("notary should have built a bundle");

        // Notary's view and the client's view of the bundle must agree.
        assert_eq!(notary_bundle.notary_pubkey, client_bundle.notary_pubkey);
        assert_eq!(notary_bundle.signature, client_bundle.signature);
        assert_eq!(notary_bundle.records.len(), client_bundle.records.len());

        // Pubkey matches the signing key we set up
        assert_eq!(client_bundle.notary_pubkey, expected_pubkey);

        // Session metadata is what we passed
        assert_eq!(client_bundle.session_id, "test-session-1");
        assert_eq!(client_bundle.server_name, "test.example.com");

        // We did 1 encrypt + 1 decrypt (both at seq=0 for this self-test)
        assert_eq!(client_bundle.records.len(), 2);
        assert_eq!(client_bundle.records[0].op, 0x01);
        assert_eq!(client_bundle.records[0].seq, 0);
        assert_eq!(client_bundle.records[1].op, 0x02);
        assert_eq!(client_bundle.records[1].seq, 0);

        // Signature verifies
        assert!(client_bundle.verify(), "bundle signature must verify");

        // Tampering breaks verification
        let mut bad = client_bundle.clone();
        bad.session_id.push('x');
        assert!(!bad.verify(), "tampered bundle must not verify");

        let mut bad2 = client_bundle.clone();
        bad2.records[0].commit_hash[0] ^= 0xff;
        assert!(!bad2.verify(), "tampered commit hash must not verify");
    }
}
