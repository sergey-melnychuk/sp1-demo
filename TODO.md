# TODO — toward production-grade zkTLS

## Status (what's already built in `notary/`)

End-to-end zkTLS demo works against a real HTTPS server (`jsonplaceholder.typicode.com`):
TLS 1.3 handshake → `dangerous_extract_secrets()` → split keys with notary → every
application record encrypted/decrypted via split-key 2PC AES-GCM over a swanky channel.
See `notary/src/bin/notary_demo.rs` + `notary/src/bin/notary_proxy.rs`.

Inventory of working primitives:

- `aes.rs` — split-key 2PC AES-GCM encrypt + decrypt with AAD and partial last blocks;
  byte-identical to the `aes-gcm` crate. Constant-time tag check (currently outside the
  circuit; see gap #4 below).
- `hkdf.rs` — 2PC HMAC-SHA256, HKDF-Extract, HKDF-Expand-Label. Asymmetric input split:
  notary only learns msg length, client provides the bytes. Built on a from-scratch
  SHA-256 compression Bristol circuit (`circuits/sha-256-compress.txt`, 127k gates,
  validated against `sha2::compress256`).
- `ecdh.rs` — additive-share X25519. Math correct. **Partials leak** — both parties
  exchange `P_n` and `P_c` in the clear, so both learn the IKM. Tracked as gap #1.
- `tls.rs` — TLS 1.3 nonce/AAD helpers, standalone primitives (`TwoPartyGcmEncrypter`,
  `NotaryTlsSession`), commit-before-reveal, **rustls bridge** with worker thread +
  `MessageEncrypter`/`MessageDecrypter` (Send+Sync), and `run_notary_worker` for the
  notary side. Per-direction (tx/rx) keys.
- `notary_demo` + `notary_proxy` binaries — end-to-end demo against a real HTTPS server.

11/11 tests pass (AES round-trip, AAD+partial blocks, HMAC/HKDF, ECDH math, commit-reveal,
rustls bridge round-trip).

---

## Cryptographic gaps (the protocol)

### 1. ECDH 2PC over Curve25519  *(blocking the security claim)*
Host briefly has `K` during the handshake before zeroizing — a malicious host could
capture `K` there and lie afterward. Closing this needs OT-based MtA share-conversion
over Curve25519's prime field, plus Edwards point addition on shares. No primitive in
swanky; `mpz` has it. Roughly ~1500–2000 lines of new MPC protocol code. Until this
ships, the "host never has K" property only holds *after* `zeroize()`.

### 2. Authenticated garbling  *(blocking third-party trust)*
Today the bridge uses `swanky-twopac::semihonest`. A malicious garbler can submit a
different circuit and the evaluator can't detect it — fine if the notary is trusted,
not fine if the attestation must be verifiable by anyone. Migrate to
`swanky-authenticated-garbling` (WRK17): `AuthenticatedWireMod2`, preprocessing
phase, different `Garbler<RNG>`/`Evaluator` types. Roughly 3–10× more bandwidth.
Likely a full session of API rewiring.

### 3. Signed attestation  *(blocking publication)*
There is no Ed25519-signed bundle leaving the demo. The notary should sign
`(session_id, server_cert_chain, transcript_hash, ciphertext, timestamp)` with a
long-term key; a verifier later checks the signature + the cert chain.

### 4. Tag-mismatch side-channel
`client_decrypt_gcm_2pc` returns `Result::Err` on tag failure. The fact that
decryption errored leaks one bit. In a malicious model the comparison should be
inside the circuit and the abort path indistinguishable from success.

### 5. Selective disclosure  *(the actual product value-add)*
Notary currently attests to the **whole transcript**. TLSNotary's real upside is
proving a substring (`"balance": "$500"`) without revealing the rest. Needs Merkle
commits per record + a zk-SNARK (Plonk / Halo2 / sp1-style proof) for substring
proofs.

---

## TLS plumbing gaps

### 6. Session tickets, key updates, post-handshake rekeying
`dangerous_extract_secrets()` is deprecated for exactly these reasons. Production
record layer must track when rustls would have rolled keys forward and rerun the
key-derivation under 2PC (which requires #1 to be done first).

### 7. Sequential records only
Demo encrypts one record then waits. Real TLS pipelines. Needs a send/recv state
machine that can interleave concurrent encrypt/decrypt ops on the worker.

### 8. Handshake is not 2PC
Even after #1, the certificate-validation flow needs to feed back into the
attestation so the verifier knows *who* this transcript is from. Today the demo
trusts rustls' built-in cert validation but doesn't surface it in the (non-existent)
signed bundle.

---

## Performance

### 9. OT bootstrap per record
Every `client_encrypt_gcm` re-runs OT initialization (≈10–100ms). Use OT extension
(swanky has `swanky-ot-alsz-kos`) with amortized setup. Likely 10–100× faster.

### 10. ~100k AND gates per record
A 50 KB JSON response (~3300 records) → minutes of 2PC end-to-end. Need: batching
multiple records into one circuit invocation, parallel record handling, faster
channel (currently a single TCP socket). Production targets are 100ms–1s per
session, not minutes.

---

## Operational

### 11. Notary auth + identity
Host connects to "whatever is at 127.0.0.1:9001". Production: TLS to the notary,
identity pinning, possibly threshold-signed bundles across N notaries.

### 12. Memory hygiene
`zeroize` is called on `tx_key`/`rx_key`, but Rust's optimizer can copy stack values
without zeroing them. Use `secrecy::SecretBox` or pinned/locked memory.

### 13. Replay / nonce tracking
Nothing stops the host running many sessions with the same K shares — the notary
should track session nonces.

### 14. HTTP layer
Currently dumps raw HTTP. Need proper HTTP/1.1 parsing, chunked decoding, gzip,
content-length verification.

### 15. Formal review / fuzzing / constant-time audit
Standard production hygiene; none done.

---

## Realistic priority order for shipping

If treating this as a roadmap toward a real product:

1. **ECDH 2PC** — without it the security claim is fake.
2. **Signed attestation + verifier tool** — without it nobody outside the host can use the result.
3. **Selective disclosure** — without it there's no privacy upside over "just publish the transcript".
4. **Authenticated garbling** — needed for third-party trust, not for self-attestation.
5. Performance (OT extension, batching) + everything else.

Items 1–4 are each non-trivial protocol/engineering projects. The public
`tlsnotary/tlsn` + `privacy-scaling-explorations/mpz` projects represent multiple
years of work on exactly these.
