# TODO — toward production-grade zkTLS

## Status (what's built in `notary/`)

**Not production-ready** — working research demo / PoC. See [Trust model gaps](#trust-model-gaps-why-this-is-not-prod-ready) below.

### Demo modes (`notary_demo` ↔ `notary_proxy`)

| Mode | Setup byte | Flag | Record-layer keys |
|------|------------|------|-------------------|
| Legacy | `0` | `--legacy-host-xor-masks` | rustls extract → XOR split |
| Default | `1` | *(none)* | same; split ephemeral + post-IV OT ECDH |
| 2PC schedule | `2` | `--two-pc-traffic-keys` | **2PC HKDF** from OT IKM XOR shares + transcript hashes; host skips extract for records |

Mode 2 E2E verified against real HTTPS (`jsonplaceholder.typicode.com`): HTTP 200, decrypt OK,
signed bundle verifies. Optional `--verify-rustls-keys` cross-checks 2PC HKDF vs rustls extract.

Docs: [`DEMO.md`](DEMO.md), ECDH wire: [`ECDH.md`](ECDH.md).

### Working primitives

- **`aes.rs`** — split-key 2PC AES-GCM encrypt/decrypt with AAD; byte-identical to `aes-gcm`.
  Tag check outside circuit (gap #4).
- **`hkdf.rs`** — 2PC HMAC-SHA256, HKDF-Extract, HKDF-Expand-Label; XOR-shared 32-byte IKM;
  full TLS 1.3 **client app traffic** schedule (`tls13_traffic_2pc_matches_reference`).
  SHA-256 compress Bristol circuit (`circuits/sha-256-compress.txt`).
- **`ecdh.rs`** — additive scalar shares; **OT-blinded** point addition (default wire);
  leaky cleartext partials (debug); TLS-correct IKM via `reference_ikm` (RFC 7748 clamp).
  Wire: `SETUP_ECDH_* ‖ server_epk (32) ‖ host_clamped_share (32) ‖ …`.
  **Not** full OT-MtA — notary still reconstructs full IKM (trusted demo).
- **`transcript.rs`** — TLS 1.3 handshake transcript hashes (`after_sh`, `after_sf`) for key schedule;
  used on **host** in mode 2; notary receives precomputed 64 B digests only.
- **`tls.rs`** — record bridge (`OP_ENCRYPT` / `OP_DECRYPT` / `OP_FINISH` / `OP_2PC_HKDF`),
  `run_notary_worker_attested` / `run_notary_worker_attested_2pc`, rustls bridge, commit-before-reveal.
- **`common::NotaryBundle`** — Ed25519-signed attestation (session id, SNI, per-record commit hashes,
  notary key shares + IVs). Host receives bundle at `OP_FINISH`; `verify()` in guest/tests.

### Tests

`cargo test -p notary --lib` — **25 passed**, 1 ignored (~75 s release profile). Includes AES/HKDF/ECDH
unit tests, rustls bridge round-trip, signed bundle verification, and TCP/local integration tests for
ECDH → 2PC HKDF (`tls::tests::hkdf_over_*`).

---

## Trust model gaps (why this is not prod-ready)

Three structural issues block third-party or malicious-security claims:

| Gap | Today | Why it matters |
|-----|--------|----------------|
| **Host-side handshake parser** | Host runs `transcript_hashes_with_ikm` locally; sends `after_sh ‖ after_sf` (64 B). Notary trusts host digests. | Malicious host can lie about transcript → wrong keys while still passing 2PC AES with notary. |
| **Trusted-notary semantics** | Notary learns full IKM (OT path), public IVs, plaintext-side commits; host sends clamped scalar on wire. Bundle signs notary's view, not independently verifiable MPC. | Verifier must trust notary RAM and honest computation, not just cryptography. |
| **Semi-honest garbling** | `swanky-twopac::semihonest` in `aes.rs` / `hkdf.rs`. | Malicious garbler can cheat; evaluator cannot detect wrong circuits. |

### Rationale

These gaps compose: even with mode 2 (no host extract for **record** keys), the host still
**asserts** the handshake context the HKDF binds to. The notary **computes** 2PC AES/HKDF honestly
but cannot **verify** the binding without raw handshake bytes or incremental 2PC schedule. Semi-honest
garbling means a malicious notary (or corrupted notary process) could deviate from the published
circuits without detection.

**Two product paths** (not mutually exclusive long-term):

1. **TLSNotary-style witness (faster)** — Notary is an independent witness: signs commits to
   **observed** wire bytes + record ciphertext hashes + server identity. Verifier checks signature
   + recomputes commits. Notary may learn IKM; trust shifts to signature + transparency, not MPC secrecy.

2. **True 2PC notary (harder)** — Neither party holds full IKM or traffic keys; OT-MtA X25519;
   incremental 2PC key schedule; authenticated garbling. Required for “host never knew K” and
   “notary never knew K” simultaneously.

### Recommended fix order

```
Raw handshake → notary     (remove host digest trust)
       ↓
Richer signed bundle       (cert chain, transcript root, circuit IDs)
       ↓
Authenticated garbling   (remove “trust notary MPC”)
       ↓
OT-MtA ECDH + incremental 2PC schedule   (remove host scalar leak + notary full IKM)
```

#### 1. Host-side handshake parser → notary-side verification *(do first)*

- **Wire change (mode 2):** after handshake, host sends length-prefixed `raw_outbound ‖ raw_inbound`
  (handshake bytes only), not precomputed `after_sh ‖ after_sf`.
- **Notary:** run `transcript.rs` locally; recompute hashes before `OP_2PC_HKDF`.
- **IKM dependency:** `after_sf` needs IKM to decrypt ClientFinished — use XOR shares after OT ECDH
  (`reference_ikm` from wire scalars short-term), or run key schedule **incrementally in 2PC**
  (hs secrets → decrypt CF → hash → app traffic) long-term.
- **Abort** if notary hashes ≠ inputs to 2PC HKDF.

#### 2. Trusted-notary semantics

**Witness path (A):**

- Extend `NotaryBundle`: `cert_chain_hash`, `handshake_transcript_hash`, `server_epk`, circuit hashes.
- Notary signs only bytes/commits it observed during the session.
- Standalone `notary_verify` tool for third parties.
- TLS + pinned identity to notary daemon (ops #11).

**2PC path (B):**

- Remove `host_clamped_share` on wire → OT-MtA (gap #1).
- Drop `TwoPcTrafficSetup.ikm_full` outside tests; notary holds `ikm_n` only.
- Remove host `reference_ikm` oracle from mode 2 demo path.
- Optional k-of-n notary threshold on bundle.

#### 3. Semi-honest garbling

- Migrate to `swanky-authenticated-garbling` (WRK17): `AuthenticatedWireMod2`, session preprocessing.
- Pin circuit hashes (AES, SHA-256 compress) in signed bundle.
- Move GCM tag verify into circuit (gap #4); amortize OT per session (gap #9).

**Minimum “production-ish” bar** (before full MtA): items 1 + witness-path 2 + authenticated garbling.

---

## Cryptographic gaps (the protocol)

### 1. ECDH 2PC over Curve25519 *(blocking “neither party knows K”)*

**Partial progress (mode 2):** OT-blinded ECDH + XOR IKM shares + 2PC HKDF for **application**
traffic keys without host `dangerous_extract_secrets()` for records. Host still uses split
ephemeral + local transcript oracle; notary learns full IKM; host sends clamped scalar on wire.

**Still needed:** OT-based MtA share-conversion over Curve25519, Edwards point addition on
shares (~1500–2000 LOC; no swanky primitive — see `mpz`). Until then:

- Mode 1: host briefly holds full AES keys between extract and `zeroize()`.
- Mode 2: host never extracts record keys, but still knows full IKM locally for transcript parsing.

### 2. Authenticated garbling *(blocking third-party trust in MPC)*

`swanky-twopac::semihonest` throughout. Malicious garbler can submit a different circuit.
Migrate to authenticated garbling (3–10× bandwidth; full `aes.rs` / `hkdf.rs` API rewiring).
See [Trust model §3](#3-semi-honest-garbling).

### 3. Signed attestation *(witness path — largely done)*

**Done:** `NotaryBundle` + Ed25519 sign/verify; per-record commit hashes; `OP_FINISH` round-trip;
tests in `tls::tests::notary_bundle_round_trip`.

**Still missing for publication-grade attestation:**

- Server **certificate chain** in bundle (or hash thereof).
- **Handshake transcript root** (not host-asserted digests alone).
- Standalone **verifier CLI** / SP1 guest alignment for full bundle fields.
- Circuit identity hashes in signed payload.

### 4. Tag-mismatch side-channel

`client_decrypt_gcm_2pc` returns `Err` on tag failure → leaks one bit. Compare inside circuit;
indistinguishable abort in malicious model.

### 5. Selective disclosure *(product value-add)*

Whole-transcript attestation only. TLSNotary-style substring proofs need Merkle commits per record
+ zk proof (Plonk / Halo2 / SP1).

---

## TLS plumbing gaps

### 6. Session tickets, key updates, post-handshake rekeying

Mode 2 avoids one-shot extract for app keys but does not track rustls rekey / NewSessionTicket
epochs. Production record layer must rerun 2PC derivation on key updates (depends on #1).

### 7. Sequential records only

One record encrypt/decrypt at a time. Need pipelined state machine on the worker thread.

### 8. Handshake binding in attestation *(partial — see trust model)*

rustls validates certs on host; **not** surfaced in bundle. Mode 2 sends **host-computed**
transcript hashes to notary — not raw handshake bytes. Fix: [§1 Host-side handshake parser](#1-host-side-handshake-parser--notary-side-verification-do-first).

---

## Performance

### 9. OT bootstrap per record / HKDF round

Each `Garbler::new` re-runs OT init (~10–100 ms). Amortize with OT extension (`swanky-ot-alsz-kos`)
+ one authenticated preprocessing per session. Critical for mode 2 (many HKDF rounds before AES).

### 10. ~100k AND gates per record

Large responses → minutes of 2PC. Batching, parallel records, faster channel. Target: 100 ms–1 s
per session for prod.

---

## Operational

### 11. Notary auth + identity

Plain TCP to `127.0.0.1:9001`. Need TLS to notary, pinning, optional threshold notaries.

### 12. Memory hygiene

`zeroize` on keys; optimizer may copy stack secrets. Prefer `secrecy::SecretBox` / locked memory.

### 13. Replay / session tracking

No notary-side session nonce / replay policy.

### 14. HTTP layer

Raw HTTP dump only — no chunked/gzip/redirect handling.

### 15. Formal review / fuzzing / constant-time audit

Not started.

---

## Priority order for shipping

If treating this as a roadmap toward a real product:

1. **Notary-side transcript verification** — raw handshake bytes; remove host digest trust.
2. **Richer signed bundle + verifier tool** — cert chain, transcript root, circuit IDs (#3 remainder, #8).
3. **Authenticated garbling** — third-party trust in MPC (#2).
4. **OT-MtA ECDH + incremental 2PC schedule** — true split IKM (#1 completion).
5. **Selective disclosure** — privacy upside over publishing full transcript (#5).
6. Performance (#9–#10) + operational (#11–#15).

Items 1–4 are each non-trivial. Public [`tlsnotary/tlsn`](https://github.com/tlsnotary/tlsn) +
[`mpz`](https://github.com/privacy-scaling-explorations/mpz) represent years of work on overlapping problems.

**Current demo is suitable for:** internal PoC, protocol debugging, circuit/integration tests, SP1 pipeline experiments.

**Not suitable for:** production notary service, untrusted third-party verification, or malicious-host/security claims without items 1–3.
