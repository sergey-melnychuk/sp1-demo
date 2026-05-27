# TODO — toward production-grade zkTLS

## Status (what's built in `notary/`)

**Production-ish witness path** for mode 2 — not full malicious-security MPC. See
[Trust model gaps](#trust-model-gaps-why-this-is-not-prod-ready) below.

### Demo modes (`notary_demo` ↔ `notary_proxy`)

| Mode | Setup byte | Flag | Record-layer keys |
|------|------------|------|-------------------|
| Legacy | `0` | `--legacy-host-xor-masks` | rustls extract → XOR split |
| Default | `1` | *(none)* | same; split ephemeral + post-IV OT ECDH |
| 2PC schedule | `2` | `--two-pc-traffic-keys` | **2PC HKDF** from OT IKM XOR shares; notary verifies raw handshake |

Mode 2 E2E: host sends [`HandshakeCapture`](notary/src/handshake.rs) (raw bytes +
cert hash + epk); notary runs `verify_handshake_capture` after ECDH; then 2PC HKDF
and AES records. Signed **NotaryBundle v1** includes [`SessionBinding`](common/src/lib.rs).
Verify with `notary_verify` or SP1 guest (transcript hash + epk checks).

Docs: [`DEMO.md`](DEMO.md), ECDH wire: [`ECDH.md`](ECDH.md).

### Working primitives

- **`handshake.rs`** — mode-2 capture wire; notary-side transcript + cert verify.
- **`aes.rs`** — split-key 2PC AES-GCM (semi-honest); byte-identical to `aes-gcm`.
- **`hkdf.rs`** — 2PC HMAC/HKDF via **one garbler session per SHA-256 compress**
  (chains XOR output shares between HMAC rounds); full TLS 1.3 client traffic schedule.
- **`ecdh.rs`** — OT-blinded ECDH (default); TLS-correct IKM via `reference_ikm`.
- **`transcript.rs`** — handshake hash parsing (host + notary).
- **`tls.rs`** — record bridge, attested worker, `OP_2PC_HKDF`.
- **`common::NotaryBundle`** — v0 legacy + **v1 `SessionBinding`** in signature.
- **`notary_verify`** — standalone bundle + optional witness cross-check.
- **`garble.rs`** — WRK17 helpers + `SplitSharedInputMaskCircuit`; HKDF + per-block AES wired.

### Tests

`cargo test --lib --release` — **28 passed** (~12 s). Includes WRK17 compress
round-trip, TCP/local ECDH→HKDF integration, signed bundle v1.

---

## Trust model gaps (why this is not prod-ready)

Three structural issues block third-party or malicious-security claims:

| Gap | Today | Why it matters |
|-----|--------|----------------|
| **Host-side handshake parser** | **Fixed (mode 2):** host sends raw bytes; notary verifies in `handshake.rs`. Host still uses local `reference_ikm` for optional rustls cross-check only. | Malicious host cannot lie about transcript for mode 2 HKDF binding. |
| **Trusted-notary semantics** | Bundle v1 signs `SessionBinding` (cert hash, transcript root, epk, circuit IDs). `notary_verify` + guest checks. Notary still learns full IKM. | Verifier can check signature + witness fields; not full MPC secrecy. |
| **Semi-honest garbling** | HKDF + AES blocks use **WRK17**; GHASH (AND gates) stays semi-honest in one session per encrypt/decrypt. | Malicious garbler can still cheat on GHASH until that moves to WRK17. |

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

#### 1. Host-side handshake parser → notary-side verification — **done (mode 2)**

- Wire: [`HandshakeCapture`](notary/src/handshake.rs) (epk, cert hash, raw outbound/inbound).
- Notary: `verify_handshake_capture` after ECDH; abort before `OP_2PC_HKDF`.

#### 2. Trusted-notary semantics — **witness path largely done**

**Witness path (A):**

- **Done:** `SessionBinding` in NotaryBundle v1; `notary_verify` CLI; guest transcript/epk checks.
- **Still missing:** TLS to notary daemon; k-of-n threshold.

**2PC path (B):** OT-MtA, drop `ikm_full`, incremental schedule — unchanged.

#### 3. Semi-honest garbling — **HKDF + AES blocks done; GHASH semi-honest**

- **Done:** per-compress HMAC sessions (WRK17); per-block AES (WRK17) with semi-honest GHASH.
- **Next:** WRK17 GHASH (optional; AND-heavy, one session per record today).

**Minimum “production-ish” bar:** items 1 + witness 2 **done**; item 3 **HKDF + AES blocks done**.

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

### 2. Authenticated garbling *(HKDF + AES blocks done; GHASH semi-honest)*

`swanky-authenticated-garbling` (WRK17) for HKDF compress and each AES-128 block in
GCM. `SplitSharedInputMaskCircuit` + `wrk17_*_masked_run` in `garble.rs`. GHASH
(128×128 AND mul) remains on one semi-honest garbler/evaluator pair per encrypt/decrypt.

### 3. Signed attestation *(witness path — done for v1)*

**Done:** `NotaryBundle` v1 + `SessionBinding`; Ed25519 sign/verify; per-record commits;
`notary_verify`; guest transcript/epk alignment.

**Still missing:** pinned notary TLS; formal publication of binding semantics.

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

### 8. Handshake binding in attestation — **done (mode 2)**

Raw handshake capture + notary verify + `SessionBinding` in signed bundle.

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

1. **WRK17 GHASH** (optional) or OT-MtA ECDH (#1 completion).
2. **OT-MtA ECDH + incremental 2PC schedule** — true split IKM (#1 completion).
3. **Selective disclosure** — privacy upside (#5).
4. Performance (#9–#10) + operational (#11–#15).

Items 1–4 are each non-trivial. Public [`tlsnotary/tlsn`](https://github.com/tlsnotary/tlsn) +
[`mpz`](https://github.com/privacy-scaling-explorations/mpz) represent years of work on overlapping problems.

**Current demo is suitable for:** internal PoC, protocol debugging, circuit/integration tests, SP1 pipeline experiments.

**Not suitable for:** production notary service, untrusted third-party verification, or malicious-host/security claims without items 1–3.
