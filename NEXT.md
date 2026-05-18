# NEXT — Roadmap from demo to production-oriented zkTLS prover

This document collects **implementation-ready** notes on what remains open after the `GUEST_TLS` refactor completed on 2026-05-18. The host is now a dumb relay; the guest independently derives all TLS keys and parses all messages from raw wire bytes. The trust gap (host-supplied key material) is closed.

For task bullets, see [`TODO.md`](TODO.md). For architecture and design decisions, see [`PLAN.md`](PLAN.md).

---

## 1. Executive summary

### 1.1 What the remaining pillars buy you

| Pillar | Problem it fixes | Does not fix |
|--------|------------------|--------------|
| **Freshness** | TLS/session replay and "pick the best historical response" | Malicious prover logging secrets off-machine; proof-layer replay |
| **Integer / fixed-scale values** | `f64` precision loss for financial amounts | Ambiguity of JSON number ↔ domain type without a schema |
| **HTTP completeness** | Host omitting tail application-data records | Replay of a complete historical session |
| **Stricter PKIX** | Accepting chains a conservative HTTPS client would reject | Revocation without OCSP/CRL or out-of-band policy |

### 1.2 "Production candidate" bar

Implementing **§2–§5** below moves the repo toward a **production candidate for a narrowly specified product**. **Production ready** also requires **§6** (operations, threat-model documentation, testing, audits). Neither milestone removes **delegated-proving** concerns — see [`TODO.md` — Future Directions](TODO.md).

---

## 2. Freshness (replay and cherry-picking)

### 2.1 Threat model

- **TLS replay:** An old witness/proof remains cryptographically valid forever unless the **statement** binds time or nonce.
- **Cherry-picking:** The prover runs many fetches and submits the proof where the asserted field is most favourable.

### 2.2 Recommended statement shape

Commit as **public outputs** (alongside existing [`PublicClaim`](shared/src/lib.rs)):

- **`now_unix`**: reference wall time agreed with the verifier (currently stored in `TlsWitness.now_unix` but not yet asserted in the guest).
- **`freshness_field`** / **`freshness_window`**: rules such as `server_time ≥ now - window` to bound stale responses.

Example already sketched in [`TODO.md`](TODO.md): Binance-style JSON with `/serverTime` (milliseconds).

### 2.3 Implementation notes

**CLI / host (`script/src/main.rs`):**

- Add flags: `--freshness-field`, `--freshness-window-past-secs`, `--now` (optional override for testing).
- `now_unix` is already captured and passed in `TlsWitness`; wire it through to the guest assertion.

**Guest (`program/src/main.rs`):**

- After parsing JSON, read the freshness field and compare against `witness.now_unix` with explicit skew tolerance.
- Document units (seconds vs milliseconds) per API.

**Verifier:**

- Must reject proofs where committed `now_unix` is implausible (e.g. far in the future) under their own policy.

---

## 3. Integers and thresholds (replace `f64`)

### 3.1 Problem

[`PublicClaim`](shared/src/lib.rs) and the guest assertion use `f64`. IEEE doubles lose precision beyond ~15 decimal digits — wrong for balances, prices, or satoshi-scale amounts.

### 3.2 Options

1. **Scaled integers** — CLI accepts `--threshold-satoshi` / `--field-scale 10000`; guest compares `i128` or `u128` after parsing JSON number string with explicit rounding mode.
2. **String / decimal crate** — Parse JSON string fields with a fixed-precision decimal type (`rust_decimal`) if available under zkVM constraints.
3. **Integer JSON values only** — `serde_json::Number` → `as_u64()` / big-int if the API uses integer JSON numbers.

### 3.3 Implementation notes

- Extend [`PublicClaim`](shared/src/lib.rs): add `value_i128`, `threshold_i128`, `scale` or use string commitments.
- Align host CLI validation with guest (reject ambiguous inputs before proving).
- Add tests around boundary values and negative amounts.

---

## 4. HTTP response completeness and transcript tightness

### 4.1 What remains open

The guest's AES-GCM decryption loop catches **middle-record omissions** automatically (wrong sequence number → wrong nonce → wrong GCM tag → auth failure). It does **not** catch **tail omission**: the host could silently withhold the last N application-data records and the guest would process a partial HTTP response.

Additionally:

| Area | File | Risk |
|------|------|------|
| Tail omission | [`program/src/main.rs`](program/src/main.rs) app-record loop | Host withholds last N records; partial body may be valid JSON |
| Chunked empty body | [`program/src/main.rs`](program/src/main.rs) `unchunk` | `0\r\n\r\n` edge case → unchunk returns raw string → JSON panic |
| Guest errors | Whole guest | Panics only; no structured error committed as public output |

### 4.2 Recommended work

1. **HTTP response completeness** — after decrypting all app records, verify the HTTP body is terminated:
   - For `Content-Length`: assert `plaintext_body.len() == content_length`.
   - For `Transfer-Encoding: chunked`: assert the terminal `0\r\n\r\n` chunk was parsed by `unchunk`.

2. **Fix `unchunk` empty-response** — if no chunks are collected, return an error instead of the raw string.

3. **`Result` in guest for HTTP/JSON** — map parse/decode errors to committed failure codes rather than panics (if the SP1 proving UX supports graceful abort with public error enum).

---

## 5. Stricter PKIX

### 5.1 What the guest does today

[`program/src/main.rs`](program/src/main.rs):

- Validates chain signatures to Mozilla anchors (`webpki-roots`) using two trust-anchor matching strategies (subject match; last-cert issuer match for cross-signed roots).
- Verifies leaf **SAN** hostname (exact and wildcard).
- Verifies CertificateVerify with the leaf cert's public key.

### 5.2 What "stricter PKIX" adds

| Check | Why | Notes for zkVM |
|-------|-----|----------------|
| **Validity** `notBefore` / `notAfter` | Reject expired / not-yet-valid certs | Requires committed `now_unix` (align with §2) |
| **Basic constraints** | CA vs EE; `pathLenConstraint` | Reject EE acting as CA |
| **Key usage** | TLS leaf needs `digitalSignature` | Match CA/B Forum expectations |
| **Extended key usage** | `serverAuth` (OID 1.3.6.1.5.5.7.3.1) | Reject leaves without EKU or with wrong EKU |
| **Critical unknown extensions** | RFC 5280 §4.2 | Reject if critical extension cannot be processed |

### 5.3 Revocation (out of scope unless you add infrastructure)

- OCSP: RFC 6960 — too expensive in-guest; consider short-lived certs or out-of-band revocation lists committed as public inputs.

### 5.4 References

- PKIX profile: RFC 5280 — <https://www.rfc-editor.org/rfc/rfc5280>
- TLS 1.3 certificate handling: RFC 8446 §4.4.2
- CA/B Forum Baseline Requirements: <https://cabforum.org/baseline-requirements-documents/>

---

## 6. Beyond the four pillars — production checklist

### 6.1 Precise cryptographic statement

Document exactly what is proved:

- Hostname (SNI vs cert SAN policy; which validation strategy is used).
- HTTP version and framing (today: HTTP/1.1 GET, single request/response).
- Which JSON fields appear in **public outputs** vs remain hidden.
- Whether the **full response body** is proved or a hash/commitment.

Version the guest ELF; verifiers must pin the **ELF hash** or SP1 **program vkey** per release.

### 6.2 Proving operations

- Local RAM: real STARK proof requires ~32 GB. `SP1_PROVER=network` is the alternative — document the Succinct prover network flow in README.
- Logging hygiene: [`script/src/main.rs`](script/src/main.rs) currently prints the full HTTP response body for debugging. Remove or gate behind a `--verbose` flag before shipping.

### 6.3 Verification surface

- Who runs `prover.verify`, on-chain vs off-chain, key rotation, replay of **proof submissions** at application layer.

### 6.4 Testing matrix

- Multiple hosts: RSA vs ECDSA leaf, chain with/without root in bundle, chunked vs `Content-Length`.
- Negative tests on guest: malformed DER, wrong extension order, truncated records.
- Fuzz the TLS record parsers in the guest.

### 6.5 Third-party / delegated proving

If the prover runs on **another party's machine**, they observe `esk_client`, API keys, and plaintext responses. Mitigations: MPC-TLS (TLSNotary-style), TEE attestation, or user-only execution — see [`TODO.md` — Future Directions](TODO.md).

### 6.6 Cipher suite expansion

Only `TLS_AES_128_GCM_SHA256` is negotiated and decrypted. Supporting all three TLS 1.3 mandatory suites requires additional AEAD paths: `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256` — RFC 8446 Appendix B.

---

## 7. Suggested implementation order

1. **HTTP completeness + `unchunk` fix** — smallest change, directly closes the tail-omission gap (§4).
2. **Freshness public inputs** — wire `now_unix` through to guest assertion + verifier docs (§2).
3. **Integer threshold arithmetic** — replace `f64` in `PublicClaim` and guest assertion (§3).
4. **Stricter PKIX** — validity window + serverAuth EKU + basic constraints (§5).
5. **Ops hardening** — logging, prover network, README updates (§6).

---

## 8. Key file index

| Component | Path |
|-----------|------|
| Guest (TLS parsing, key schedule, verification, JSON assert) | [`program/src/main.rs`](program/src/main.rs) |
| Host CLI (three-phase orchestration) | [`script/src/main.rs`](script/src/main.rs) |
| Key injection + raw byte capture | [`script/src/capture.rs`](script/src/capture.rs) |
| Phase 1 key generation | [`script/src/keygen.rs`](script/src/keygen.rs) |
| Shared witness + public claim | [`shared/src/lib.rs`](shared/src/lib.rs) |

---

## 9. External references

- **SP1** (Succinct): <https://docs.succinct.xyz/>
- **RFC 8446** — TLS 1.3: <https://www.rfc-editor.org/rfc/rfc8446>
  - §4.2.8 key_share extension; §7.1 key schedule; §4.4.3 CertificateVerify
- **RFC 5280** — PKIX: <https://www.rfc-editor.org/rfc/rfc5280>
- **RFC 9112** — HTTP/1.1 chunked encoding: <https://www.rfc-editor.org/rfc/rfc9112>
- **x25519-dalek**: <https://docs.rs/x25519-dalek>
- **webpki-roots** trust anchor format: docs.rs for the pinned minor version

---

*Last updated 2026-05-18 — GUEST_TLS implementation complete.*
