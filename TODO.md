# TODO — toward production-grade zkTLS

Engineering backlog for the full repo (SP1 + notary). Production phases and acceptance
criteria: **[`PROD.md`](PROD.md)** (especially §2.1 replaceable notary). Architecture:
**[`INFO.md`](INFO.md)**.

---

## Recommended path forward

**Bet on the witness → SP1 layer, not custom MPC.** The durable product is
`common/` + guest notary path + `host/notarized`. The `notary/` crate (WRK17, swanky,
mode 0–2) is a **reference backend** that already produces valid witnesses — treat it as
frozen unless you need a local demo without tlsn.

```
  [Notary backend]          [This repo — core]
  tlsn / trusted witness    common/ witness schema
        or                      ↓
  notary_demo (ref)  ──►  TlsWitness.bin  ──►  host/notarized  ──►  SP1 guest  ──►  proof
```

### Phase A — Ship the contract (weeks)

Focus: make the witness schema the public API and prove one E2E path works without touching
garbled circuits.

- [ ] **`SessionBinding` v2** — new `bundle_version`; keep TLS fields (`server_epk`,
  `cert_chain_hash`, `handshake_transcript_hash`, `key_schedule_context_hash`); drop or
  optionalize `circuit_*` + `garbling_mode`. Guest + `notary_verify` accept v1 and v2.
- [ ] **Proof statement doc** — one page: public outputs, witness layout, what is / isn't
  proved in notary vs self-prove modes (verifier-facing).
- [ ] **Fixture + CI** — checked-in `TlsWitness` bin + SP1 mock prove in CI; fast default
  tests stay under ~2 min.
- [ ] **Guest binding hardening** — assert `cert_chain_hash` and `key_schedule_context_hash`
  against witness bytes where feasible today (epk + transcript already checked).
- [ ] **Document E2E** — single flow in README: witness export → `notarized --prove`
  (reference: `notary_demo --witness-out` mode 2).

### Phase B — Replace reference MPC (months)

Focus: stop maintaining WRK17 as a dependency; plug in a real notary ecosystem.

- [ ] **tlsn adapter (preferred)** — map tlsn attestation → `NotaryAttestation` /
  `NotaryBundle` + host key shares; same SP1 guest unchanged.
- [ ] **Or: minimal trusted notary** — thin service: observe TLS, sign commits + binding v2,
  no garbling (faster path to model A in [`PROD.md`](PROD.md)).
- [ ] **Notary transport** — mTLS or pinned pubkey to notary daemon (applies to any backend).
- [ ] **Replay policy** — session id, timestamp, verifier rejects stale bundles.

### Phase C — Stronger proofs (optional, when needed)

- [ ] **In-guest TLS verify on notary path** — cert chain + `CertificateVerify` inside zkVM
  using bound transcript (expensive; reduces trust in notary signature alone).
- [ ] **Selective disclosure** — Merkle commits + prove predicate without full body leak.
- [ ] **Self-prove path polish** — keep as Succinct demo / user-runs-prover use case.

### Explicitly deprioritized (unless you want model B)

Do **not** block shipping on these — they live in reference `notary/` or long-horizon
[`PROD.md`](PROD.md) §4.1:

- WRK17 performance (unrolled HMAC, batched AES, pipelined worker)
- OT-MtA X25519 / incremental 2PC schedule / “neither party knows K”
- GCM tag inside garbled circuit
- swanky vendoring upgrades

**Exit criteria for “promising product slice”:** third party verifies SP1 proof + notary
signature + witness binding without trusting host-chosen digests; notary backend is
pluggable (tlsn or trusted witness); reference `notary/` optional for demos only.

---

## Status (reference notary — `notary/`)

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

Docs: [`DEMO.md`](DEMO.md), [`INFO.md`](INFO.md), [`PROD.md`](PROD.md), ECDH: [`ECDH.md`](ECDH.md).

### Working primitives

- **`handshake.rs`** — mode-2 capture wire; notary-side transcript + cert verify.
- **`aes.rs`** — split-key 2PC AES-GCM; byte-identical to `aes-gcm`; unrolled WRK17
  GHASH chain per record direction; `Wrk17*Session` OT reuse on the channel.
- **`ghash.rs`** — GF(2^128) multiply chain in one WRK17 `execute` per direction.
- **`hkdf.rs`** — 2PC HMAC/HKDF (WRK17 compress); chains XOR shares between HMAC
  rounds; full TLS 1.3 client traffic schedule; reuses `Wrk17*Session`.
- **`ecdh.rs`** — OT-blinded ECDH (default); TLS-correct IKM via `reference_ikm`.
- **`transcript.rs`** — handshake hash parsing (host + notary).
- **`tls.rs`** — record bridge, attested worker, `OP_2PC_HKDF`.
- **`common::NotaryBundle`** — v0 legacy + **v1 `SessionBinding`** in signature.
- **`notary_verify`** — standalone bundle + optional witness cross-check.
- **`garble.rs`** — WRK17 helpers + `Wrk17NotarySession` / `Wrk17ClientSession`
  (KOS OT extension once per channel; shared Δ per session).

### Tests

Default `cargo test --release -p notary --lib` runs the **fast** suite (~18 s):
**18 passed**, **14 ignored** — GHASH/HKDF unit round-trips, ECDH wire tests, commit flow.

**Ignored** (WRK17 integration — run with `--ignored` when needed):

- `decrypt_2pc_*` — full AES-GCM 2PC records
- `hkdf_over_*`, `tls13_traffic_2pc_*` — full TLS 1.3 traffic HKDF schedule (~80 WRK17 compress sessions)
- `split_key_record`, `rustls_bridge`, `notary_bundle` — record worker round-trips

---

## Trust model gaps (why this is not prod-ready)

Three structural issues block third-party or malicious-security claims:

| Gap | Today | Why it matters |
|-----|--------|----------------|
| **Host-side handshake parser** | **Fixed (mode 2):** host sends raw bytes; notary verifies in `handshake.rs`. Host still uses local `reference_ikm` for optional rustls cross-check only. | Malicious host cannot lie about transcript for mode 2 HKDF binding. |
| **Trusted-notary semantics** | Bundle v1 signs `SessionBinding` (cert hash, transcript root, epk, circuit IDs). `notary_verify` + guest checks. Notary still learns full IKM. | Verifier can check signature + witness fields; not full MPC secrecy. |
| **Authenticated garbling** | HKDF, AES blocks, and GHASH use **WRK17**; KOS OT reused per channel (`Wrk17*Session`). GCM tag check still outside circuit. | WRK17 auth mode; not a full malicious-MPC proof; tag failure leaks one bit today. |

### Rationale

These gaps compose: even with mode 2 (no host extract for **record** keys), the notary still
learns full IKM on the OT path. WRK17 covers record-layer circuits, but **tag verify** and
**delegated proving** remain open — see [`PROD.md`](PROD.md).

**Two product paths** (see [`PROD.md`](PROD.md) §1):

1. **Witness notary (recommended)** — independent notary signs commits + binding; SP1 proves
   the JSON claim. MPC stack is **replaceable** (§2.1). Ship Phase A + B above.
2. **True 2PC notary (long horizon)** — neither party knows K; OT-MtA, malicious MPC. Only if
   you commit to tlsn-class engineering — not the default path for this repo.

### Recommended fix order (historical — reference notary)

Mode 2 + WRK17 record layer + bundle v1 are **done for the reference demo**. Further MPC
work is optional; prefer Phase A/B in [Recommended path forward](#recommended-path-forward).

#### 1. Host-side handshake parser → notary-side verification — **done (mode 2)**

- Wire: [`HandshakeCapture`](notary/src/handshake.rs) (epk, cert hash, raw outbound/inbound).
- Notary: `verify_handshake_capture` after ECDH; abort before `OP_2PC_HKDF`.

#### 2. Trusted-notary semantics — **witness path largely done**

**Witness path (A):**

- **Done:** `SessionBinding` in NotaryBundle v1; `notary_verify` CLI; guest transcript/epk checks.
- **Still missing:** TLS to notary daemon; k-of-n threshold.

**2PC path (B):** OT-MtA, drop `ikm_full`, incremental schedule — unchanged.

#### 3. WRK17 record layer — **done (demo bar)**

- **Done:** per-compress HMAC (WRK17); per-block AES (WRK17); unrolled GHASH chain (WRK17);
  `Wrk17NotarySession` / `Wrk17ClientSession` (KOS OT once per channel).
- **Next:** GCM tag inside circuit; unrolled HMAC (4 compresses → 1 session); batched AES blocks.

**Minimum “production-ish” demo bar:** items 1 + witness 2 + WRK17 record layer **done**.
Production gaps: [`PROD.md`](PROD.md).

---

## Reference-notary backlog (model B / `notary/` only)

Detailed gaps below apply to the **in-repo MPC demo** or long-horizon true 2PC. They are
**not** on the default shipping path — see [Recommended path forward](#recommended-path-forward).

## Cryptographic gaps (the protocol)

### 1. ECDH 2PC over Curve25519 *(blocking “neither party knows K”)*

**Partial progress (mode 2):** OT-blinded ECDH + XOR IKM shares + 2PC HKDF for **application**
traffic keys without host `dangerous_extract_secrets()` for records. Host still uses split
ephemeral + local transcript oracle; notary learns full IKM; host sends clamped scalar on wire.

**Still needed:** OT-based MtA share-conversion over Curve25519, Edwards point addition on
shares (~1500–2000 LOC; no swanky primitive — see `mpz`). Until then:

- Mode 1: host briefly holds full AES keys between extract and `zeroize()`.
- Mode 2: host never extracts record keys, but still knows full IKM locally for transcript parsing.

### 2. Authenticated garbling — **WRK17 on HKDF + AES + GHASH (demo)**

`swanky-authenticated-garbling` (WRK17) via `SplitSharedInputMaskCircuit` in `garble.rs`.
Vendored patch: `new_with_and_generator`, shared `AndTripleGenerator` per channel.

**Still open:** GCM tag equality in-circuit; unrolled HMAC; batched AES; formal MPC review.

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

### 9. OT bootstrap — **partially done**

**Done:** `Wrk17*Session` reuses KOS OT extension for the whole host↔notary channel (no full
re-bootstrap per `Garbler::new`).

**Still open:** each SHA compress / AES block still runs full WRK17 **preprocess + execute**
(~80 compress sessions for full mode-2 HKDF). Unroll HMAC + batch AES — see [`PROD.md`](PROD.md) §4.1 P3.

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

**Default roadmap:** [Recommended path forward](#recommended-path-forward) (witness contract →
external notary → optional guest hardening). Full phased plan: **[`PROD.md`](PROD.md)**.

| Priority | Work | Where |
|----------|------|--------|
| **P0** | `SessionBinding` v2, proof statement, witness fixture + CI mock prove | `common/`, `guest/`, `host/` |
| **P1** | tlsn adapter *or* minimal trusted notary; mTLS / pinning | new adapter crate or service |
| **P2** | Guest cert/`CertificateVerify` (optional); selective disclosure | `guest/` |
| **P3** | Self-prove demo polish | `host/main`, `guest/` |
| **Frozen** | WRK17 perf, OT-MtA, tag-in-circuit | `notary/` — reference only |

**Current demo is suitable for:** witness → SP1 experiments, protocol debugging, internal PoC
with reference `notary_demo` mode 2.

**Not suitable for:** production notary service or malicious-host claims without Phase B+
(notary transport, replay policy, and ideally tlsn or audited trusted witness).
