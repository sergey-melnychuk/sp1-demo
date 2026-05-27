# Production roadmap — full ZK-TLS with Notary

This document defines what **production-ready** means for this repo: a user (or delegated
prover) obtains a **zero-knowledge proof** that a JSON claim holds over data fetched from a
**real TLS 1.3 server**, with an **independent notary** co-signing the session — without
trusting the host’s hand-picked digests or a single party holding full traffic keys.

Related docs: [`README.md`](README.md) (self-proving SP1 path), [`DEMO.md`](DEMO.md) (notary
E2E), [`INFO.md`](INFO.md) (repository guide), [`TODO.md`](TODO.md) (engineering backlog),
[`ECDH.md`](ECDH.md) (ECDH wire).

---

## 1. Target product

### What “full ZK-TLS with Notary” should prove

A third-party verifier accepts a STARK (or similar) proof whose public outputs include
something like `{ host, field, threshold, value }` and is convinced that:

1. The host and a **named notary** participated in a TLS 1.3 session to `host`.
2. The **server identity** (cert chain / SPKI binding) matches what the notary attested.
3. The **handshake transcript** the keys bind to is what the notary saw (not host-chosen hashes).
4. **Application records** decrypted for the claim match **notary-committed** ciphertext hashes.
5. The **predicate** over plaintext (e.g. `json[field] > threshold`) holds.
6. (Strong bar) A **malicious host** cannot forge app data without breaking crypto or notary/MPC assumptions.
7. (Strong bar) A **malicious notary** cannot attest to a session it did not observe or substitute circuits.

### Two deployment models (both valid products)

| Model | Trust shift | MPC depth | Time-to-ship |
|-------|-------------|-----------|--------------|
| **A. Witness notary** (TLSNotary-style) | Verifier trusts **notary signature + transparency**; notary may learn IKM | Split keys for record ops; notary signs commits | Months |
| **B. True 2PC notary** | Neither party holds full IKM / traffic keys | OT-MtA ECDH, incremental 2PC schedule, malicious MPC | Years (tlsn/mpz class) |

This repo today is a **working PoC toward A**, with **research hooks toward B**. Production
can ship **A** first while **B** remains the long-term cryptographic north star.

---

## 2. Architecture today

```
┌─────────────────────────────────────────────────────────────────────────┐
│  End user / host                                                         │
│  notary_demo  ──TCP──►  notary_proxy  (2PC AES-GCM, mode 0/1/2)         │
│       │                              │                                   │
│       │  raw TLS bytes + NotaryBundle│                                   │
│       ▼                              ▼                                   │
│  TlsWitness.bin ──►  host/notarized  ──►  SP1 guest  ──►  proof.bin   │
└─────────────────────────────────────────────────────────────────────────┘
```

| Crate | Role today |
|-------|------------|
| **`notary/`** | 2PC record layer, OT ECDH, mode-2 HKDF, signed `NotaryBundle` v1 |
| **`common/`** | `TlsWitness`, `NotaryBundle`, `SessionBinding` (shared wire types) |
| **`host/`** | SP1 driver: self-prove (`main`) or notary witness (`notarized`) |
| **`guest/`** | zkVM: full TLS verify (self path) **or** bundle + decrypt (notary path) |

**Mode 2** (`--two-pc-traffic-keys`) is the intended production handshake path: raw
[`HandshakeCapture`](notary/src/handshake.rs) to notary, notary verifies transcript + cert,
2PC HKDF for traffic keys, 2PC AES-GCM records, `OP_FINISH` → signed bundle.

### 2.1 Replaceable notary / MPC boundary

**Production shape:** heavy TLS and trust live **off-chain**; the zkVM proves a **cheap
predicate** over a **small signed witness**. The custom MPC stack in `notary/` is a
**reference implementation**, not the core product.

#### Stable contract (keep investing)

The API is the bincode witness schema in **`common/`** plus the guest notary path in
**`guest/src/main.rs`**. Any backend that emits this shape can replace `notary_proxy` /
`notary_demo`:

```
TlsWitness {
  raw_outbound, raw_inbound, hostname, json_field, threshold,
  notary: Some(NotaryAttestation {
    bundle: NotaryBundle { … Ed25519-signed … },
    k_c_tx, k_c_rx,   // host key shares — never sent to the notary
  })
}
```

The guest does **not** care how keys were split. It checks:

1. Ed25519 signature on the bundle
2. `SessionBinding.handshake_transcript_hash` and `server_epk` match the raw witness bytes
3. Per-record `commit_hash == SHA-256(ciphertext payload)` before decrypt
4. `K = K_N ⊕ K_C`, decrypt application records, run the JSON claim

#### MPC-specific (can drop in bundle v2)

These `SessionBinding` fields exist only because this repo's reference notary uses garbled
circuits — they are **not** TLS semantics:

| Field | Role today |
|-------|------------|
| `circuit_aes_sha256` | Bristol AES circuit identity |
| `circuit_sha256_compress_sha256` | Bristol SHA-256 compress identity |
| `garbling_mode` | WRK17 / twopac version tag |

A notary-agnostic **binding v2** should keep `server_epk`, `cert_chain_hash`,
`handshake_transcript_hash`, and `key_schedule_context_hash`; make circuit/garbling fields
optional or remove them.

#### What to freeze vs replace

| Keep / evolve | Freeze or replace |
|---------------|-------------------|
| `common/` types + canonical signing bytes | WRK17 performance tuning in `notary/` |
| Guest notary path (verify → decrypt → claim) | swanky vendoring, OT ECDH wire protocol |
| `host/notarized` + self-prove path | `notary_demo` modes 0–1 as product surface |
| Stronger guest binding (cert hash, key-schedule context) | Custom 2PC HKDF/AES/GHASH as long-term dependency |

#### Replacement backends (examples)

| Backend | Fit | Notes |
|---------|-----|-------|
| **[tlsn](https://github.com/tlsnotary/tlsn)** | High | Adapter: tlsn attestation → `NotaryBundle` + host shares; same SP1 story |
| **Trusted notary (no MPC)** | Medium | Notary observes traffic, signs commits; faster, weaker trust model |
| **Self-prove only** | Demo / self-attestation | Skip notary; `notary == None`; full in-guest TLS verify |

§4.1 (MPC engineering in `notary/`) remains relevant for **model B** and for running this
repo's reference notary; it is **not** required to ship witness-notary zkTLS if an external
backend implements the witness contract above.

---

## 3. Current state vs production bar

### Done (demo / internal PoC)

- Real HTTPS fetch with byte-identical TLS ciphertext (modes 0–2).
- Split client ephemeral + post-handshake OT ECDH framing.
- Mode 2: notary-side handshake verify; no host `extract` for **record** keys.
- WRK17 authenticated garbling for HKDF compress, AES blocks, GHASH (unrolled chain).
- KOS OT extension reuse per host↔notary channel (`Wrk17*Session`).
- `NotaryBundle` v1 + `SessionBinding` (transcript root, cert hash, epk, circuit IDs).
- `notary_verify` CLI; SP1 guest notary path (signature, commits, `K = K_N ⊕ K_C`, JSON claim).
- Self-proving SP1 path with full in-guest cert chain + `CertificateVerify` (no notary).

### Not production-ready

| Area | Gap |
|------|-----|
| **Secrecy** | Notary learns full IKM on OT path; host knows full IKM locally in mode 2 for optional cross-check |
| **Malicious MPC** | WRK17 auth mode; no full malicious-security proof; GCM tag check **outside** circuit (side channel) |
| **ECDH** | No OT-MtA X25519; host sends clamped scalar; not true “neither knows K” |
| **Performance** | Mode 2 HKDF: ~80 WRK17 SHA-compress sessions; one WRK17 AES circuit per 16 B block |
| **Operations** | Plain TCP to notary; no pinning, HA, threshold, audit log |
| **TLS coverage** | `TLS_AES_128_GCM_SHA256` only; no rekey / tickets / ChaCha / AES-256 |
| **HTTP** | No chunked encoding, gzip, redirects, completeness guarantees |
| **ZK** | Notary path skips in-guest cert/`CertificateVerify`; verifier trusts notary signature |
| **Testing** | Heavy integration tests `#[ignore]`; no fuzzing / formal review / constant-time audit |
| **Supply chain** | Vendored `swanky-authenticated-garbling`; not pinned to upstream releases |

---

## 4. Workstreams (what needs to be done)

### 4.1 Cryptography & MPC (`notary/`)

#### P0 — Close obvious security holes

- [ ] **Constant-time / constant-shape decrypt** — move GCM tag equality into the
  garbled circuit (or use indistinguishable abort); today `client_decrypt_gcm_2pc` returns
  `Err` on bad tag (leaks one bit per attempt).
- [ ] **Memory hygiene** — `zeroize` + `secrecy` (or locked pages) for IKM shares, key
  material, and bundle signing keys; audit stack copies in release builds.
- [ ] **Document & enforce garbling Δ policy** — one Δ per channel session is a deliberate
  tradeoff; document in threat model or rotate per circuit if required by WRK17 analysis.

#### P1 — Witness-notary MVP (ship model A)

- [ ] **TLS to notary daemon** — mTLS or noise channel; pin notary pubkey / SPKI in host and
  in `SessionBinding`; reject wrong identity before any 2PC.
- [ ] **Notary transparency** — publish long-term signing key, circuit hashes (`SessionBinding`
  already commits AES + SHA-compress Bristol IDs), garbling mode, and bundle schema version.
- [ ] **Replay & session policy** — notary-issued session id + timestamp + optional nonce;
  verifier rejects stale bundles; notary rate-limits / logs sessions.
- [ ] **Complete witness → SP1 story** — single documented flow:
  `notary_demo --witness-out` → `host/notarized --prove`; public inputs documented for verifiers.
- [ ] **Guest hardening (notary path)** — verify cert chain + hostname + `CertificateVerify`
  **inside the guest** using notary-bound transcript (optional dual path: trust signature
  **or** re-verify TLS — strongest when both agree).

#### P2 — True split IKM (model B — blocking “neither party knows K”)

- [ ] **OT-MtA X25519** — multiply-then-add on Ed25519/X25519 shares so neither party
  reconstructs full ECDH scalar/point from wire messages alone (see `mpz` / tlsn literature).
- [ ] **Drop notary `ikm_full` oracle** — notary must not hold full IKM for IV/HKDF public
  steps; move to incremental 2PC key schedule bound to verified transcript.
- [ ] **Incremental 2PC TLS 1.3 schedule** — derive handshake traffic keys in 2PC where
  needed for transcript parsing; bind each HKDF expand to notary-verified hash inputs.
- [ ] **Host must not know record keys** — mode 2 already avoids extract for records; extend
  to handshake traffic where host currently uses local `reference_*` helpers.

#### P3 — Performance (required for usable prod)

- [ ] **Unroll HMAC** — chain 4 SHA-256 compresses per HMAC into one WRK17 session (same
  pattern as GHASH chain); cuts HKDF from ~40 to ~10 sessions per party.
- [ ] **Unroll / batch AES** — multiple 128-bit blocks per WRK17 circuit per record direction.
- [ ] **Optional: semi-honest fast path** — dev/CI and low-assurance deployments only.
- [ ] **Pipelined record worker** — overlap encrypt/decrypt on worker thread; target **100 ms–1 s**
  wall-clock for typical API responses (not minutes).
- [ ] **Parallel OT / preprocessing** — profile WRK17 preprocess; consider session pooling.

#### P4 — Cipher & protocol breadth

- [ ] **Session tickets & key update** — detect rustls rekey / `NewSessionTicket`; rerun 2PC
  derivation per epoch.
- [ ] **Additional cipher suites** — AES-256-GCM, ChaCha20-Poly1305 (guest + 2PC circuits).
- [ ] **ALPN / HTTP semantics** — chunked transfer, `Content-Encoding: gzip`, redirects,
  response completeness (mitigate tail-record omission).

---

### 4.2 Zero-knowledge layer (`guest/`, `host/`, `common/`)

#### P0 — Verifier-facing clarity

- [ ] **Single proof statement spec** — document exact public inputs, witness layout, and
  what is / isn’t proved in notary vs self-prove modes.
- [ ] **Bundle schema versioning** — migration path for `NotaryBundle` v2+ (threshold sigs,
  additional binding fields).

#### P1 — Stronger notary-backed proofs

- [ ] **In-guest TLS verify on notary path** — re-derive keys from split shares only;
  verify cert chain, SAN, `CertificateVerify`, Server `Finished` against `SessionBinding`
  transcript (large cycle cost; prioritize SP1 precompiles / circuit layout).
- [ ] **Commit ciphertext Merkle root** — bundle commits root over `(seq, commit_hash)` list;
  guest checks inclusion for records used in claim.
- [ ] **Selective disclosure** — prove predicate on a field without revealing full body
  (TLSNotary-style Merkle + SNARK / SP1 sub-circuit).

#### P2 — Delegated proving

- [ ] **Prover never holds `server_write_key`** — requires P2 from §4.1; until then, only
  **self-proving** (user runs prover locally) is sound per [`README.md`](README.md) threat model.
- [ ] **Witness encryption** — optional: encrypt `k_c_*` shares for prover enclave.

---

### 4.3 Operations & deployment

- [ ] **Notary service** — systemd/k8s, health checks, config (listen addr, signing key HSM),
  structured audit logs (session id, host, cert fp, record count, no plaintext).
- [ ] **Key ceremony** — Ed25519 notary key generation, rotation, backup; separate from
  TLS termination key.
- [ ] **Host SDK** — stable API instead of only `notary_demo` CLI; timeouts, reconnect, clear
  errors when notary rejects handshake.
- [ ] **Monitoring** — latency histograms for HKDF / per-record 2PC; alert on verify failures.
- [ ] **Legal / abuse** — ToS, rate limits, blocklist; notary is a witness to user-initiated fetches.

---

### 4.4 Quality & assurance

- [ ] **CI** — fast default `cargo test --release` (unit + semihonest); nightly `--ignored`
  WRK17 integration; SP1 mock prove on witness fixtures.
- [ ] **Fuzzing** — handshake capture parser, record bridge framing, bundle decode.
- [ ] **Property tests** — 2PC AES-GCM vs `aes-gcm` crate (release, bounded sizes).
- [ ] **Third-party crypto review** — WRK17 integration, OT reuse, bundle binding semantics.
- [ ] **Pen test** — malicious host (bad transcript, swapped epk), malicious notary (wrong circuit).

---

## 5. Recommended phases

### Phase 0 — Stabilize PoC (weeks)

- Merge mode-2 path; fix warnings/clippy; document witness E2E.
- Operational: mTLS to notary, pinned pubkey, replay policy.
- Publish proof statement for notary path (what verifier gets).

**Exit:** Internal demo repeatable; `notary_verify` + SP1 mock prove on fixed fixture.

### Phase 1 — Witness notary product (months)

- TLS + identity + transparency for notary.
- Guest checks: bundle signature + transcript/epk binding + record commits (today) **plus**
  optional cert/`CertificateVerify` re-verify.
- HTTP completeness for target sites; chunked/gzip.
- Performance: unrolled HMAC, batched AES, pipelined worker → sub-minute sessions.

**Exit:** Third party can verify proofs + notary signature without trusting host digests;
suitable for **trusted-notary** zkTLS (model A).

### Phase 2 — Cryptographic hardening (6–12+ months)

- GCM tag inside circuit; malicious-security audit of WRK17 usage.
- OT-MtA ECDH prototype; incremental 2PC schedule; remove full IKM from notary.

**Exit:** Credible path to model B; academic / beta partners only.

### Phase 3 — Full ZK-TLS (long horizon)

- Neither party knows K; delegated proving; selective disclosure at scale.
- Align with or adopt components from [`tlsn`](https://github.com/tlsnotary/tlsn) / [`mpz`](https://github.com/privacy-scaling-explorations/mpz) where appropriate.

**Exit:** Production indistinguishable from tlsn-class threat model + SP1 predicate proofs.

---

## 6. Acceptance criteria (production checklist)

Use this as a release gate for **model A (witness notary)**:

### Security

- [ ] Notary verifies raw handshake bytes before any record keys (mode 2 only in prod).
- [ ] `SessionBinding` in signed bundle matches witness raw bytes and ServerHello epk.
- [ ] Per-record `commit_hash` verified in guest before decrypt.
- [ ] Notary connection authenticated (TLS + pinning).
- [ ] No secret material in logs; keys zeroized on drop.
- [ ] Documented threat model signed off (notary trusted; host cannot forge commits without breaking sig/MPC).

### Correctness

- [ ] SP1 proof verifies on Succinct verifier / `sp1-sdk`.
- [ ] `notary_verify` agrees with guest on bundle validity.
- [ ] Cross-test: 2PC ciphertext matches rustls reference for same keys/nonce/AAD.

### Performance

- [ ] Mode 2 E2E: typical JSON API (&lt; 10 KB) completes in **&lt; 60 s** on reference hardware (release).
- [ ] Default CI **&lt; 2 min** (no multi-hour WRK17 integration in PR path).

### Operations

- [ ] Notary key rotation procedure documented.
- [ ] Session replay policy enforced.
- [ ] Runbook for notary reject (cert mismatch, transcript fail, tag fail).

---

## 7. Explicit non-goals (for v1 prod)

- Multi-hop TLS (CONNECT), mTLS client auth, post-quantum hybrids.
- OCSP/CRL inside zkVM (too expensive; pin or staple out-of-band if needed).
- Full malicious-security MPC proof (WRK17 is a step, not the final theorem).
- Replacing Succinct prover network / 32 GB RAM requirement for **real** STARKs without documenting it.

---

## 8. Summary

**Today:** A credible **research demo** — real TLS, split-key 2PC records, signed notary bundles,
SP1 proofs over JSON claims — with mode 2 removing host extract for record keys and notary
verification of handshake bytes. The **`notary/` MPC stack is replaceable**; the durable product
surface is **`common/` witness types + guest notary path + `host/notarized`** (see §2.1).

**To ship witness-notary zkTLS:** harden transport and identity, clarify the proof statement,
close tag side-channels, improve performance (unrolled HMAC + batched AES), and operationalize
the notary service — **or** plug in an external notary (e.g. tlsn) that emits the same witness.

**To reach full ZK-TLS (model B):** OT-MtA ECDH, incremental 2PC key schedule, in-circuit
tag verify, and either full in-guest TLS verification or a formally reviewed reduction to
notary signatures — plus years-class MPC engineering aligned with the broader tlsn ecosystem
(optional if using tlsn rather than this repo's reference `notary/`).
