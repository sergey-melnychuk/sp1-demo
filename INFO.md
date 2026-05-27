# sp1-demo — repository guide

End-to-end **zkTLS**: prove a JSON predicate over an HTTPS response inside an
[SP1](https://docs.succinct.xyz/) zkVM, optionally with an independent **2PC notary**
that co-signs the session. This document walks the repo **crate by crate**, **module by
module**, explains **crypto primitives**, **why** each exists, and **what it produces**.

| Doc | Purpose |
|-----|---------|
| [`README.md`](README.md) | Quick start (SP1 self-prove + notary witness) |
| [`DEMO.md`](DEMO.md) | Notary E2E demo (modes 0–2) |
| [`PROD.md`](PROD.md) | Production roadmap |
| [`TODO.md`](TODO.md) | Engineering backlog |
| [`ECDH.md`](ECDH.md) | ECDH wire protocol |
| **INFO.md** | This file — architecture deep dive |

---

## 1. Big picture

### Two proof paths

| Path | Who runs TLS | Keys in proof | Guest verifies |
|------|----------------|---------------|----------------|
| **Self-prove** | `host` only | Host supplies `esk_client` + raw bytes | Full TLS 1.3: X25519, HKDF, certs, `CertificateVerify`, AES-GCM, JSON |
| **Notary witness** | `notary_demo` + `notary_proxy` (2PC) | `TlsWitness` + `NotaryAttestation` | Ed25519 bundle, record commits, `K = K_N ⊕ K_C`, JSON (no full cert path today) |

Both converge on the same **public claim**: `{ host, field, threshold, value }`.

### Workspace layout

```
sp1-demo/
├── Cargo.toml          # Workspace: guest, host, common (+ SP1 crypto patches)
├── common/             # Shared types (witness, bundle, binding)
├── host/               # SP1 prover driver + TLS capture
├── guest/              # SP1 zkVM program (verification + claim)
├── notary/             # Separate crate: 2PC MPC-TLS (swanky); not in workspace
│   ├── src/            # Library modules
│   ├── src/bin/        # notary_proxy, notary_demo, notary_verify, …
│   ├── circuits/       # Bristol boolean circuits (AES, SHA-256 compress)
│   └── deps/           # Vendored swanky-authenticated-garbling patch
├── DEMO.md, PROD.md, ECDH.md, INFO.md (this file)
└── README.md
```

**Why two workspaces?** `notary` pulls in **swanky** MPC stacks that conflict with
`sp1-sdk`’s pinned `generic-array`. The handoff is **bincode files** (`TlsWitness`) and
types in `common/`, not a direct Rust dependency from `host` → `notary`.

### End-to-end notary + SP1 flow

```
  notary_proxy ◄──TCP/swanky Channel──► notary_demo
        │                                    │
        │ 2PC HKDF + 2PC AES-GCM             │ real HTTPS (rustls)
        │ Ed25519 NotaryBundle               │ raw_inbound/outbound
        └────────────────────────────────────┘
                         │
              TlsWitness.bin (--witness-out)
                         │
              host/bin/notarized ──► SP1 guest ──► proof.bin
```

---

## 2. Root `Cargo.toml`

**Role:** Cargo workspace for the SP1 stack; **default member** is `host`.

**`[patch.crates-io]`** — SP1-accelerated / zkVM-compatible crypto ([Succinct patches](https://github.com/sp1-patches)):

| Crate | Patch | Used in guest for |
|-------|--------|-------------------|
| `sha2` | sp1-patches/RustCrypto-hashes | SHA-256, HKDF, transcript hashes (precompile) |
| `curve25519-dalek` | sp1-patches/curve25519-dalek | X25519 ECDH (precompile) |
| `p256` | sp1-patches/elliptic-curves | ECDSA cert verify |
| `crypto-bigint` | sp1-patches/RustCrypto-bigint | RSA bigint |
| `rsa` | fork `fix/no-std-zkvm-core-mem` | RSA-PSS cert verify |

**Result:** Guest executes TLS verification in the zkVM with far fewer cycles on patched
primitives; AES-GCM remains software (no SP1 precompile yet).

---

## 3. Crate: `sp1-demo-common` (`common/`)

**Role:** Single source of truth for types shared by **host**, **guest**, and **notary**
(wire-compatible via `serde` + `bincode`).

### Types

| Type | Purpose | Crypto |
|------|---------|--------|
| [`SessionBinding`](common/src/lib.rs) | Committed in bundle v1 signature | SHA-256 digests of transcript, cert chain, epk, circuit IDs, garbling mode |
| [`RecordCommit`](common/src/lib.rs) | One TLS record op in bundle | `commit_hash = SHA-256(payload)` |
| [`NotaryBundle`](common/src/lib.rs) | Signed session attestation | Ed25519 over canonical byte encoding |
| [`NotaryAttestation`](common/src/lib.rs) | Host-side witness extension | Bundle + host key shares `k_c_tx`, `k_c_rx` |
| [`TlsWitness`](common/src/lib.rs) | SP1 stdin input | Raw TLS bytes + claim params + optional notary attestation |
| [`PublicClaim`](common/src/lib.rs) | SP1 public outputs | Hostname, JSON pointer, threshold, value |

### `NotaryBundle::verify()`

Reconstructs **canonical signing bytes** (version, pubkey, timestamp, session metadata,
record list, notary key/IV shares, optional `SessionBinding`) and checks **Ed25519**
([RFC 8032](https://www.rfc-editor.org/rfc/rfc8032)).

**Why:** Third parties (`notary_verify`, SP1 guest) check the same bytes the notary signed
without linking to the MPC crate.

---

## 4. Crate: `sp1-demo-host` (`host/`)

**Role:** Run TLS on the host, build `TlsWitness`, invoke SP1 execute/prove.

### Modules

| Path | Role |
|------|------|
| [`src/crypto.rs`](host/src/crypto.rs) | **`ExternalKxGroup`** — rustls hook that injects a pre-generated X25519 ephemeral instead of rustls generating one |
| [`src/stream.rs`](host/src/stream.rs) | **`CapturingStream`** — records every raw byte in/out for the witness |
| [`src/lib.rs`](host/src/lib.rs) | Re-exports `crypto`, `stream` |
| [`build.rs`](host/build.rs) | Builds / locates guest ELF via `sp1-build` |

### Binaries

| Binary | Entry | Result |
|--------|-------|--------|
| **`main`** | [`src/bin/main.rs`](host/src/bin/main.rs) | Phase 1 keygen → Phase 2 HTTPS fetch → Phase 3 SP1 execute or prove (self-prove path) |
| **`notarized`** | [`src/bin/notarized.rs`](host/src/bin/notarized.rs) | Load bincode `TlsWitness` from `notary_demo --witness-out` → SP1 |

### Crypto on the host path

- **X25519** ([RFC 7748](https://www.rfc-editor.org/rfc/rfc7748)) via `x25519-dalek` +
  custom `SupportedKxGroup` — ties ClientHello `key_share` to witness `esk_client`.
- **TLS 1.3** via **rustls** + ring — real network fetch; cipher suite pinned to
  `TLS_AES_128_GCM_SHA256` in `main`.
- **SP1** ([Succinct SDK v6](https://docs.succinct.xyz/)) — `ProverClient`, mock or STARK prove.

**Trust note (documented in README):** Host knows `esk_client` and `epk_server`, so it can
forge application data unless using the notary path or future full MPC.

---

## 5. Crate: `sp1-demo-guest` (`guest/`)

**Role:** `#![no_main]` zkVM program — **the statement being proved**.

### Structure (`guest/src/main.rs`, ~1247 lines)

| Section | Self-prove path | Notary path (`run_notary_path`) |
|---------|-----------------|----------------------------------|
| Input | `TlsWitness` from `sp1_zkvm::io::read()` | Same |
| Key derivation | X25519 + HKDF-SHA256 ([RFC 8446 §7.1](https://www.rfc-editor.org/rfc/rfc8446#section-7.1)) | `K_rx = k_n_rx ⊕ k_c_rx` from bundle + attestation |
| Handshake | Parse records, decrypt with hs traffic keys, verify chain (**webpki-roots**), SAN, **CertificateVerify**, Server Finished | Skipped — trusts notary signature + binding fields |
| App data | AES-128-GCM decrypt ([RFC 5116](https://www.rfc-editor.org/rfc/rfc5116)) | Decrypt with reconstructed key; check `commit_hash` per record |
| Claim | JSON pointer ([RFC 6901](https://www.rfc-editor.org/rfc/rfc6901)), assert `value > threshold` | Same |
| Output | `sp1_zkvm::io::commit(&PublicClaim)` | Same |

### Crypto primitives in guest

| Primitive | Crate | SP1 precompile? |
|-----------|-------|-----------------|
| X25519 | `x25519-dalek` (patched) | Yes |
| SHA-256 / HMAC / HKDF | `sha2`, `hmac`, `hkdf` (patched sha2) | SHA-256 yes |
| AES-128-GCM | `aes-gcm` | No (software) |
| ECDSA P-256 / P-384 | `p256`, `p384` (p256 patched) | P-256 yes |
| RSA-PSS | `rsa` (patched) | Yes |
| X.509 | `x509-cert`, `der` | Parse + verify in software |

**Result:** Self-prove path proves “this witness bytes + this esk imply a valid TLS session
and JSON claim.” Notary path proves “this signed bundle + host shares imply decryptable
records matching commits and JSON claim.”

---

## 6. Crate: `notary` (`notary/`)

**Role:** **Two-party computation** for TLS record layer — split keys, garbled circuits,
notary daemon. Uses [Galois **swanky**](https://github.com/GaloisInc/swanky) (Yao /
authenticated garbling, OT).

**Edition 2024.** Not a member of the root workspace.

### 6.1 Library modules (`notary/src/`)

#### `circuits.rs`

- Embeds **`circuits/AES-non-expanded.txt`** and **`circuits/sha-256-compress.txt`**
  (Bristol format, ~33k / ~128k AND gates).
- Publishes **SHA-256 circuit identity hashes** for `SessionBinding`.
- **`GARBLING_*` constants** — version the attested garbling mode in bundles.

**Why:** Verifiers bind proofs to exact boolean circuits used for 2PC.

**Reference:** Bristol format (legacy MPC benchmark format); circuits often derived from
[SCALE-MAMBA / Bristol](https://github.com/emp-toolkit) ecosystems.

---

#### `garble.rs` — WRK17 integration layer

**Primitives:**

| Piece | Library | Role |
|-------|---------|------|
| **WRK17 garbling** | `swanky-authenticated-garbling` (vendored) | Malicious-security authenticated garbling ([Wang–Rathee–Kumar–Choi–Wang–Raghuraman, ePrint 2017/116](https://eprint.iacr.org/2017/116)) |
| **KOS OT extension** | `swanky-authenticated-bits` (`AndTripleGenerator`) | Generates authenticated AND triples ([Keller–Orsini–Scholl, Crypto 2015](https://eprint.iacr.org/2015/546)) |
| **Circuit wrapper** | `SplitSharedInputMaskCircuit` | XOR-combine party input shares **inside** the circuit; garbler masks output |

**Key types:**

- **`Wrk17NotarySession` / `Wrk17ClientSession`** — one `AndTripleGenerator::init` per
  TCP/swanky channel; reuse across many circuits (shared garbling Δ).
- **`wrk17_notary_masked_run` / `wrk17_client_masked_run`** — one garble+eval round;
  parties hold **XOR shares** of 256-bit compress outputs or 128-bit AES outputs.

**Constraint (documented in module):** one `circ.execute()` per `Garbler`/`Evaluator`
session — HMAC chains multiple sessions with share handoff.

**Vendored patch** (`notary/deps/swanky-authenticated-garbling/`):

- Public `preprocess_circuit`
- `Garbler::new_with_and_generator` / `Evaluator::new_with_and_generator` (reuse OT session Δ)

---

#### `hkdf.rs` — 2PC TLS 1.3 key schedule

**Goal:** Compute **HKDF-SHA256** ([RFC 5869](https://www.rfc-editor.org/rfc/rfc5869)) /
TLS 1.3 expand-label ([RFC 8446 §7.1](https://www.rfc-editor.org/rfc/rfc8446#section-7.1))
where PRK and outputs are **XOR-shared** between notary (garbler) and host (evaluator).

**Building block:** One **SHA-256 compression** = one WRK17 session on
`sha-256-compress.txt` (768 input bits = 256-bit IV ⊕ 512-bit block).

**HMAC-SHA256** = 4 compress rounds (inner ipad, inner msg, outer ipad, outer digest).
Each **`notary_hmac_sha256` / `client_hmac_sha256`** chain uses the previous round’s XOR
share as the next IV share.

**Public API (selection):**

| Function | Meaning |
|----------|---------|
| `notary_hmac_sha256_xor_msg` | HKDF-Extract with **XOR-shared 32-byte IKM** (mode 2) |
| `notary_tls13_client_traffic_from_ikm_shares` | Full client traffic key schedule (notary side) |
| `client_tls13_client_traffic_from_ikm_shares` | Host side |
| `reference_tls13_client_traffic` | Single-party oracle for tests |

**Scope limits:** HMAC messages ≤ 55 bytes (one SHA block after padding) — sufficient for
TLS 1.3 labels used here.

**Result:** Each party holds `k_*_tx`, `k_*_rx`, and public IV shares; `K = K_N ⊕ K_C`.

**Tests:** Single-compress round-trips (fast); full schedule tests `#[ignore]` (~80 WRK17 sessions).

---

#### `ghash.rs` — GF(2^128) multiply for GCM

**Goal:** GHASH authentication in **AES-GCM** ([NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)).

**Circuits:**

- **`GhashMulCircuit`** — one 128×128 bit-serial multiply in GF(2^128) (GCM algorithm).
- **`GhashChainCircuit` / `GhashChainWrk17Circuit`** — chain `N` multiplies in **one**
  WRK17 `execute` per record direction (AAD blocks + ciphertext blocks + length block).

**Result:** XOR-share of GHASH accumulator for tag computation; combined with AES-CTR
shares in `aes.rs`.

---

#### `aes.rs` — Split-key AES-128-GCM

**Goal:** Encrypt/decrypt TLS application records where **`K = K_N ⊕ K_C`** never appears
in the clear on either machine.

**Per record (WRK17 path):**

1. **`notary_aes_block_wrk17` / `client_aes_block_wrk17`** — one Bristol AES circuit per
   16-byte block (keystream XOR).
2. **`notary_ghash_chain_wrk17` / `client_ghash_chain_wrk17`** — one chained GHASH session.
3. Tag = `GHASH(...) ⊕ E(K, 0^128)` with shares combined via XOR on the wire.

**Also:** Semi-honest **twopac** garbling path (`swanky-twopac` + Chou–Orlandi OT) for
tests / legacy.

**Reference implementation check:** Compared to **`aes-gcm`** crate for byte-identical ciphertext.

**Result:** Wire-compatible TLS records; `NotaryCommit` hashes ciphertext payloads for the bundle.

---

#### `ecdh.rs` — X25519 / IKM sharing

**Goal:** Produce **32-byte IKM shares** for mode-2 HKDF without sending full ECDH secret
in the clear on the host wire (OT-blinded path).

| Mechanism | Security | Result |
|-----------|----------|--------|
| **Additive scalar shares** | `esk = k_host + k_notary (mod L)` | Correct TLS math; partial points leak IKM if exchanged |
| **`OtX25519Blinded`** (default) | Semi-honest blinded point add + XOR IKM mask | Host gets XOR share only; **notary still learns full IKM** |
| **`LeakyAdditivePointEcdh`** | Cleartext partial points | Debug / tests only |
| **`xor_split_ikm`** | One-time pad | Masks IKM if secret already known — does not fix host knowledge |

**Wire:** Documented in [`ECDH.md`](ECDH.md) — flags `SETUP_ECDH_OT`, `SETUP_ECDH_LEAKY`, etc.

**Future:** OT-MtA scalar multiplication ([`mpz`](https://github.com/privacy-scaling-explorations/mpz), [tlsn](https://github.com/tlsnotary/tlsn)) for true split IKM.

**References:** [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) (X25519), [RFC 8446 §7.1](https://www.rfc-editor.org/rfc/rfc8446#section-7.1) (HKDF input).

---

#### `handshake.rs` — Mode-2 witness capture

**Goal:** Host sends **raw handshake bytes**; notary **independently verifies** before 2PC HKDF.

| Function | Role |
|----------|------|
| `HandshakeCapture` | `server_epk`, `cert_chain_hash`, `outbound`, `inbound` |
| `write_handshake_capture` / `read_handshake_capture` | Length-prefixed wire format |
| `verify_handshake_capture` | Recompute transcript hashes, parse certs, check epk |
| `handshake_transcript_hash` | SHA-256(len‖out‖len‖in) — bound in `SessionBinding` |

**Result:** Malicious host cannot pick arbitrary HKDF context hashes for mode 2.

---

#### `transcript.rs` — TLS 1.3 handshake hash oracle

**Goal:** Compute **`transcript_hash(after_server_hello)`** and **`after_server_finished`**
([RFC 8446 §4.4.1](https://www.rfc-editor.org/rfc/rfc8446#section-4.4.1)) for notary-side
verification and reference HKDF.

**Method:** Parse TLS records, decrypt handshake traffic (using reference keys or 2PC-derived
keys in tests), walk handshake messages.

**Used by:** `handshake::verify_handshake_capture`, mode-2 binding hashes.

---

#### `tls.rs` — Record bridge & rustls glue

**Goal:** Framing over **`swanky_channel::Channel`**, compose ECDH + HKDF + AES into a
session workers can drive from **`notary_demo`** / **rustls**.

| Layer | Types / functions |
|-------|-------------------|
| TLS record crypto helpers | `tls13_nonce`, `tls13_aad` ([RFC 8446 §5.3](https://www.rfc-editor.org/rfc/rfc8446#section-5.3)) |
| Standalone 2PC record API | `TwoPartyGcmEncrypter`, `NotaryTlsSession` |
| rustls integration | `ClientWorker` (thread + mpsc), `run_notary_worker`, `run_notary_worker_attested` |
| Mode 2 HKDF | `client_run_2pc_traffic_hkdf`, `run_notary_worker_attested_2pc`, `TwoPcTrafficSetup` |
| Attestation | `OP_ENCRYPT=0x01`, `OP_DECRYPT=0x02`, `OP_FINISH=0x03`, `OP_2PC_HKDF=0x04` |
| I/O adapter | `ChannelRw` (Read/Write over Channel), `notary_ecdh_after_setup_ivs` |

**Result:** Signed **`NotaryBundle`** at `OP_FINISH`; per-record **`RecordCommit`** list.

---

### 6.2 Notary binaries (`notary/src/bin/`)

| Binary | Purpose |
|--------|---------|
| **`notary_proxy`** | Listen TCP; setup modes 0/1/2; run attested worker; Ed25519 sign bundles |
| **`notary_demo`** | Host client: rustls fetch + notary channel; modes 1/2; optional `--witness-out` |
| **`notary_verify`** | Offline bundle signature + optional witness cross-check |
| **`ecdh_2pc_sanity`** | ECDH wire self-test (leaky / OT) |
| **`gen_sha256_compress`** | Dev tool: emit Bristol SHA-256 compress circuit |

---

### 6.3 Bundled assets

| Path | Content |
|------|---------|
| `notary/circuits/AES-non-expanded.txt` | AES-128 block cipher, Bristol |
| `notary/circuits/sha-256-compress.txt` | SHA-256 compression function (~128k ANDs) |
| `notary/notary_signing.key` | Local Ed25519 signing key (gitignored in prod) |

---

## 7. Crypto primitive reference table

| Primitive | Standard / paper | Where used | Why | Output |
|-----------|------------------|------------|-----|--------|
| **X25519 ECDH** | RFC 7748 | Host TLS, guest self-prove, `ecdh.rs` | TLS 1.3 key agreement | 32-byte IKM → HKDF |
| **HKDF-SHA256** | RFC 5869, RFC 8446 §7 | Guest, `hkdf.rs` (2PC) | Derive traffic keys / IVs | `key`, `iv` shares |
| **HMAC-SHA256** | RFC 2104 | HKDF-Extract/Expand, Finished verify | PRF for HKDF and TLS MAC | 32-byte tags / PRK shares |
| **SHA-256** | FIPS 180-4 | Transcript hashes, commits, guest | Binding & integrity | 32-byte digests |
| **AES-128-GCM** | SP 800-38D | Guest, `aes.rs` (2PC) | TLS record protection | Ciphertext + 16-byte tag |
| **GHASH** | GCM spec | `ghash.rs` | Universal hash for GCM tag | 128-bit accumulator shares |
| **Ed25519** | RFC 8032 | `NotaryBundle` | Notary attestation signatures | 64-byte sig |
| **Garbled circuits (Yao)** | Yao 1986 | swanky / twopac | Private evaluation of AES/SHA | Secret-shared wire labels |
| **WRK17 auth garbling** | ePrint 2017/116 | `garble.rs` | Malicious-security AND gates | Authenticated wire labels |
| **OT extension (KOS)** | ePrint 2015/546 | `AndTripleGenerator` | Cheap AND triples for garbling | OT sessions |
| **Chou–Orlandi OT** | ePrint 2015/267 | semihonest tests | Base OT for twopac | 1-out-of-2 OT |
| **Bristol circuits** | MPC community format | `circuits/` | Fixed topology for SHA/AES | Boolean gate lists |

---

## 8. Demo modes (notary)

| Mode byte | Flag | Traffic keys | Handshake trust |
|-----------|------|--------------|-----------------|
| `0` | `--legacy-host-xor-masks` | rustls extract → XOR split | Host-chosen masks |
| `1` | *(default)* | Same + split ephemeral | Notary scalar + OT ECDH |
| `2` | `--two-pc-traffic-keys` | **2PC HKDF** from XOR IKM | **Raw bytes → notary verify** |

**Result (mode 2):** Host never calls `dangerous_extract_secrets()` for **record** keys;
notary binds HKDF to verified transcript + cert hash in **`SessionBinding`**.

---

## 9. External projects & further reading

| Resource | Relation to this repo |
|----------|----------------------|
| [Succinct SP1 docs](https://docs.succinct.xyz/) | Prover/verifier for `guest` |
| [sp1-patches](https://github.com/sp1-patches) | zkVM crypto acceleration in root `Cargo.toml` |
| [Galois swanky](https://github.com/GaloisInc/swanky) | MPC garbling / OT (`notary` deps) |
| [TLSNotary / tlsn](https://github.com/tlsnotary/tlsn) | Production zkTLS + MPC direction |
| [mpz](https://github.com/privacy-scaling-explorations/mpz) | OT-MtA toolkit (future ECDH) |
| [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446) | TLS 1.3 |
| [WRK17 paper](https://eprint.iacr.org/2017/116) | Authenticated garbling |
| [KOS15](https://eprint.iacr.org/2015/546) | OT extension |

---

## 10. Quick command map

```bash
# Self-prove SP1 (from repo root)
cargo run --release -- --url https://example.com --field "/x" --threshold 0

# Notary daemon + demo (from notary/)
cargo build --release --bin notary_proxy --bin notary_demo
./target/release/notary_proxy --listen 127.0.0.1:9001
./target/release/notary_demo --two-pc-traffic-keys --url https://… --notary 127.0.0.1:9001

# Witness → SP1
./target/release/notary_demo … --witness-out witness.bin --field "/x" --threshold 0
cargo run --release -p sp1-demo-host --bin notarized -- --witness-in witness.bin --prove

# Verify bundle offline
./target/release/notary_verify --bundle bundle.bin --outbound out.bin --inbound in.bin

# Fast tests
cd notary && cargo test --release -p notary --lib
```

---

## 11. Summary

- **`common`** — shared witness/bundle types and Ed25519 verify.
- **`host`** — real TLS + capture + SP1 driver; injects external X25519 for provable ephemerals.
- **`guest`** — zkVM: either full TLS verify (self-prove) or notary-backed decrypt + JSON claim.
- **`notary`** — 2PC MPC-TLS: OT ECDH framing, verified handshake (mode 2), WRK17 HKDF/AES/GHASH,
  signed record commits, rustls bridge.

**Cryptographic story:** TLS 1.3 on the wire is unchanged. Privacy comes from **splitting**
keys and running **garbled circuits** (WRK17 + KOS OT) for record crypto and key schedule;
**integrity toward verifiers** comes from **Ed25519 bundles**, **SHA-256 commits**, and
(optionally) **SP1 proofs** over the decrypted claim.

For production gaps and phased delivery, see [`PROD.md`](PROD.md).
