# zkTLS JSON Assertion with SP1

Prove that a JSON field fetched over HTTPS exceeds a threshold — with a zero-knowledge
proof. Two paths live in this repo:

1. **Self-prove (SP1 only)** — host captures raw TLS bytes + `esk_client`; guest re-verifies
   the full TLS 1.3 handshake and cert chain inside the zkVM.
2. **Notary + SP1** — `notary_demo` + `notary_proxy` run split-key 2PC TLS; host exports a
   `TlsWitness` for the SP1 guest notary path (bundle signature + record commits).

No server modification. Real HTTPS. See **[`INFO.md`](INFO.md)** for crate/module map and
**[`DEMO.md`](DEMO.md)** for the notary demo.

| Doc | Purpose |
|-----|---------|
| [`INFO.md`](INFO.md) | Repository guide (crates, modules, crypto) |
| [`DEMO.md`](DEMO.md) | Notary E2E quick start (modes 0–2) |
| [`ECDH.md`](ECDH.md) | ECDH wire protocol |
| [`TODO.md`](TODO.md) | Engineering backlog |
| [`PROD.md`](PROD.md) | Production roadmap |

---

## Path A — Self-prove (default `cargo run`)

### How it works

**Phase 1 — Key generation.**  
The host generates a fresh X25519 ephemeral `(esk_client, epk_client)`. The private key stays
on the host; `epk_client` is injected into the TLS handshake.

**Phase 2 — TLS relay.**  
The host opens TLS 1.3 using `epk_client` ([`host/src/crypto.rs`](host/src/crypto.rs)
`ExternalKxGroup`) and records all raw bytes ([`host/src/stream.rs`](host/src/stream.rs)
`CapturingStream`). The host does **not** pass traffic secrets to the guest.

**Phase 3 — Prove.**  
The host passes `esk_client` and raw wire bytes to the SP1 guest ([`guest/src/main.rs`](guest/src/main.rs)).
The guest:

1. Parses `epk_client` from `ClientHello` key_share
2. Asserts `epk_client == esk_client × G`
3. Parses `epk_server` from `ServerHello` key_share
4. Computes `shared_secret = X25519(esk_client, epk_server)`
5. Derives TLS 1.3 traffic keys via HKDF-SHA256
6. Decrypts handshake records; verifies cert chain (`webpki-roots`), hostname, `CertificateVerify`, Server `Finished`
7. Decrypts application data (AES-128-GCM)
8. Asserts `json[field] > threshold`
9. Commits `{ host, field, threshold, value }` as public outputs

### Threat model (self-prove)

The host knows `esk_client` and can derive `server_write_key`, so a malicious prover could
forge application-data records. This is acceptable when **the user runs the prover on their
own machine** (they attested their own fetch). Delegated proving requires split keys — see
Path B and [`PROD.md`](PROD.md).

---

## Path B — Notary witness + SP1

1. Run **`notary_proxy`** + **`notary_demo`** (mode 2 recommended) — see [`DEMO.md`](DEMO.md).
2. Export witness: `notary_demo … --witness-out witness.bin --field "/x" --threshold 0`
3. Prove: `cargo run --release -p sp1-demo-host --bin notarized -- --witness-in witness.bin [--prove]`

The guest **notary path** verifies the Ed25519 bundle, checks record commit hashes, reconstructs
`K = K_N ⊕ K_C`, decrypts, and runs the JSON claim (no full in-guest cert verify today).

---

## Prerequisites

### Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### SP1 toolchain

```bash
curl -L https://sp1up.succinct.xyz | bash
sp1up
cargo prove --version
```

### Build

From repo root (builds guest ELF via `host/build.rs` on first compile):

```bash
cargo build --release
```

Or build the guest explicitly:

```bash
cd guest && cargo prove build
```

Notary binaries (separate crate):

```bash
cd notary && cargo build --release --bin notary_proxy --bin notary_demo --bin notary_verify
```

---

## Usage (self-prove)

### Execute only (no proof)

```bash
cargo run --release -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000
```

### Mock proof

```bash
SP1_PROVER=mock cargo run --release -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000 \
  --prove
```

### Real STARK proof (~32 GB RAM)

```bash
cargo run --release -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000 \
  --prove
```

Use `SP1_PROVER=mock` on smaller machines.

---

## CLI flags (`host` main)

| Flag | Required | Description |
|------|----------|-------------|
| `--url` | yes | HTTPS URL (TLS 1.3, JSON body) |
| `--field` | yes | JSON pointer (RFC 6901), e.g. `/USD/last` |
| `--threshold` | yes | Guest asserts `value > threshold` |
| `--prove` | no | Generate proof (default: execute only) |

| Variable | Effect |
|----------|--------|
| `SP1_PROVER=mock` | Mock prover (fast, unsound) |
| `SP1_SKIP_PROGRAM_BUILD=1` | Skip guest rebuild (after first build) |

---

## Project structure

```
sp1-demo/
├── Cargo.toml              # Workspace: guest, host, common (+ SP1 crypto patches)
├── common/src/lib.rs       # TlsWitness, NotaryBundle, SessionBinding, PublicClaim
├── guest/src/main.rs       # SP1 zkVM program
├── host/
│   ├── src/crypto.rs       # ExternalKxGroup (inject epk into rustls)
│   ├── src/stream.rs       # CapturingStream
│   ├── src/bin/main.rs     # Self-prove CLI
│   └── src/bin/notarized.rs # Witness file → SP1
├── notary/                 # 2PC MPC-TLS (not in workspace; swanky deps)
│   ├── src/                # aes, ecdh, hkdf, ghash, garble, tls, …
│   └── src/bin/            # notary_proxy, notary_demo, notary_verify
├── DEMO.md, INFO.md, PROD.md, TODO.md, ECDH.md
└── README.md               # this file
```

---

## SP1 precompiles (guest)

| Primitive | Crate | Accelerated |
|-----------|-------|-------------|
| X25519 | `x25519-dalek` | yes (curve25519) |
| SHA-256 | `sha2` | yes |
| P-256 ECDSA | `p256` | yes (patched) |
| RSA | `rsa` | yes (patched) |
| AES-128-GCM | `aes-gcm` | no (software) |
| P-384 ECDSA | `p384` | no |

Patches: root [`Cargo.toml`](Cargo.toml) `[patch.crates-io]`.

---

## Tests & lint

```bash
# SP1 workspace
cargo clippy --all-targets -- -D warnings

# Notary (fast suite ~18 s)
cd notary && cargo test --release -p notary --lib
```

Heavy WRK17 integration tests are `#[ignore]` — see [`TODO.md`](TODO.md).

---

## Limitations

- **Cipher suite:** `TLS_AES_128_GCM_SHA256` only.
- **Real proof RAM:** ~32 GB for full STARK; use mock prover otherwise.
- **Replay / OCSP / HTTP:** not handled — see [`PROD.md`](PROD.md).
- **Self-prove:** host can forge app data; **notary path** trusts notary signature for TLS binding.
- **Production:** demo / research PoC — see [`PROD.md`](PROD.md).
