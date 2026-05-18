# zkTLS JSON Assertion with SP1

Prove that a JSON field fetched over HTTPS exceeds a threshold — with a zero-knowledge proof anchored to the server's TLS certificate. No trusted oracle. No modification to the server. No MPC.

## How it works

The implementation has three phases:

**Phase 1 — Key generation.**
The host generates a fresh X25519 ephemeral key pair `(esk_client, epk_client)`. The private key never leaves the machine; the public key is injected into the TLS handshake.

**Phase 2 — TLS relay.**
The host opens a real TLS 1.3 connection using `epk_client` (via a custom `rustls` key-exchange hook that accepts an externally-supplied key). It captures all raw inbound and outbound TCP bytes — nothing else. The host does not derive any TLS traffic secrets.

**Phase 3 — Prove.**
The host passes `esk_client` and the raw wire bytes to the SP1 guest. The guest independently performs the full TLS verification pipeline:

1. Parses `epk_client` from the raw `ClientHello` key_share extension
2. Asserts `epk_client == esk_client × G` — closes the authorship gap
3. Parses `epk_server` from the raw `ServerHello` key_share extension
4. Computes `shared_secret = X25519(esk_client, epk_server)`
5. Derives all TLS 1.3 traffic keys via HKDF-SHA256
6. Decrypts the encrypted handshake records (`EncryptedExtensions`, `Certificate`, `CertificateVerify`, `Finished`)
7. Verifies the certificate chain against hardcoded Mozilla root CAs (`webpki-roots`)
8. Checks the server hostname against the leaf cert's SAN
9. Verifies `CertificateVerify` — proving the real server signed this exact transcript
10. Verifies the Server `Finished` HMAC
11. Decrypts application data records with AES-128-GCM
12. Asserts `json[field] > threshold` over the plaintext HTTP response
13. Commits `{ host, field, threshold, value }` as public outputs

## Threat model

```
┌─────────────────────────────────────────────┐
│  SP1 GUEST (proof attests this computation) │
│                                             │
│  re-derives shared_secret, server_write_key │
│  decrypts handshake + application records   │
│  verifies cert chain + CertificateVerify    │
│  asserts predicate over plaintext           │
│  commits: hostname, field, threshold, value │
└─────────────────────────────────────────────┘
         ▲ esk_client + raw TCP bytes
┌────────┴────────────────────────────────────┐
│  HOST                                       │
│                                             │
│  generates esk_client                       │
│  knows epk_server (from raw ServerHello)    │
│  can compute X25519(esk_client, epk_server) │
│  can therefore derive server_write_key      │
│  can forge application-data records         │
└─────────────────────────────────────────────┘
```

**What the proof establishes:** given the witness `(esk_client, raw_inbound, raw_outbound)`, the TLS session is cryptographically valid — real cert chain, real `CertificateVerify`, authenticated decryption — and the JSON field exceeds the threshold.

**What the proof does not establish:** that the witness was not constructed by the prover. The host knows `esk_client` and `epk_server`, so it can compute `server_write_key` and encrypt arbitrary application-data records. `CertificateVerify` covers only the handshake transcript; it does not cover application data.

**Self-proving threat model (current scope):** the user runs the prover on their own machine. They made a real request; they have the real data. The proof lets them attest a single field to a third party without sharing the full response. A user has no incentive to forge their own data for their own proof. This is the valid use case for this implementation.

**Out of scope:** delegated proving — where a third party runs the prover on a user's behalf — requires that the prover never holds `server_write_key` in full. That requires splitting the session key across parties, which is a substantially harder problem.

## Prerequisites

### 1. Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. Install SP1 toolchain

```bash
curl -L https://sp1up.succinct.xyz | bash
sp1up
```

This installs `cargo-prove` and the `riscv64im-succinct-zkvm-elf` target.
Verify with:

```bash
cargo prove --version
```

### 3. Clone and build

```bash
git clone https://github.com/sergey-melnychuk/sp1-demo
cd sp1-demo
cd program && cargo prove build && cd ..
```

## Usage

### Execute only (no proof, fastest)

Runs the full verification pipeline inside the SP1 zkVM executor without generating a proof. Good for development and checking correctness.

```bash
cargo run --release -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000
```

Expected output:
```
phase 1: epk_client generated (32 bytes)
Response: ...
phase 2: inbound=10825 bytes, outbound=480 bytes
Execution succeeded (no proof generated).
   host:      blockchain.info
   field:     /USD/last
   threshold: 1000
   value:     76468.06
   cycles:    20857618
```

### Generate a mock proof (instant, no RAM requirement)

Uses SP1's mock prover — cryptographically unsound but structurally identical to a real proof. Useful for testing the full prove → verify flow locally.

```bash
SP1_PROVER=mock cargo run --release -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000 \
  --prove
```

Output: `proof.bin` (proof + public values). The script verifies the proof immediately after generation and prints `Proof verified.`

### Generate a real STARK proof (requires ~32 GB RAM)

```bash
cargo run --release -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000 \
  --prove
```

Verified working on a 32 GB machine. On machines with less RAM use the mock prover or the Succinct prover network.

## CLI flags

| Flag | Required | Description |
|---|---|---|
| `--url` | ✅ | HTTPS URL to fetch (must be TLS 1.3, JSON response) |
| `--field` | ✅ | JSON pointer (RFC 6901) to the numeric field, e.g. `/USD/last` |
| `--threshold` | ✅ | The guest asserts `value > threshold` |
| `--prove` | ❌ | Generate a proof (default: execute only) |

## Build environment variables

| Variable | Effect |
|---|---|
| `SP1_SKIP_PROGRAM_BUILD=1` | Skip rebuilding the guest ELF (set after first build) |
| `SP1_PROVER=mock` | Use the mock prover (no real cryptography, instant) |
| `SP1_PROVER=network` | Submit to the Succinct prover network |

## Project structure

```
sp1-demo/
├── program/src/main.rs     guest: full TLS parsing + verification + JSON assertion
├── script/src/
│   ├── main.rs             CLI: three-phase orchestration (keygen → relay → prove)
│   ├── capture.rs          ExternalKxGroup (injects pre-generated epk_client into
│   │                       rustls) + CapturingStream (raw byte recording)
│   └── keygen.rs           Phase 1: generate (esk_client, epk_client) locally
└── shared/src/lib.rs       TlsWitness + PublicClaim (shared between host and guest)
```

## SP1 precompiles active

| Primitive | Crate | Accelerated |
|---|---|---|
| X25519 ECDH | `x25519-dalek` | ✅ curve25519 precompile |
| SHA-256 | `sha2` | ✅ SHA256 precompile |
| P-256 ECDSA | `p256` | ✅ patched elliptic-curves |
| RSA | `rsa` | ✅ pinned to `=0.9.6`, patched |
| AES-128-GCM | `aes-gcm` | ❌ software (no SP1 precompile) |
| P-384 ECDSA | `p384` | ❌ software (no SP1 patch; not used by blockchain.info) |

## Limitations

- **Real proof RAM:** A real STARK proof requires ~32 GB RAM. Use `SP1_PROVER=mock` on smaller machines.
- **Cipher suite:** Only `TLS_AES_128_GCM_SHA256` is negotiated. ChaCha20-Poly1305 and AES-256-GCM are not yet supported.
- **Replay:** The proof does not prevent replaying an old valid session. Mitigation: add a timestamp or nonce assertion (see `NEXT.md §2`).
- **Certificate revocation:** OCSP is not checked — too expensive inside the zkVM.
- **Tail record omission:** The host could withhold the last N application-data records. Middle-record omission is caught by AES-GCM authentication (wrong nonce → wrong tag). Tail omission requires HTTP response completeness verification (see `NEXT.md §4`).
- **Self-proving only:** The host knows `esk_client` and can derive `server_write_key`, so a dishonest prover can forge application-data records. The design is sound when the user runs the prover on their own machine; see the threat model above.
