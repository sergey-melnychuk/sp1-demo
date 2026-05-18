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

## Trust boundary

```
┌─────────────────────────────────────────────┐
│  SP1 GUEST (trusted: proof attests this)    │
│                                             │
│  owns esk_client (never committed publicly) │
│  derives shared_secret, K, server_write_key │
│  decrypts handshake + application records   │
│  asserts predicate over plaintext           │
│  commits: hostname, field, threshold, value │
└─────────────────────────────────────────────┘
         ▲ esk_client + raw TCP bytes only
┌────────┴────────────────────────────────────┐
│  HOST (untrusted relay)                     │
│                                             │
│  knows epk_client (public by definition)    │
│  knows all wire bytes (public TLS record)   │
│  does NOT derive server_write_key           │
│  does NOT see plaintext                     │
└─────────────────────────────────────────────┘
```

The host cannot forge server responses: AES-128-GCM authentication requires `server_write_key`, which only the guest derives. The server's `CertificateVerify` signs the full transcript including `epk_client`, so the host cannot substitute a different key or a different server's bytes.

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
Response body: ...
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
- **Delegated proving:** The entity running the prover knows `esk_client` and therefore `server_write_key`. For self-proving (user runs prover on their own machine) this is not a concern. Delegated proving requires MPC-TLS or a TEE.
