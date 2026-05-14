# zkTLS JSON Assertion with SP1

Prove that a JSON field fetched over HTTPS exceeds a threshold — with a zero-knowledge proof anchored to the server's TLS certificate. No trusted oracle. No modification to the server.

## How it works

The host makes a real TLS 1.3 connection, captures the raw wire bytes and the client ephemeral ECDH private key, then hands a `TlsWitness` to the SP1 guest. The guest independently:

1. Verifies the certificate chain against hardcoded Mozilla root CAs (`webpki-roots`)
2. Checks the server hostname against the leaf cert's SAN
3. Verifies the `CertificateVerify` signature — proving the real server participated
4. Re-derives traffic keys via X25519 + HKDF-SHA256 — nothing can be forged without the server's private key
5. Decrypts the application records with AES-128-GCM
6. Asserts `json[field] > threshold` and commits the result publicly

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

# Build the guest ELF (runs cargo prove build inside program/)
SP1_SKIP_PROGRAM_BUILD=1 cargo build --release --manifest-path script/Cargo.toml
```

Or build the guest separately first:

```bash
cd program
cargo prove build
cd ..
```

## Usage

### Execute only (no proof, fastest)

Runs the full verification pipeline inside the SP1 zkVM executor without generating a proof. Good for development and checking correctness.

```bash
SP1_SKIP_PROGRAM_BUILD=1 cargo run --release \
  --manifest-path script/Cargo.toml \
  --bin sp1-https-json-script -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000
```

Expected output:
```
host:      blockchain.info
field:     /USD/last
threshold: 1000
value:     79349.99
cycles:    21202056
```

### Generate a mock proof (instant, no RAM requirement)

Uses SP1's mock prover — cryptographically unsound but structurally identical to a real proof. Useful for testing the full prove → verify flow locally.

```bash
SP1_PROVER=mock SP1_SKIP_PROGRAM_BUILD=1 cargo run --release \
  --manifest-path script/Cargo.toml \
  --bin sp1-https-json-script -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000 \
  --prove
```

Output: `proof.bin` (proof + public values). The script verifies the proof immediately after generation and prints `Proof verified.`

### Generate a real STARK proof (requires ~32–64 GB RAM)

```bash
SP1_SKIP_PROGRAM_BUILD=1 cargo run --release \
  --manifest-path script/Cargo.toml \
  --bin sp1-https-json-script -- \
  --url "https://blockchain.info/ticker" \
  --field "/USD/last" \
  --threshold 1000 \
  --prove
```

On a machine without enough RAM this will be OOM-killed. Use the mock prover or the Succinct prover network for local development.

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
├── program/src/main.rs     guest: TLS verification + JSON assertion (runs in SP1 zkVM)
├── script/src/
│   ├── main.rs             CLI entry point
│   ├── capture.rs          CapturingStream + CapturingKxGroup (raw byte + key capture)
│   ├── keylog.rs           KeyLog impl — captures SERVER_HANDSHAKE_TRAFFIC_SECRET
│   └── witness.rs          TLS record parser → TlsWitness assembler
└── shared/src/lib.rs       TlsWitness struct (shared between host and guest)
```

## Limitations

- **Real proof RAM:** A real STARK proof requires 32–64 GB RAM. Use `SP1_PROVER=mock` locally.
- **Cipher suite:** Only `TLS_AES_128_GCM_SHA256` is negotiated. ChaCha20-Poly1305 and AES-256-GCM
  are not yet supported in the guest decryption path.
- **Replay:** The proof does not prevent replaying an old session. For high-stakes use, add a
  timestamp or nonce assertion (e.g. `--field /timestamp --threshold <yesterday's epoch>`).
- **Certificate revocation:** OCSP is not checked — too expensive inside the zkVM.
