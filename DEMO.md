# Split-key 2PC AES-GCM TLS notary — end-to-end demo

A working zkTLS-style flow: a host fetches an HTTPS resource from a real
third-party server while coordinating with a `notary_proxy` daemon so that
**neither party holds the full TLS session key during the data phase**.

After setup, session keys are split additively between the host and the notary,
and every application record is encrypted/decrypted via split-key 2PC AES-GCM
(garbled circuits over swanky). The ciphertext that hits the wire is
byte-identical to what a normal TLS client would produce — the server has no
idea anything unusual happened.

| Doc | Purpose |
|-----|---------|
| [`INFO.md`](INFO.md) | Full repo guide (crates, modules, crypto) |
| [`README.md`](README.md) | SP1 self-prove + witness overview |
| [`PROD.md`](PROD.md) | Production roadmap |
| [`ECDH.md`](ECDH.md) | ECDH wire protocol |
| [`TODO.md`](TODO.md) | Backlog |

## Demo modes

`notary_proxy` reads a **setup mode byte** on connect. `notary_demo` picks the
mode via flags.

| Mode byte | Flag | Traffic keys | Handshake |
|-----------|------|--------------|-----------|
| `0` | `--legacy-host-xor-masks` | rustls `dangerous_extract_secrets()` → XOR split | stock rustls X25519 |
| `1` | *(default)* | same as mode 0 | split client ephemeral (`ExternalKxGroup`) + post-IV OT ECDH |
| `2` | `--two-pc-traffic-keys` | **2PC HKDF** from OT IKM XOR shares + notary-verified transcript | split ephemeral + OT ECDH; **no extract for record keys** |

**Mode 1 (default)** is the original demo: notary sends XOR mask halves and its
scalar share before TLS; host runs the handshake, extracts AES traffic secrets,
zeros them, then drives the record layer via 2PC.

**Mode 2** (`--two-pc-traffic-keys`) is the production-ish witness path:
OT-blinded ECDH yields XOR-shared IKM; the host sends **raw handshake bytes**
(not precomputed digests); the notary recomputes transcript hashes and cert
binding before **2PC HKDF-SHA256** derives traffic keys. IVs come from the same
schedule (public on the notary side). The host never calls
`dangerous_extract_secrets()` for record-layer keys (unless `--verify-rustls-keys`
is set for a debug cross-check).

> **Honesty limits:** WRK17 for **HKDF compress**, **AES blocks**, and **GHASH**
> (one unrolled chain per record direction); KOS OT extension is reused for the
> whole host↔notary channel via `Wrk17*Session`. The notary is still trusted
> (learns full IKM on the OT path, holds public IVs). Full OT-MtA X25519 is not
> implemented.

## Quick start

From `notary/`:

```bash
# Build release binaries (debug is too slow for 2PC circuits)
cargo build --release --bin notary_proxy --bin notary_demo --bin notary_verify

# Terminal A — notary daemon
./target/release/notary_proxy --listen 127.0.0.1:9001

# Terminal B — default mode 1
./target/release/notary_demo \
    --url https://jsonplaceholder.typicode.com/posts/1 \
    --notary 127.0.0.1:9001
```

### Mode 2 — 2PC HKDF traffic keys

```bash
./target/release/notary_demo \
    --two-pc-traffic-keys \
    --url https://jsonplaceholder.typicode.com/posts/1 \
    --notary 127.0.0.1:9001

# Optional: assert 2PC HKDF keys match rustls extract + reference schedule
./target/release/notary_demo \
    --two-pc-traffic-keys \
    --verify-rustls-keys \
    --url https://jsonplaceholder.typicode.com/posts/1 \
    --notary 127.0.0.1:9001
```

### Verify a signed bundle (third party)

```bash
./target/release/notary_verify \
    --bundle /path/to/bundle.bin \
    --outbound /path/to/raw_outbound.bin \
    --inbound /path/to/raw_inbound.bin
```

Expected wall-clock for a ~1.4 KB response: **~10–30 s** in mode 1, **minutes in
mode 2** (many WRK17 SHA-256 compress rounds for full HKDF before AES). Release builds
are mandatory. Mode 2 E2E against `jsonplaceholder.typicode.com` completes with
HTTP 200 + `verify(): ok` on the signed bundle.

### SP1 witness export (notary → zkVM)

After a successful demo run, export a bincode `TlsWitness` and prove with the SP1 host:

```bash
# Terminal B — mode 2 + witness (example field from JSONPlaceholder post)
./target/release/notary_demo \
    --two-pc-traffic-keys \
    --url https://jsonplaceholder.typicode.com/posts/1 \
    --notary 127.0.0.1:9001 \
    --witness-out /tmp/witness.bin \
    --field "/userId" \
    --threshold 0

# From repo root
SP1_PROVER=mock cargo run --release -p sp1-demo-host --bin notarized -- \
    --witness-in /tmp/witness.bin \
    --prove
```

The guest **notary path** checks the Ed25519 bundle, transcript binding, record commits,
and the JSON claim — it does not re-run full cert/`CertificateVerify` in the zkVM today.
See [`README.md`](README.md) and [`PROD.md`](PROD.md).

### Other flags (mode 1 only)

| Flag | Effect |
|------|--------|
| `--legacy-host-xor-masks` | Mode byte `0`: host sends one 56-byte frame (masks + IVs) after handshake |
| `--skip-ecdh-wire` | Skip post-IV ECDH (`SETUP_ECDH_SKIP`) |
| `--leaky-ecdh-wire` | Cleartext partial-point ECDH instead of OT-blinded (debug) |

## Sample output

**Mode 2** (2PC HKDF + handshake capture):

```
phase 0: connect notary (single Channel session) 127.0.0.1:9001
phase 0a: scalar share received — ClientHello uses split ephemeral
phase 1: TCP+TLS handshake to jsonplaceholder.typicode.com:443
phase 2: 2PC traffic key path (no rustls extract for record keys)
phase 3: handshake capture + OT ECDH on notary channel
phase 3b: host XOR IKM share=... (2PC HKDF next)
phase 4a: 2PC HKDF traffic key schedule (OP_2PC_HKDF)
phase 4: encrypting 93 bytes of HTTP request via 2PC AES-GCM
phase 5: reading response records
--- notary bundle ---
  verify():       ok
--- session binding ---
  server_epk:                 ...
  handshake_transcript_hash:  ...
```

## Architecture

### Mode 2 (`--two-pc-traffic-keys`)

```
   ┌──────────────────────────────────────────────────┐
   │ notary_demo — one Channel::with for whole session│
   │  0.  mode 2 → recv notary scalar                 │
   │  1.  TLS handshake (capture transcript)          │
   │  2.  (optional) verify-rustls-keys               │
   │  3.  HandshakeCapture wire + OT ECDH             │
   │  4a. OP_2PC_HKDF → 2PC TLS 1.3 key schedule      │
   │  4–5. 2PC AES-GCM application records            │
   │  6.  OP_FINISH → signed NotaryBundle (v1)        │
   └──────────────────────────┬───────────────────────┘
                              │
                              ▼
   ┌──────────────────────────────────────────────────┐
   │ notary_proxy                                     │
   │  read HandshakeCapture → ECDH → verify transcript│
   │  → wait OP_2PC_HKDF → run_notary_worker_2pc      │
   └──────────────────────────────────────────────────┘
```

Keep **one** `Channel::with` open for the full host↔notary session in mode 2.

## Mode 2 — witness path detail

1. **Setup (mode byte `2`):** notary sends its clamped scalar share (32 B).
2. **TLS handshake:** host captures `raw_outbound` / `raw_inbound`, `server_epk`,
   and `cert_chain_hash` from rustls peer certificates.
3. **HandshakeCapture wire** (host → notary, before ECDH):

   ```
   server_epk        32 B
   cert_chain_hash   32 B
   outbound_len      4 B BE
   outbound          outbound_len
   inbound_len       4 B BE
   inbound           inbound_len
   ```

4. **OT ECDH:** `SETUP_ECDH_OT ‖ server_epk ‖ host_clamped_share (32 B)` …
5. **Notary verify:** `handshake::verify_handshake_capture` recomputes
   `after_sh` / `after_sf`, checks cert chain + epk; aborts on mismatch.
6. **2PC HKDF:** `OP_2PC_HKDF` → TLS 1.3 client traffic schedule (`hkdf.rs`).
7. **Records + attestation:** 2PC AES-GCM; `OP_FINISH` → **NotaryBundle v1**
   with [`SessionBinding`](common/src/lib.rs) (transcript root, cert hash, circuit
   IDs, garbling mode) in the Ed25519 signature.

## Wire protocol (summary)

| Value | Setup mode |
|-------|------------|
| `0` | Legacy host-chosen XOR masks |
| `1` | Notary XOR masks + scalar; IVs + ECDH |
| `2` | Notary scalar; **HandshakeCapture** + ECDH + HKDF |

Record bridge ops: `0x01` encrypt, `0x02` decrypt, `0x03` finish, `0x04` 2PC HKDF.
See [`ECDH.md`](ECDH.md) for ECDH framing.

## What's implemented vs not

**Implemented (production-ish witness bar):**

- Raw handshake bytes to notary + independent transcript verify (`handshake.rs`)
- Signed bundle v1 with `SessionBinding` + `notary_verify` CLI
- Mode 2 2PC HKDF without host extract for record keys
- **WRK17 authenticated garbling** for HKDF compress, AES blocks, and GHASH
  (`garble.rs`, `hkdf.rs`, `aes.rs`, `ghash.rs`; unrolled GHASH chain + OT session
  reuse on one `Channel::with` in mode 2)

**Not yet:**

- Full OT-MtA X25519
- GCM tag inside circuit
- Batched WRK17 for per-block AES (still one circuit per AES block)
- Unrolled HMAC (4 compresses per HMAC in one WRK17 session)
- SP1 guest: in-circuit full TLS verify on notary path

### Tests & lint

```bash
cd notary
cargo test --release -p notary --lib          # fast suite (~18 s)
cargo clippy --all-targets -- -D warnings
```

Heavy WRK17 integration tests (`hkdf_over_*`, `decrypt_2pc`, …) are `#[ignore]` —
run with `cargo test --release … -- --ignored` when needed.

See [`TODO.md`](TODO.md) for the full gap list.
