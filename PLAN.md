# zkTLS JSON Assertion — Design and Implementation

## Goal

Generate a ZK proof that says:
> "A server whose TLS certificate chains to a trusted root CA participated in a handshake
> that produced a response whose JSON field `/USD/last` is greater than `1000`."

No trusted third party. No oracle. No MPC. The server's own certificate is the trust anchor.

---

## Trust Model

TLS 1.3's **CertificateVerify** message is the key. The server signs the entire handshake
transcript with its certificate private key. This means:

- If the guest verifies the cert chain → the certificate is legitimately issued
- If the guest verifies CertificateVerify → the real server (holder of the cert's private key) participated in this exact handshake
- If the guest derives traffic keys from the handshake → the decrypted plaintext is what the server sent
- The prover **cannot forge any of this** without the server's private key

The guest does not need network access. It is a pure function over `esk_client` + raw wire bytes.

### Trust boundary

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

### Why the host cannot forge

`epk_client` appears inside `ClientHello` key_share. The server's `CertificateVerify`
signs the full handshake transcript, which covers `ClientHello`. The guest proves
`epk_client = esk_client × G` matches the transcript. The host cannot substitute a
different `epk_client` without invalidating `CertificateVerify`. Therefore ciphertext
encrypted under `server_write_key(K)` where `K = HKDF(esk_client × epk_server)` cannot
be forged by the host: it does not know `esk_client` in the context of a live session.

### What the proof does NOT cover

- The prover could replay an old valid session (mitigation: timestamp/nonce assertion in JSON — see `NEXT.md §2`)
- The prover could withhold tail application-data records without detection (mitigation: HTTP response completeness check — see `NEXT.md §4`)
- The guest trusts hardcoded root CAs — if a CA is compromised, the proof is compromised
- Certificate revocation is not checked (OCSP inside guest is too expensive)

---

## Three-Phase Execution Model

### Phase 1 — Key generation (`script/src/keygen.rs`)

Generate a fresh X25519 key pair locally:

```rust
let esk = StaticSecret::random_from_rng(rand::thread_rng());
let epk = PublicKey::from(&esk);
// esk stays in memory; epk is injected into ClientHello
```

For production, `esk_client` should never touch disk unencrypted; pass in-memory between phases.

### Phase 2 — TLS relay (`script/src/main.rs` + `script/src/capture.rs`)

The host opens a real TLS 1.3 connection using a custom rustls key-exchange hook
(`ExternalKxGroup`) that accepts `esk_client` externally instead of generating one.
`CapturingStream` records all raw inbound and outbound TCP bytes.

The host derives **no** TLS traffic secrets. It captures:
- All raw inbound bytes (ServerHello, encrypted HS records, encrypted app records)
- All raw outbound bytes (ClientHello, ClientFinished)

### Phase 3 — Prove (`program/src/main.rs`)

Guest receives `TlsWitness { esk_client, raw_inbound, raw_outbound, ... }` and:

1. Parses `ClientHello` from `raw_outbound` → extracts `epk_client_wire`
2. Asserts `PublicKey::from(&StaticSecret::from(esk_client)) == epk_client_wire`
3. Parses `ServerHello` from `raw_inbound` → extracts `epk_server`
4. `shared_secret = X25519(esk_client, epk_server)`
5. Full HKDF-SHA256 key schedule → `server_hs_secret`, `master_secret`
6. Decrypts encrypted handshake records in-guest using `server_hs_secret`
7. Collects `EE`, `Certificate`, `CertificateVerify`, `Finished` messages from decrypted payload
8. Verifies `Finished` HMAC
9. Verifies cert chain against `webpki-roots`
10. Verifies hostname (SAN)
11. Verifies `CertificateVerify` signature
12. Derives app traffic key from `master_secret` + full transcript hash
13. Decrypts application records
14. Parses HTTP, unchunks, evaluates JSON predicate
15. Commits `PublicClaim { host, field, threshold, value }`

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    HOST (script crate)                      │
│                                                             │
│  keygen::generate()                                         │
│    → (esk_client: [u8;32], epk_client: [u8;32])             │
│                                                             │
│  ExternalKxGroup { esk_client }                             │
│    → rustls uses epk_client in ClientHello key_share        │
│    → completes X25519 normally (host needs it to finish HS) │
│                                                             │
│  CapturingStream                                            │
│    → records every raw byte in both directions              │
│                                                             │
│  TlsWitness {                                               │
│    esk_client, raw_inbound, raw_outbound,                   │
│    hostname, json_field, threshold, now_unix                │
│  }  →  sp1_zkvm::io::write()                                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                     GUEST (program crate)                    │
│                                                              │
│  parse CH key_share → epk_client_wire                        │
│  assert epk_client_wire == esk_client × G                    │
│  parse SH key_share → epk_server                             │
│  X25519(esk_client, epk_server) → shared_secret              │
│  HKDF → hs_key, hs_iv, master_secret                         │
│  decrypt HS records → EE, Cert, CertVerify, Finished         │
│  verify Finished HMAC                                        │
│  verify cert chain → webpki-roots                            │
│  verify hostname (SAN)                                       │
│  verify CertificateVerify (P-256 / P-384 / RSA-PSS / PKCS1)  │
│  HKDF → app_key, app_iv                                      │
│  decrypt app records (AES-128-GCM, seq-nonce)                │
│  unchunk HTTP → serde_json → json[field] > threshold         │
│  commit(PublicClaim)                                         │
└──────────────────────────────────────────────────────────────┘
```

---

## Data Model

```rust
// shared/src/lib.rs — passed host → guest via SP1 stdin
pub struct TlsWitness {
    pub esk_client: [u8; 32],      // X25519 private scalar (phase 1 output)
    pub raw_inbound: Vec<u8>,      // all bytes received from server
    pub raw_outbound: Vec<u8>,     // all bytes sent to server
    pub hostname: String,
    pub json_field: String,
    pub threshold: f64,
    pub now_unix: i64,
}

// Committed as public outputs
pub struct PublicClaim {
    pub host: String,
    pub field: String,
    pub threshold: f64,
    pub value: f64,
}
```

---

## Key Schedule (TLS 1.3, RFC 8446 §7.1)

```
shared_secret = X25519(esk_client, epk_server)

early_secret       = HKDF-Extract(salt=0×00·32, ikm=0×00·32)
derived1           = HKDF-Expand-Label(early_secret, "derived", SHA256(""), 32)
hs_secret          = HKDF-Extract(salt=derived1, ikm=shared_secret)
server_hs_secret   = HKDF-Expand-Label(hs_secret, "s hs traffic", transcript_after_sh, 32)
derived2           = HKDF-Expand-Label(hs_secret, "derived", SHA256(""), 32)
master_secret      = HKDF-Extract(salt=derived2, ikm=0×00·32)
server_app_secret  = HKDF-Expand-Label(master_secret, "s ap traffic", transcript_after_fin, 32)
app_key            = HKDF-Expand-Label(server_app_secret, "key", "", 16)
app_iv             = HKDF-Expand-Label(server_app_secret, "iv",  "", 12)
```

Handshake records decrypted with `server_hs_secret`-derived key/iv.
Application records decrypted with `app_key` / `app_iv`.

---

## AES-GCM Record Decryption

```
nonce    = app_iv XOR seq_num_as_12_byte_be   (seq starts at 0 for each key)
aad      = 5-byte TLS record header
plaintext = AES-128-GCM-Decrypt(key=app_key, nonce, aad, ciphertext)
inner_ct = plaintext[-1]  // strip inner content type byte (RFC 8446 §5.2)
```

Middle-record omission is caught automatically: wrong seq → wrong nonce → wrong tag → GCM auth failure.

---

## SP1 Precompiles

| Primitive | Crate | Status |
|---|---|---|
| X25519 ECDH | `x25519-dalek` | ✅ curve25519 precompile |
| SHA-256 | `sha2` | ✅ SHA256 precompile |
| P-256 ECDSA | `p256` | ✅ patched elliptic-curves |
| BigInt (RSA) | `crypto-bigint` | ✅ patched |
| RSA verify | `rsa` | ✅ pinned `=0.9.6`, patched |
| AES-128-GCM | `aes-gcm` | ❌ software |
| P-384 ECDSA | `p384` | ❌ software (no SP1 patch) |

RSA must be pinned to `=0.9.6` in `program/Cargo.toml`; the workspace patch targets that version. Resolving `0.9.10` (the crates.io default) silently skips the patch.

---

## Directory Structure

```
sp1-demo/
├── program/src/main.rs     guest: TLS parsing, key schedule, verification, JSON assert
├── script/src/
│   ├── main.rs             CLI: three-phase orchestration
│   ├── capture.rs          ExternalKxGroup + CapturingStream
│   └── keygen.rs           Phase 1: X25519 key pair generation
└── shared/src/lib.rs       TlsWitness + PublicClaim
```

Deleted (no longer needed):
- `script/src/keylog.rs` — host-side HS decryption; guest now decrypts independently
- `script/src/witness.rs` — host-side record parser; guest now parses from raw bytes

---

## Implementation Status (2026-05-18)

### ✅ Fully Working End-to-End

The pipeline passes for `https://blockchain.info/ticker` with field `/USD/last` threshold `1000`.

```
SP1_SKIP_PROGRAM_BUILD=1 cargo run --release --package sp1-https-json-script -- \
  --url https://blockchain.info/ticker --field /USD/last --threshold 1000
```

**~20.9M cycles** (execute mode, all precompiles active).

| Component | File | Notes |
|---|---|---|
| Key generation | `script/src/keygen.rs` | X25519 key pair, phase 1 |
| `ExternalKxGroup` | `script/src/capture.rs` | Injects pre-generated `esk_client` into rustls |
| `CapturingStream` | `script/src/capture.rs` | Records raw inbound + outbound bytes |
| Three-phase orchestration | `script/src/main.rs` | keygen → relay → witness → SP1 |
| `TlsWitness` | `shared/src/lib.rs` | `esk_client` + raw bytes only |
| Authorship assertion | `program/src/main.rs` | `epk_client_wire == esk_client × G` |
| CH/SH key_share parsing | `program/src/main.rs` | Extracts epk_client and epk_server from raw records |
| In-guest HS decryption | `program/src/main.rs` | Decrypts EE/Cert/CertVerify/Finished |
| Transcript integrity | `program/src/main.rs` | Four transcript hashes computed in-guest |
| Server Finished HMAC | `program/src/main.rs` | Proves server completed handshake |
| Cert chain verification | `program/src/main.rs` | ECDSA-P256, ECDSA-P384, RSA-PSS, RSA-PKCS1 + webpki-roots |
| CertificateVerify | `program/src/main.rs` | Schemes: 0x0403, 0x0503, 0x0804, 0x0805, 0x0401 |
| Hostname check | `program/src/main.rs` | Leaf cert SAN, wildcard support |
| App traffic key derivation | `program/src/main.rs` | HKDF from master_secret + full transcript hash |
| AES-128-GCM decryption | `program/src/main.rs` | Per-record seq-nonce; GCM enforces middle-omission detection |
| Chunked HTTP decoder | `program/src/main.rs` | Handles `Transfer-Encoding: chunked` |
| Session ticket filter | `program/src/main.rs` | Skips NewSessionTicket (inner_ct=22) |
| JSON predicate | `program/src/main.rs` | RFC 6901 pointer + `f64` comparison |
| Public claim commit | `program/src/main.rs` | `{ host, field, threshold, value }` |

### Known open items

See `NEXT.md` for detailed notes. Short list:

- Replay prevention (`--freshness-field`)
- HTTP tail-record completeness check
- `f64` → integer arithmetic for financial values
- ChaCha20-Poly1305 / AES-256-GCM decryption paths
- Stricter PKIX (validity window, EKU, basic constraints)
- Succinct prover network integration
