# Split-key 2PC AES-GCM TLS notary — end-to-end demo

A working zkTLS-style flow: a host fetches an HTTPS resource from a real
third-party server while coordinating with a `notary_proxy` daemon so that
**neither party holds the full TLS session key during the data phase**.

After setup, session keys are split additively between the host and the notary,
and every application record is encrypted/decrypted via split-key 2PC AES-GCM
(garbled circuits over swanky). The ciphertext that hits the wire is
byte-identical to what a normal TLS client would produce — the server has no
idea anything unusual happened.

## Demo modes

`notary_proxy` reads a **setup mode byte** on connect. `notary_demo` picks the
mode via flags.

| Mode byte | Flag | Traffic keys | Handshake |
|-----------|------|--------------|-----------|
| `0` | `--legacy-host-xor-masks` | rustls `dangerous_extract_secrets()` → XOR split | stock rustls X25519 |
| `1` | *(default)* | same as mode 0 | split client ephemeral (`ExternalKxGroup`) + post-IV OT ECDH |
| `2` | `--two-pc-traffic-keys` | **2PC HKDF** from OT IKM XOR shares + transcript hashes | split ephemeral + OT ECDH; **no extract for record keys** |

**Mode 1 (default)** is the original demo: notary sends XOR mask halves and its
scalar share before TLS; host runs the handshake, extracts AES traffic secrets,
zeros them, then drives the record layer via 2PC.

**Mode 2** (`--two-pc-traffic-keys`) is the `TODO.md` #1 key-schedule iteration:
OT-blinded ECDH yields XOR-shared IKM; a multi-round **2PC HKDF-SHA256**
derives client traffic keys from transcript hashes (`after ServerHello`,
`after ServerFinished`); IVs come from the same schedule (public on the notary
side). The host never calls `dangerous_extract_secrets()` for record-layer keys
(unless `--verify-rustls-keys` is set for a debug cross-check).

> **Honesty limits (both modes):** semi-honest 2PC only; the notary is trusted
> in this demo (learns full IKM in the OT path, holds public IVs, signs the
> bundle). Mode 2 still uses a host-side `reference_ikm` oracle to parse the
> handshake transcript. Full OT-MtA X25519 is not implemented.

## Quick start

From `notary/`:

```bash
# Build release binaries (debug is too slow for 2PC circuits)
cargo build --release --bin notary_proxy --bin notary_demo

# Terminal A — notary daemon
./target/release/notary_proxy --listen 127.0.0.1:9001

# Terminal B — default mode 1
./target/release/notary_demo \
    --url https://jsonplaceholder.typicode.com/posts/1 \
    --notary 127.0.0.1:9001
```

### Mode 2 — 2PC HKDF traffic keys

```bash
# Same notary_proxy; mode is chosen by the host on connect
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

Expected wall-clock for a ~1.4 KB response: **~10–30 s** in mode 1, **longer in
mode 2** (extra HKDF rounds before AES). Release builds are mandatory. See
`TODO.md` #9–#10 for performance work.

### Other flags (mode 1 only)

| Flag | Effect |
|------|--------|
| `--legacy-host-xor-masks` | Mode byte `0`: host sends one 56-byte frame (masks + IVs) after handshake |
| `--skip-ecdh-wire` | Skip post-IV ECDH (`SETUP_ECDH_SKIP`) |
| `--leaky-ecdh-wire` | Cleartext partial-point ECDH instead of OT-blinded (debug) |

## Sample output

**Mode 1** (extract + XOR split):

```
phase 0a: connect notary for notary-chosen XOR masks ...
phase 1: TCP+TLS handshake to jsonplaceholder.typicode.com:443
phase 2: traffic secrets extracted (tx_seq=0, rx_seq=0)
phase 3b: OT-blinded ECDH (server epk from ServerHello)
phase 4: encrypting 93 bytes of HTTP request via 2PC AES-GCM
phase 5: reading response records
--- response (1429 bytes) ---
HTTP/1.1 200 OK
...
--- notary bundle ---
  verify():       ok
```

**Mode 2** (2PC HKDF):

```
phase 0: connect notary (single Channel session) 127.0.0.1:9001
phase 0a: scalar share received — ClientHello uses split ephemeral
phase 1: TCP+TLS handshake to jsonplaceholder.typicode.com:443
phase 2: 2PC traffic key path (no rustls extract for record keys)
phase 3: transcript + OT ECDH on notary channel
phase 3b: host XOR IKM share=... (2PC HKDF next)
phase 4a: 2PC HKDF traffic key schedule (OP_2PC_HKDF)
phase 4: encrypting 93 bytes of HTTP request via 2PC AES-GCM
phase 5: reading response records
--- notary bundle ---
  verify():       ok
```

## Architecture

### Mode 1 (default)

```
                  HTTPS server
                                ▲   │
                       TLS 1.3  │   │  application records
                                │   ▼
   ┌──────────────────────────────────────────────────┐
   │ notary_demo (host)                               │
   │  0a. recv K_N + notary scalar (mode 1)           │
   │  1.  rustls handshake (split ephemeral)          │
   │  2.  extract secrets → XOR split → zeroize       │
   │  3.  IV_tx||IV_rx + OT ECDH on notary TCP        │
   │  4–5. 2PC AES-GCM records (one Channel session)  │
   └──────────────────────────┬───────────────────────┘
                              │ swanky Channel
                              ▼
   ┌──────────────────────────────────────────────────┐
   │ notary_proxy                                     │
   │  setup → run_notary_worker_attested (OP 0x01/02) │
   └──────────────────────────────────────────────────┘
```

### Mode 2 (`--two-pc-traffic-keys`)

```
   ┌──────────────────────────────────────────────────┐
   │ notary_demo — one Channel::with for whole session│
   │  0.  mode 2 → recv notary scalar                 │
   │  1.  TLS handshake (capture transcript)          │
   │  2.  (optional) verify-rustls-keys               │
   │  3.  after_sh||after_sf + OT ECDH                │
   │  4a. OP_2PC_HKDF → 2PC TLS 1.3 key schedule      │
   │  4–5. 2PC AES-GCM application records            │
   │  6.  OP_FINISH → signed NotaryBundle             │
   └──────────────────────────┬───────────────────────┘
                              │
                              ▼
   ┌──────────────────────────────────────────────────┐
   │ notary_proxy                                     │
   │  setup mode 2 → OT ECDH → wait OP_2PC_HKDF       │
   │  → run_notary_worker_attested_2pc                │
   └──────────────────────────────────────────────────┘
```

Keep **one** `Channel::with` open for the full host↔notary session in mode 2
(setup, ECDH, HKDF, and every record). Opening a second channel on the same TCP
stream loses buffer state.

## What happens, phase by phase

### Shared: TLS 1.3 handshake

The host runs rustls with `TLS_AES_128_GCM_SHA256`. In modes 1 and 2 the
ClientHello uses a **split client ephemeral**: `combined_client_esk(host_share,
notary_share)` injected via `ExternalKxGroup`. After the server's Finished, the
host drains post-handshake records (e.g. `NewSessionTicket`).

### Mode 1 — extract and XOR split

1. **Extract:** `dangerous_extract_secrets()` → full `K_tx`, `K_rx`, IVs.
2. **Split:** `K_C = K_full XOR K_N`; zero full keys on the host.
3. **Notary setup:** host sends `IV_tx || IV_rx`, then OT ECDH (or skip / leaky).
4. **Records:** 2PC encrypt/decrypt with pre-split keys.

The host briefly holds full AES keys between extract and zeroize — the main gap
mode 2 addresses for the **record layer**.

### Mode 2 — 2PC key schedule

1. **Setup (mode byte `2`):** notary sends its clamped scalar share (32 B).
2. **Transcript hashes:** host parses captured handshake bytes with
   `transcript_hashes_with_ikm` → `after_sh` (hash after ServerHello) and
   `after_sf` (hash after ServerFinished).
3. **OT ECDH:** host sends `after_sh || after_sf`, then
   `SETUP_ECDH_OT || server_epk || host_clamped_share (32 B)` and runs blinded
   point addition. Host receives only `host_ikm_share`; notary holds
   `notary_ikm_share` and full IKM (trusted demo).
4. **2PC HKDF:** host sends `OP_2PC_HKDF` (see wire format below). Both sides
   run the TLS 1.3 client traffic schedule under 2PC (`hkdf.rs`): Extract with
   XOR-shared IKM, Expand-Label for `c ap traffic` / `s ap traffic`, then `key`
   / `iv` leaves. Result: `K_C_tx`, `K_C_rx` XOR shares; IVs are public.
5. **Records + attestation:** same 2PC AES-GCM bridge as mode 1; session ends
   with `OP_FINISH` and an Ed25519-signed `NotaryBundle`.

## Wire protocol on the swanky channel

All multi-byte integers are big-endian unless noted.

### Setup mode byte (first byte from host)

| Value | Meaning |
|-------|---------|
| `0` | Legacy: host sends 56 B `K_N_tx ‖ IV_tx ‖ K_N_rx ‖ IV_rx` |
| `1` | Notary sends 32 B XOR masks + 32 B scalar; host sends IVs + ECDH |
| `2` | Notary sends 32 B scalar; host sends 64 B transcript + ECDH + HKDF |

### Post-IV ECDH (modes 1 and 2)

After IVs (mode 1) or transcript (mode 2), the host sends:

```
SETUP_ECDH_*   1 B     0 = skip, 1 = leaky, 2 = OT (default)
server_epk     32 B    from ServerHello key_share
host_share     32 B    clamped host scalar (TLS-compatible IKM derivation)
<protocol body>        leaky partials or OT-blinded points (see ECDH.md)
```

The host clamped share lets the notary compute TLS-correct IKM via
`reference_ikm` (RFC 7748 clamp on the combined scalar), matching rustls.

### Record bridge (both modes)

One frame per 2PC operation:

```
op           1 B     0x01 encrypt, 0x02 decrypt, 0x03 finish, 0x04 2PC HKDF
seq          8 B     TLS sequence number (0 for HKDF / finish)
aad_len      2 B
aad          aad_len
payload_len  4 B     0 for HKDF / finish
<2PC payload>
```

- **0x04 (`OP_2PC_HKDF`):** multi-round garbled HKDF; no payload in the header.
- **0x03 (`OP_FINISH`):** host sends session metadata; notary replies with a
  signed bincode `NotaryBundle`.

Encrypt/decrypt frames are followed by ciphertext + tag bytes on the channel so
the notary can commit to the exact wire bytes.

## What's _not_ in this demo

- **Malicious security** — semi-honest garbling + OT only.
- **Private notary** — trusted notary learns full IKM (OT path) and public IVs.
- **Host transcript oracle** — mode 2 host still uses `reference_ikm` locally to
  parse handshake hashes (not yet 2PC).
- **Full OT-MtA X25519** — blinded point-add is a demo stepping stone (`ECDH.md`).
- **Selective disclosure** — verifier with keys sees full plaintext.
- **Rekey / session tickets** — single traffic secret epoch only.
- **HTTP conveniences** — raw HTTP printed; no gzip/chunked/redirect handling.

Implemented and worth noting:

- **Signed attestation** — `OP_FINISH` + Ed25519 `NotaryBundle` with per-record
  commit hashes (`run_notary_worker_attested` / `_2pc`).
- **Mode 2 key schedule** — 2PC HKDF for AES-128-GCM traffic keys without
  host-side extract for the record layer.

See `TODO.md` for the full gap list and priority ordering.
