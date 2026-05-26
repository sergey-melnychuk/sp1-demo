# Split-key 2PC AES-GCM TLS notary — end-to-end demo

A working zkTLS-style flow: a host fetches an HTTPS resource from a real
third-party server while coordinating with a `notary_proxy` daemon so that
**neither party holds the full TLS session key during the data phase**.

After the TLS handshake, the session keys are split additively between the
host and the notary, and every application record is encrypted/decrypted via
split-key 2PC AES-GCM (garbled circuits over swanky). The ciphertext that
hits the wire is byte-identical to what a normal TLS client would produce —
the server has no idea anything unusual happened.

> **Caveat:** the handshake still runs through stock rustls + ring AEAD, so the host
> _briefly_ holds the full AES traffic keys between `dangerous_extract_secrets()`
> and `zeroize()`. Closing that gap needs **real 2PC X25519 / key schedule**
> (`TODO.md` #1, `OtX25519Placeholder` in [`notary/src/ecdh.rs`](notary/src/ecdh.rs)).
>
> **Notary vs host XOR-mask role (default demo):** `notary_proxy` reads a **mode byte**.
> Mode **`1`** (default for `notary_demo`): notary sends random `K_N_tx||K_N_rx` **before**
> the HTTPS TLS handshake finishes; host XOR-splits after extract and uploads IVs, then runs a
> **leaky additive ECDH** round (both sides log matching `IKM=` — plumbing only, see
> [`notary/doc/PROTOCOL_ECDH.md`](notary/doc/PROTOCOL_ECDH.md)). Mode **`0`**:
> `--legacy-host-xor-masks` — original single 56-byte host→notary setup (masks + IVs after handshake).

## Quick start

From `notary/`:

```bash
# 1. Build release binaries (debug mode is too slow for the 2PC workload)
cargo build --release --bin notary_proxy --bin notary_demo

# 2. Start the notary daemon (terminal A)
./target/release/notary_proxy --listen 127.0.0.1:9001

# 3. Run the demo (terminal B)
./target/release/notary_demo \
    --url https://jsonplaceholder.typicode.com/posts/1 \
    --notary 127.0.0.1:9001
```

Expected wall-clock for a ~1.4 KB response: ~10–30 seconds (most of it is the
2PC circuit work — release mode is mandatory). See `TODO.md` items #9–#10 for
performance work that would bring this down to seconds.

## Sample output

```
phase 0a: connect notary for notary-chosen XOR masks ...
phase 0a: XOR mask halves received ...
phase 1: TCP+TLS handshake to jsonplaceholder.typicode.com:443
phase 2: traffic secrets extracted (tx_seq=0, rx_seq=0)
phase 3: finalizing setup with notary at 127.0.0.1:9001
phase 3b: leaky additive ECDH (server epk from ServerHello)
phase 3b: host-side IKM=... (both parties learn full IKM — demo only)
phase 4: encrypting 93 bytes of HTTP request via 2PC AES-GCM
phase 4: request record sent
phase 5: reading response records
--- response (1429 bytes) ---
HTTP/1.1 200 OK
...
{
  "userId": 1,
  "id": 1,
  "title": "sunt aut facere repellat provident occaecati excepturi optio reprehenderit",
  "body": "..."
}
```

## Architecture

```
                  HTTPS server (e.g. jsonplaceholder.typicode.com)
                                ▲   │
                       TLS 1.3  │   │  TLS 1.3
                  application   │   │  application
                      records   │   │  records
                                │   ▼
   ┌──────────────────────────────────────────────────┐
   │ notary_demo (host)                               │
   │  ──────────────────────                          │
   │  0a. (default) TCP to notary: recv K_N_tx||K_N_rx│
   │  1. rustls handshake (ring AEAD)                 │
   │  2. dangerous_extract_secrets() → K_tx, K_rx     │
   │  3. K_C_* = K_* XOR K_N_* ; zeroize(K_*)         │
   │  4. send IV_tx||IV_rx to notary (mode 1)         │
   │  4b. leaky ECDH partial exchange (mode 1)        │
   │     or `--skip-ecdh-wire` / legacy skips this    │
   │     or legacy: mode 0 — one 56 B frame ──────────┤
   │     for each request record:                     │
   │       2PC-encrypt (host: K_C_tx) ─────────────────────────┐
   │       send TLS record to server                  |     │  │
   │     for each response record:                    |     │  │
   │       2PC-decrypt (host: K_C_rx) ─────────────────────────┤
   │       strip inner-type, append plaintext         |     │  │
   └──────────────────────────────────────────────────┘     │  │
                                                            │  │
                                                            ▼  ▼
                                  ┌──────────────────────────────────┐
                                  │ notary_proxy (daemon)            │
                                  │  ───────────────                 │
                                  │  - reads mode byte + setup frames│
                                  │  - run_notary_worker:            │
                                  │    loop on (op, seq, aad, len):  │
                                  │      OP_ENCRYPT  → notary_       │
                                  │                    encrypt_gcm   │
                                  │                    (K_N_tx,IV_tx)│
                                  │      OP_DECRYPT  → notary_       │
                                  │                    decrypt_gcm   │
                                  │                    (K_N_rx,IV_rx)│
                                  └──────────────────────────────────┘
```

## What happens, phase by phase

### Phase 1 — TLS 1.3 handshake (no 2PC yet)

The host runs a normal rustls TLS 1.3 handshake using the ring AEAD provider
and the `TLS_AES_128_GCM_SHA256` cipher suite. After the server's Finished
arrives, the host flushes its own Finished, then drains any post-handshake
records (e.g. `NewSessionTicket`).

This is the gap. The host's `ClientConfig` has `enable_secret_extraction = true`,
which means rustls is willing to hand over the derived keys later. At this
moment the host has the full AES key in memory.

### Phase 2 — secret extraction

`tls.dangerous_extract_secrets()` returns an `ExtractedSecrets` struct with
`tx: (seq, ConnectionTrafficSecrets)` and `rx: (seq, ConnectionTrafficSecrets)`.
For our cipher suite these unpack to `Aes128Gcm { key: [u8; 16], iv: [u8; 12] }`.

After this the `ClientConnection` is consumed; we won't talk to rustls again.
The TCP socket to the server is still alive — we just take it over manually.

### Phase 3 — key split with the notary

```rust
let mut k_n_tx = [0u8; 16]; rand::thread_rng().fill_bytes(&mut k_n_tx);
let mut k_n_rx = [0u8; 16]; rand::thread_rng().fill_bytes(&mut k_n_rx);
let k_c_tx = xor_key(&tx_key, &k_n_tx);
let k_c_rx = xor_key(&rx_key, &k_n_rx);
tx_key.zeroize();
rx_key.zeroize();
```

Host opens a TCP connection to the notary daemon and writes a 56-byte setup
frame: `K_N_tx ‖ IV_tx ‖ K_N_rx ‖ IV_rx`. From this point:

- **Host has:** `K_C_tx`, `K_C_rx`, `IV_tx`, `IV_rx`, `tx_seq`, `rx_seq`.
- **Notary has:** `K_N_tx`, `K_N_rx`, `IV_tx`, `IV_rx`.
- **Neither party has the full TLS write keys.**

### Phase 4 — encrypt outbound request via 2PC

The HTTP request is built as a plain string and converted to the TLS 1.3 inner
plaintext form: `request_bytes || 0x17` (the inner content-type byte for
application_data). The AAD is the 5-byte TLS 1.3 record header per RFC 8446 §5.2.

Inside one `Channel::with(&mut notary_tcp, |ch| { … })` block (kept open for
the whole session — multiple opens lose buffered bytes), the host calls
`client_encrypt_record(ch, k_c_tx, iv_tx, &inner, &aad, tx_seq)`. That
function:

1. Writes a small bridge header to the channel — `op=OP_ENCRYPT, seq, aad,
payload_len` — so the notary side knows what's coming.
2. Runs `client_encrypt_gcm` (evaluator role), which performs the split-key
   2PC AES-GCM in lockstep with `notary_encrypt_gcm` on the other side.
3. Returns `(ciphertext, tag)` — byte-identical to what
   `aes_gcm::Aes128Gcm::encrypt` would produce with the full `K = K_N XOR K_C`.

The host writes a TLS 1.3 record (`0x17 ‖ 0x0303 ‖ length ‖ ciphertext ‖ tag`)
to the server's TCP socket. The server decrypts with its `client_write_key`
(which is the real `K`) and processes the GET as if nothing unusual happened.

### Phase 5 — read and decrypt response records

The host reads TLS records off the server socket one at a time. For each
record with content-type `0x17` (application_data):

1. Split the payload into `ciphertext ‖ tag`.
2. Build the AAD from the record header.
3. Call `client_decrypt_record(ch, k_c_rx, iv_rx, &ct, tag, &aad, rx_seq)` on
   the same notary channel. That writes an `OP_DECRYPT` bridge header and
   runs `client_decrypt_gcm_2pc` (which does the 2PC keystream, the GHASH
   tag verification, and returns the plaintext on tag match).
4. TLS 1.3 strips the trailing inner content-type byte (and any padding
   zeros). For inner type `0x17` we append to the plaintext buffer.

The loop ends when the server sends close-notify (alert `0x15`) or closes
the TCP socket. The host prints the assembled plaintext (HTTP response).

## Wire protocol on the swanky channel

One frame per TLS record (per direction). All multi-byte integers are
big-endian.

```
op           1 byte    0x01 = encrypt, 0x02 = decrypt
seq          8 bytes   TLS record sequence number
aad_len      2 bytes   length of AAD (typically 5 for TLS 1.3)
aad          aad_len   bytes
payload_len  4 bytes   plaintext-or-ciphertext length
<2PC encrypt or decrypt then runs in lockstep on the same channel>
```

The setup frame sent once at connection start is just `K_N_tx ‖ IV_tx ‖
K_N_rx ‖ IV_rx` (56 bytes). The notary reads it via the same swanky channel
before entering the worker loop.

## What's _not_ in this demo

- **ECDH 2PC** (handshake key derivation under MPC) — host still briefly has `K`.
- **Signed attestation** — the notary doesn't yet emit an Ed25519-signed bundle.
- **Selective disclosure** — verifier with the keys sees the _whole_ plaintext.
- **Authenticated garbling** — semi-honest 2PC only.
- **Session tickets / key updates** — rustls' `dangerous_extract_secrets` is
  one-shot and doesn't track rekeying.
- **HTTP layer** — host prints raw HTTP; no chunked decoding, no gzip, no
  redirect following.

See `TODO.md` for the full gap list and priority ordering.
