# ECDH.md — 2PC X25519 (ECDH) only

**Scope:** Design and implement **secure two-party computation of the TLS 1.3 X25519 shared secret** (the 32-byte output that becomes **IKM** for HKDF in RFC 8446). This file does **not** roadmap HKDF, rustls, `notary_demo`, SP1, or attestation — only what must be true **after** this step for a host+notary split.

**Background in this repo:** [`TODO.md`](TODO.md) item **#1**. Implementation lives in [`notary/src/ecdh.rs`](notary/src/ecdh.rs): additive scalar shares, **leaky** cleartext partial exchange (debug), and **OT-blinded** point addition (default wire path).

**Normative crypto:** RFC 7748 (X25519), RFC 8446 §7.1 (where the 32-byte output is consumed — read for alignment only; **do not** implement HKDF in this track unless you intentionally expand scope).

## Status (2026-05-26)

| Phase | State |
|-------|--------|
| A — curve math + tests | ✅ `ecdh.rs`: additive shares, XOR split, 4 unit tests |
| B — protocol note | ✅ **§ Protocol** below |
| C — wire + sanity binary | ✅ leaky + OT-blinded, `ecdh_2pc_sanity --self-test [--ot]` |
| C+ — ServerHello parser | ✅ `parse_server_hello_key_share` |
| D — TLS / `notary_demo` integration | ✅ mode 1: pre-TLS scalar share + post-IV ECDH on notary TCP |
| Real OT 2PC (`OtX25519Blinded`) | ✅ blinded point-add wire (host XOR IKM share); MtA scalar mult ⬜ |

---

## Protocol

Wire formats for `notary_demo` ↔ `notary_proxy` (mode **1**). Code: [`notary/src/ecdh.rs`](notary/src/ecdh.rs).

**Security:** Semi-honest demo. **OT-blinded** (default) does not send cleartext partial points; the host receives only an XOR share of IKM. The notary (trusted) reconstructs full IKM locally. **Leaky** mode still sends `P_c`/`P_n` in the clear. Full OT-MtA scalar mult ([`TODO.md`](TODO.md) #1) is not implemented.

### Mode 1 pre-TLS (notary → host)

After setup mode byte `1`:

| Payload | Size |
|---------|------|
| `K_N_tx \|\| K_N_rx` | 32 B |
| notary scalar share (clamped) | 32 B |

Host samples its own scalar share, forms `esk = clamp(s_host + s_notary)` for ClientHello (`ExternalKxGroup` in `notary_demo`).

### Post-IV ECDH flag

After `IV_tx (12) || IV_rx (12)`:

| Flag | Value | Meaning |
|------|-------|---------|
| `SETUP_ECDH_SKIP` | `0` | Skip ECDH |
| `SETUP_ECDH_LEAKY` | `1` | Cleartext partial points (`--leaky-ecdh-wire`) |
| `SETUP_ECDH_OT` | `2` | OT-blinded point add (default) |

Then `server_epk` (32 B) when not skipping.

### OT-blinded round (`SETUP_ECDH_OT`)

| Step | Direction | Payload |
|------|-----------|---------|
| 0 | host → notary | `server_epk` (32 B) |
| 1 | notary → host | `R` compressed Edwards (32 B), random mask point |
| 2 | host → notary | `Q = P_host + R` compressed (32 B) |
| 3 | notary → host | `host_ikm_share` (32 B) = `u(P_host+P_notary) ⊕ notary_mask` |

Partial points never traverse the wire. Notary holds `notary_ikm_share` and full IKM locally.

### Leaky round (`SETUP_ECDH_LEAKY`)

| Step | Direction | Payload |
|------|-----------|---------|
| 0 | host → notary | `server_epk` (32 B) |
| 1 | host → notary | `P_c` compressed Edwards (32 B) |
| 2 | notary → host | `P_n` compressed Edwards (32 B) |
| 3 | notary → host | `ikm_mask` (32 B) random |

Both parties compute full IKM locally. Debug / plumbing only.

### Verify

```bash
cd notary
cargo test --lib ecdh
cargo run --release --bin ecdh_2pc_sanity -- --self-test
cargo run --release --bin ecdh_2pc_sanity -- --self-test --ot
```

Full demo (OT default): see [`DEMO.md`](DEMO.md).

### Next (real 2PC)

OT/MtA scalar multiplication so neither party reconstructs IKM; feed XOR shares into 2PC HKDF with secret IKM. See [`TODO.md`](TODO.md) #1.

---

## 1. Target object (what “done” means here)

**Inputs (protocol view):**

- **Host** holds share `a₀` of client ephemeral scalar; **notary** holds `a₁` with `a = a₀ + a₁ (mod L)` (or your chosen sharing; document it).
- **Both** know server’s X25519 public key `B` from `ServerHello` / `key_share` (32 bytes, TLS encoding per RFC 8446 §4.2.8).

**Output:**

- Each party holds a share of the **32-byte X25519 shared secret** `S = X25519(a, B)` (same byte string a single-party client would feed to HKDF‑Extract in the handshake path you use later).

**Security (demo / semi-honest baseline):**

- After the protocol, **neither** party should be able to compute `S` alone from their view + messages. Today’s OT-blinded path is **not** there yet (notary learns full `S`); leaky mode lets both learn `S`. Malicious security is out of scope unless this section is extended.

**Out of scope for this document**

- Proving anything in zkVM, Ed25519 bundles, split AES-GCM (already in [`notary/src/aes.rs`](notary/src/aes.rs)), or wiring into [`notary/src/bin/notary_demo.rs`](notary/src/bin/notary_demo.rs). Those consume **your** ECDH output later.

---

## 2. Repo anchors (minimal)

| File | Relevance to ECDH |
|------|-------------------|
| [`notary/src/ecdh.rs`](notary/src/ecdh.rs) | **Single ECDH module:** curve math, leaky + OT-blinded wire, [`OtX25519Blinded`] |
| [`notary/Cargo.toml`](notary/Cargo.toml) | `curve25519-dalek`, `x25519-dalek`, `swanky-channel`, `swanky-ot-chou-orlandi` |

---

## 3. Why naive sharing fails (agent must internalize)

- **Do not** send `a₀·B` and `a₁·B` to each other and add points in the clear: that reveals `S` to both (leaky mode in `ecdh.rs`).
- **Goal** is a protocol where **scalar multiplication** with the **combined** secret happens under MPC (OT / garbling / field protocol per your reference), then **only shares** of the Montgomery-u / agreed encoding leave the protocol.

---

## 4. Implementation phases (ECDH only)

### Phase A — Vectors and leakage marking

- Add **RFC 7748** X25519 test vectors; assert single-party `x25519-dalek` (or equivalent) matches.
- Mark any API that leaks partial points or full `S` as **`SECURITY:`** in doc comments; consider `#[deprecated]` on demo-only entry points.

**Check:** `cargo test --manifest-path notary/Cargo.toml -- ecdh`

### Phase B — Protocol note

- **§ Protocol** above — message sequence, semi-honest assumption.

### Phase C — Extend [`notary/src/ecdh.rs`](notary/src/ecdh.rs)

- API: `server_epk: [u8;32]`, byte stream or [`swanky_channel::Channel`](notary/src/tls.rs).
- **Dev binary** [`notary/src/bin/ecdh_2pc_sanity.rs`](notary/src/bin/ecdh_2pc_sanity.rs): pipe/TCP roundtrip; test harness compares to `reference_ikm`.

**Acceptance:** for random split `a`, output shares xor-combine to exact `S` (notary side / test oracle only for OT-blinded).

### Phase D — Handoff hook

- **Bytes out of Phase C** are the IKM input to whatever later implements TLS key schedule (that work touches [`notary/src/hkdf.rs`](notary/src/hkdf.rs) and today assumes public IKM — **explicitly a separate task**).

---

## 5. Complexity (why this isn’t “2k LOC and done”)

| Pitfall | Note |
|--------|------|
| Curve MPC cost | Full garbled ladder is huge; prefer established OT-based scalar-mult protocols or a vetted library. |
| Clamping / encoding | TLS `KeyShare` bytes must match X25519 rules you test against vectors. |
| Semi-honest vs malicious | Malicious security changes message counts and consistency checks — **out of this doc** unless **§ Protocol** is extended. |

---

## 6. Single cross-link

- [`TODO.md`](TODO.md) **#1** — parent issue; **this file** is only the ECDH slice.

---

*Agents: do not expand this file into full zkTLS; add separate `HKDF.md` or integration doc if needed.*
