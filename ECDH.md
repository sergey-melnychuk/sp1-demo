# ECDH.md — 2PC X25519 (ECDH) only

**Scope:** Design and implement **secure two-party computation of the TLS 1.3 X25519 shared secret** (the 32-byte output that becomes **IKM** for HKDF in RFC 8446). This file does **not** roadmap HKDF, rustls, `notary_demo`, SP1, or attestation — only what must be true **after** this step for a host+notary split.

**Background in this repo:** [`TODO.md`](TODO.md) item **#1**. Current code in [`notary/src/ecdh.rs`](notary/src/ecdh.rs) builds additive shares of the client scalar but **exchanges partial curve points in the clear**; both parties can compute the full shared secret (`combine_partial_points`). That module is **math reference / tests**, not a private 2PC.

**Normative crypto:** RFC 7748 (X25519), RFC 8446 §7.1 (where the 32-byte output is consumed — read for alignment only; **do not** implement HKDF in this track unless you intentionally expand scope).

## Status (2026-05-26)

| Phase | State |
|-------|--------|
| A — curve math + tests | ✅ `ecdh.rs`: additive shares, XOR split, 3 unit tests |
| B — protocol note | ✅ [`notary/doc/PROTOCOL_ECDH.md`](notary/doc/PROTOCOL_ECDH.md) |
| C — wire + sanity binary | ✅ `host_run_leaky_additive` / `notary_run_leaky_additive`, `ecdh_2pc_sanity --self-test` |
| C+ — ServerHello parser | ✅ `parse_server_hello_key_share` (for TLS wiring) |
| D — TLS / `notary_demo` integration | ⬜ not wired yet |
| Real OT 2PC (`OtX25519Placeholder`) | ⬜ `TODO.md` #1 |

---

## 1. Target object (what “done” means here)

**Inputs (protocol view):**

- **Host** holds share `a₀` of client ephemeral scalar; **notary** holds `a₁` with `a = a₀ + a₁ (mod L)` (or your chosen sharing; document it).
- **Both** know server’s X25519 public key `B` from `ServerHello` / `key_share` (32 bytes, TLS encoding per RFC 8446 §4.2.8).

**Output:**

- Each party holds a share of the **32-byte X25519 shared secret** `S = X25519(a, B)` (same byte string a single-party client would feed to HKDF‑Extract in the handshake path you use later).

**Security (demo / semi-honest baseline):**

- After the protocol, **neither** party should be able to compute `S` alone from their view + messages (define precisely: semi-honest vs malicious in `notary/doc/PROTOCOL_ECDH.md` when you add the protocol).

**Out of scope for this document**

- Proving anything in zkVM, Ed25519 bundles, split AES-GCM (already in [`notary/src/aes.rs`](notary/src/aes.rs)), or wiring into [`notary/src/bin/notary_demo.rs`](notary/src/bin/notary_demo.rs). Those consume **your** ECDH output later.

---

## 2. Repo anchors (minimal)

| File | Relevance to ECDH |
|------|-------------------|
| [`notary/src/ecdh.rs`](notary/src/ecdh.rs) | **Single ECDH module:** additive-share curve math (**leaky** cleartext partials), XOR IKM helpers, [`OtX25519Placeholder`] (`EcdhIkmDriver`); tests |
| [`notary/Cargo.toml`](notary/Cargo.toml) | `curve25519-dalek`, `x25519-dalek`, `swanky-channel`, `swanky-ot-chou-orlandi` — likely building blocks for OT-based ECDH |

---

## 3. Why naive sharing fails (agent must internalize)

- **Do not** send `a₀·B` and `a₁·B` to each other and add points in the clear: that reveals `S` to both (current teaching path in `ecdh.rs`).
- **Goal** is a protocol where **scalar multiplication** with the **combined** secret happens under MPC (OT / garbling / field protocol per your reference), then **only shares** of the Montgomery-u / agreed encoding leave the protocol.

---

## 4. Implementation phases (ECDH only)

### Phase A — Vectors and leakage marking

- Add **RFC 7748** X25519 test vectors; assert single-party `x25519-dalek` (or equivalent) matches.
- Mark any API that leaks partial points or full `S` as **`SECURITY:`** in doc comments; consider `#[deprecated]` on demo-only entry points.

**Check:** `cargo test --manifest-path notary/Cargo.toml -- ecdh`

### Phase B — Protocol note (short, required before coding OT-heavy core)

- Add **`notary/doc/PROTOCOL_ECDH.md`**: message sequence, rounds, OT count order-of-magnitude, semi-honest assumption, reference to external paper or TLSNotary-style note.

### Phase C — Extend [`notary/src/ecdh.rs`](notary/src/ecdh.rs) (or add `ecdh_ot.rs` only if file size explodes)

- **No TLS parsing inside** — API like: `server_epk: [u8;32]`, channel to peer, state machine.
- Use existing [`swanky_channel::Channel`](notary/src/tls.rs) pattern for symmetry with AES 2PC.
- **Dev binary** e.g. `notary/src/bin/ecdh_2pc_sanity.rs`: two roles over TCP localhost; **reconstruct** `S` from shares **only inside test harness** to compare to golden `x25519(a, B)` where `a` is known to the test oracle (not to either party in the real protocol).

**Acceptance:** property test / fuzz: for random split `a`, output shares xor-combine (or per spec) to exact `S`.

### Phase D — Handoff hook (documentation only, not full integration)

- One paragraph in `PROTOCOL_ECDH.md` or this file: **bytes out of Phase C** are the IKM input to whatever later implements TLS key schedule (that work touches [`notary/src/hkdf.rs`](notary/src/hkdf.rs) and today assumes public IKM — **explicitly a separate task**).

---

## 5. Complexity (why this isn’t “2k LOC and done”)

| Pitfall | Note |
|--------|------|
| Curve MPC cost | Full garbled ladder is huge; prefer established OT-based scalar-mult protocols or a vetted library. |
| Clamping / encoding | TLS `KeyShare` bytes must match X25519 rules you test against vectors. |
| Semi-honest vs malicious | Malicious security changes message counts and consistency checks — **out of this doc** unless you extend `PROTOCOL_ECDH.md`. |

---

## 6. Single cross-link

- [`TODO.md`](TODO.md) **#1** — parent issue; **this file** is only the ECDH slice.

---

*Agents: do not expand this file into full zkTLS; add separate `HKDF.md` or integration doc if needed.*
