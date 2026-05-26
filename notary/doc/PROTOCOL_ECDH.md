# PROTOCOL_ECDH — leaky additive wire (demo only)

**Status:** implemented in [`../src/ecdh.rs`](../src/ecdh.rs) as `host_run_leaky_additive` / `notary_run_leaky_additive`, wired into **`notary_demo` ↔ `notary_proxy`** (setup mode **1**) after IV exchange.

**Security:** **Semi-honest, leaky.** Both parties learn the full 32-byte X25519 IKM. This is **not** the target from `ECDH.md` §1; it validates curve math + framing before OT-based MPC (`OtX25519Placeholder`).

## Setup mode 1 — post-IV ECDH flag

After `IV_tx (12) || IV_rx (12)` on the notary TCP stream:

| Flag byte | Meaning |
|-----------|---------|
| `SETUP_ECDH_SKIP` (`0`) | No ECDH round; proceed to 2PC AES-GCM |
| `SETUP_ECDH_LEAKY` (`1`) | Leaky additive partial-point exchange below |

Host sends `SETUP_ECDH_SKIP` when `--skip-ecdh-wire` is set or ServerHello `key_share` could not be parsed from the captured handshake.

## Leaky round (when flag = `SETUP_ECDH_LEAKY`)

| Step | Direction | Payload |
|------|-----------|---------|
| 0 | host → notary | `server_epk` (32 B) — parsed from ServerHello in captured TLS bytes |
| 1 | host → notary | `P_c` compressed Edwards (32 B) |
| 2 | notary → host | `P_n` compressed Edwards (32 B) |
| 3 | notary → host | `ikm_mask` (32 B) random — notary’s XOR share of IKM |

Each party computes `IKM = u(P_c + P_n)` locally. Host holds `IKM ⊕ mask`; notary holds `mask`.

**Note:** host’s additive share is **independent** of rustls’s ClientHello ephemeral today — this round does not yet drive HKDF; it proves wire plumbing only.

## Sanity binary (standalone)

```bash
cd notary
cargo run --release --bin ecdh_2pc_sanity -- --listen 127.0.0.1:9010
cargo run --release --bin ecdh_2pc_sanity -- --connect 127.0.0.1:9010
```

Compare printed IKM lines — they must match.

## Full demo

```bash
# terminal A
./target/release/notary_proxy --listen 127.0.0.1:9001

# terminal B
./target/release/notary_demo --url https://jsonplaceholder.typicode.com/posts/1 --notary 127.0.0.1:9001
```

Both sides log matching `IKM=` hex in phase 3b / notary setup.

## Next (real 2PC)

Replace steps 1–3 with OT/MtA scalar mult so **neither** party reconstructs `IKM` alone. Tie host ephemeral to rustls ClientHello; feed XOR shares into 2PC HKDF. See workspace `TODO.md` #1.
