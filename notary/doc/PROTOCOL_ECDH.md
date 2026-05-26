# PROTOCOL_ECDH — leaky additive wire (demo only)

**Status:** implemented in [`../src/ecdh.rs`](../src/ecdh.rs) as `host_run_leaky_additive` / `notary_run_leaky_additive`.

**Security:** **Semi-honest, leaky.** Both parties learn the full 32-byte X25519 IKM. This is **not** the target from `ECDH.md` §1; it validates curve math + framing before OT-based MPC (`OtX25519Placeholder`).

## Messages (over byte stream, host connects to notary)

| Step | Direction | Payload |
|------|-----------|---------|
| 1 | host → notary | `server_epk` (32 B) — simulated ServerHello `key_share` in sanity binary |
| 2 | host → notary | `P_c` compressed Edwards (32 B) |
| 3 | notary → host | `P_n` compressed Edwards (32 B) |
| 4 | notary → host | `ikm_mask` (32 B) random — notary’s XOR share of IKM |

Each party computes `IKM = u(P_c + P_n)` locally. Host holds `IKM ⊕ mask`; notary holds `mask`.

## Sanity binary

```bash
cd notary
cargo run --release --bin ecdh_2pc_sanity -- --listen 127.0.0.1:9010
cargo run --release --bin ecdh_2pc_sanity -- --connect 127.0.0.1:9010
```

Compare printed IKM lines — they must match.

## Next (real 2PC)

Replace steps 2–4 with OT/MtA scalar mult so **neither** party reconstructs `IKM` alone. Output still XOR shares for HKDF input. See workspace `TODO.md` #1.
