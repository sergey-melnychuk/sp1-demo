# TODO

## Target Use Case

**"Prove my Binance balance is above $X to a 3rd party."**

The user holds a Binance API key. They run the prover locally, which makes an authenticated request to Binance, captures the full TLS session, and produces a ZK proof. The 3rd party receives only the proof — not the API key, not the full response.

The proof guarantees, unforgeably:

- The TLS session was with `binance.com`, cert chain verified against Mozilla roots
- The request was authenticated (Binance only returns real balances to valid API keys)
- The decrypted, authenticated response body had `balance > X`
- The prover cannot fake any of this — AES-GCM auth, ECDSA/RSA, and the full key schedule are all verified inside the guest against a fixed ELF whose hash the verifier checks

The prover is a courier for the witness, not a trusted party. The verifier trusts the TLS stack and Mozilla root store — the same things they'd trust making the request themselves.

**Remaining limitation:** a user could run the prover multiple times and pick the best session. Bounded by asserting on Binance's `/serverTime` in the same response — replay window collapses to minutes. Acceptable for a 3rd party doing a spot check.

**Note on selective disclosure:** the prover sees the full Binance response (all balances, positions, etc.) but the proof only reveals the single asserted field. The user must trust the prover not to log the full response. For self-proving (user runs prover on their own machine) this is not an issue. For delegated proving it requires MPC-TLS or a TEE — see Future Directions below.

---

## Trust model (current)

The host is a **dumb relay**: it generates `esk_client`, performs the TLS handshake
with the externally-supplied `epk_client`, and captures raw wire bytes. It does not
derive any TLS traffic secret or see any plaintext.

The guest independently:
- Parses `epk_client` from the raw `ClientHello` and asserts `epk_client == esk_client × G`
- Parses `epk_server` from the raw `ServerHello`
- Derives all keys via X25519 + HKDF
- Decrypts and verifies the handshake flight (EncryptedExtensions, Certificate, CertificateVerify, Finished)
- Decrypts application records

The host cannot forge server ciphertext (requires `server_write_key` for AES-GCM auth).

---

## Next: Replay Prevention (blocks shipping the Binance use case)

- [ ] **Add `--freshness-field` and `--freshness-min` CLI args** — assert a second JSON field (the server's timestamp) is within an acceptable window of the current time. The verifier supplies `now` as a public input; the guest commits it alongside the balance claim. Example: `--freshness-field /serverTime --freshness-min 300` asserts `json["/serverTime"] > now - 300s`. Binance includes `/serverTime` (Unix ms) in all API responses. This collapses the cherry-pick window to minutes.

---

## Security / Correctness

- [ ] **HTTP response completeness check** — the guest currently has no way to verify the host didn't withhold the last N application-data records. Middle-record omission is caught by AES-GCM (wrong nonce → wrong tag). Tail omission requires verifying a terminal boundary: `Content-Length` match or `0\r\n\r\n` chunked terminator. Add an explicit assert in the guest after decryption.

- [ ] **Fix `unchunk` empty-response edge case** — if a chunked response starts with `0\r\n\r\n` (valid empty body), `unchunk` returns the raw string unchanged and passes it to `serde_json::from_str`, which panics. Add proper error handling.

## Precision

- [ ] **Replace `f64` with integer or decimal arithmetic** for the JSON field value and threshold. `f64` loses precision beyond ~15 significant digits — wrong for financial values. Use string comparison or scale to integer (e.g. cents / satoshis).

## Cipher suite coverage

- [ ] **ChaCha20-Poly1305 and AES-256-GCM decryption** in the guest. Currently only `TLS_AES_128_GCM_SHA256` is negotiated. Add decryption paths for the other two TLS 1.3 mandatory cipher suites.

## Proving

- [ ] **Succinct prover network integration** — real STARK proof works on 32 GB RAM (verified on NUC). Wire up `SP1_PROVER=network` as an alternative for machines with less RAM, and document the flow in the README.

## Possible extensions

- [ ] On-chain verifier: generate a Solidity verifier with `sp1-sdk`'s `evm` feature and post proofs to a smart contract.
- [ ] Certificate revocation (OCSP) — expensive inside the zkVM; explore caching or off-circuit revocation checks committed as a separate public input.
- [ ] P-384 precompile — no SP1 patch currently exists; upstream or fork one if targeting servers that use P-384 leaf certs.

## Future Directions (stronger trust model)

The current design requires the user to run the prover on their own machine. For delegated proving — where a 3rd party runs the prover on behalf of a user — the selective disclosure and agency problems require one of:

- **MPC-TLS** (e.g. TLSNotary): verifier co-participates in the TLS handshake via 2-of-2 MPC. Neither party alone can forge the session. Strongest guarantees, no hardware trust, but complex and slow.
- **TEE-assisted witness generation**: run the host inside an attested enclave (Intel TDX, AMD SEV). TEE makes the connection, produces the witness, returns only the proof. Verifier checks TEE attestation + proof. Pragmatic, trusts the hardware vendor.

Both are out of scope for a self-proving demo but are the natural next step for a production delegated-proving system.

---

## Done

- ✅ **Full in-guest TLS parsing** — guest independently derives all keys and decrypts handshake records from raw bytes; host is a dumb relay (`GUEST_TLS` design)
- ✅ **Authorship gap closed** — guest asserts `epk_client == esk_client × G`; no pre-parsed key material accepted from host
- ✅ **RSA precompile active** — pinned `rsa = "=0.9.6"` so the SP1 patch applies (was silently falling back to software at `0.9.10`)
- ✅ **`CapturingKxGroup` / `CapturingKeyLog` removed** — replaced by `ExternalKxGroup` (accepts pre-generated key) and raw byte capture only
- ✅ **`witness.rs` / `keylog.rs` deleted** — host-side handshake decryption no longer needed
- ✅ **Transcript integrity** — all transcript hashes computed in-guest from raw parsed messages
- ✅ **Server Finished HMAC** — proves server completed handshake
- ✅ **Cert chain verification** — ECDSA-P256, ECDSA-P384, RSA-PSS, RSA-PKCS1 + webpki-roots
- ✅ **CertificateVerify** — multi-scheme: 0x0403, 0x0503, 0x0804, 0x0805, 0x0401
- ✅ **Hostname check** — leaf cert SAN, wildcard support
- ✅ **ECDH + HKDF + AES-GCM** — full key schedule and app record decryption
- ✅ **Chunked HTTP decoder** — handles `Transfer-Encoding: chunked`
- ✅ **Session ticket filter** — skips `NewSessionTicket` records (inner_ct=22)
- ✅ **Middle-record omission detection** — AES-GCM nonce (iv XOR seq) fails auth on any gap
- ✅ **Replace `Box::leak` in `make_capturing_provider`** — `ExternalKxGroup` uses a plain `&'static` reference, same pattern, no semantic change needed since there is one connection per process
