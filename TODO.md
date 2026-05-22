Necessary pieces for complete zkTLS:

- 2PC ECDH (X25519): needs share-conversion (multiplicative-to-additive over Curve25519's field) via OT-based MtA. ~1500–2000 lines of new protocol code. No primitive for it in swanky. mpz has it.
- 2PC HKDF-SHA256: doable on top of swanky's SHA-256 Bristol circuit. Hours of work IF the rest exists.
- 2PC AES-GCM wired into TLS record layer: requires hooking rustls' MessageEncrypter/MessageDecrypter and interleaving 2PC ops with TLS state. Real engineering work, days.
- Commit-before-reveal flow: simple once the above is in place.
- Authenticated garbling instead of semi-honest: backend swap, hours.
