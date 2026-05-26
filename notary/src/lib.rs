//! notary — 2PC notary primitives for ZK-TLS.
//!
//! Clean module structure:
//! - `aes`   : split-key AES-GCM 2PC
//! - `ecdh`  : X25519 additives / OT-blinded + leaky wire helpers (`OtX25519Blinded`)
//! - `hkdf`  : 2PC HKDF-SHA256
//! - `tls`   : high-level notary TLS session tooling (usable from host)

pub mod aes;
pub mod ecdh;
pub mod hkdf;
pub mod tls;
pub mod transcript;

// Re-export the public surface so existing code continues to work
pub use aes::*;
pub use ecdh::*;
pub use hkdf::*;
pub use tls::*;
pub use transcript::*;
