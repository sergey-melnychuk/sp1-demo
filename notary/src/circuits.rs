//! Bundled Bristol circuits and SHA-256 identity hashes for attestation.

use sha2::{Digest, Sha256};

pub const GARBLING_SEMIHONEST: u8 = 0;
/// HKDF/HMAC compress uses WRK17; AES-GCM record layer still semi-honest.
pub const GARBLING_HKDF_AUTH: u8 = 1;
pub const GARBLING_AUTHENTICATED: u8 = 1;

const AES_CIRCUIT: &[u8] = include_bytes!("../circuits/AES-non-expanded.txt");
const SHA256_COMPRESS_CIRCUIT: &[u8] = include_bytes!("../circuits/sha-256-compress.txt");

/// SHA-256 of the bundled AES Bristol file (identity commitment).
pub fn circuit_aes_sha256() -> [u8; 32] {
    Sha256::digest(AES_CIRCUIT).into()
}

/// SHA-256 of the bundled SHA-256 compression Bristol file.
pub fn circuit_sha256_compress_sha256() -> [u8; 32] {
    Sha256::digest(SHA256_COMPRESS_CIRCUIT).into()
}
