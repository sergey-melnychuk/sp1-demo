//! 2PC HKDF-SHA256 for TLS 1.3 key schedule.
//!
//! Built on the generated [`sha-256-compress.txt`] Bristol circuit
//! (256-bit IV + 512-bit message → 256-bit chaining value). HMAC is two pairs of
//! `compress` calls; HKDF-Extract is one HMAC; HKDF-Expand-Label (≤32 bytes of
//! output) is one HMAC.
//!
//! Sharing invariant: the HMAC key is split byte-wise between the two parties
//! (`K = K_N XOR K_C`). The output is masked with a fresh random value chosen
//! by the garbler before being revealed to the evaluator, so the result is
//! also split byte-wise. No party ever holds the full secret in the clear.
//!
//! ### Scope (current iteration)
//!
//! - HMAC messages must fit in **one** 512-bit block after SHA-256 padding —
//!   i.e. `msg.len() ≤ 55` bytes. That covers every label HKDF uses in TLS 1.3
//!   (the largest is `"c hs traffic"` / `"s hs traffic"` with a 32-byte
//!   transcript-hash context: 54 bytes including the trailing `0x01`).
//! - The HMAC *message* is assumed PUBLIC (encoded by the notary; client passes
//!   matching bytes for assertion). This matches HKDF use in TLS 1.3 where the
//!   `info` is a public label + context hash. HKDF-Extract's `IKM` is also
//!   public in our current ecdh.rs (both parties learn the X25519 IKM).
//! - The HMAC *key* is split between parties — this is what HKDF-Expand-Label
//!   needs (the secret PRK is split).
//!
//! Out of scope here: secret-message HMAC (would require both parties to
//! provide byte shares of `M`), HMAC for `msg.len() > 55` (would need a
//! multi-block inner SHA chain).

use fancy_garbling::{
    Fancy, FancyBinary, WireMod2,
    circuit::{BinaryCircuit, CircuitExecutor},
};
use rand::Rng;
use swanky_channel::Channel;
use swanky_error::Result as SwankyResult;
use swanky_ot_chou_orlandi::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

use super::bytes_to_bits;

// ── Constants ─────────────────────────────────────────────────────────────────

/// FIPS 180-4 SHA-256 initial chaining value.
const SHA256_INITIAL_IV_BYTES: [u8; 32] = [
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19,
];

const IPAD: u8 = 0x36;
const OPAD: u8 = 0x5c;

// ── Circuit ───────────────────────────────────────────────────────────────────

fn sha256_compress_circuit() -> BinaryCircuit {
    BinaryCircuit::parse(std::io::Cursor::new(include_bytes!(
        "../circuits/sha-256-compress.txt"
    )))
    .expect("bundled SHA-256 compression Bristol circuit is valid")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn bits_to_bytes_32(bits: &[u16]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, chunk) in bits.chunks(8).enumerate().take(32) {
        for (j, &bit) in chunk.iter().enumerate() {
            out[i] |= (bit as u8) << (7 - j);
        }
    }
    out
}

fn xor_wires<F: FancyBinary>(f: &mut F, a: &[F::Item], b: &[F::Item]) -> Vec<F::Item> {
    debug_assert_eq!(a.len(), b.len());
    let mut out = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        out.push(f.xor(&a[i], &b[i]));
    }
    out
}

/// Produce wires representing the value `byte_share_n XOR byte_share_c` where
/// the notary contributes `notary_share` and the client contributes `client_share`.
/// Both parties call this in lockstep.
fn gb_split_bytes(
    gb: &mut Garbler<SwankyRng, OtSender, WireMod2>,
    channel: &mut Channel,
    notary_share: &[u8],
) -> SwankyResult<Vec<WireMod2>> {
    let bits = bytes_to_bits(notary_share);
    let n = bits.len();
    let mod2 = vec![2u16; n];
    let notary_wires = gb.encode_many(&bits, &mod2, channel)?;
    let client_wires = gb.receive_many(&mod2, channel)?;
    Ok(xor_wires(gb, &notary_wires, &client_wires))
}

fn ev_split_bytes(
    ev: &mut Evaluator<SwankyRng, OtReceiver, WireMod2>,
    channel: &mut Channel,
    client_share: &[u8],
) -> SwankyResult<Vec<WireMod2>> {
    let bits = bytes_to_bits(client_share);
    let n = bits.len();
    let mod2 = vec![2u16; n];
    let notary_wires = ev.receive_many(&mod2, channel)?;
    let client_wires = ev.encode_many(&bits, &mod2, channel)?;
    Ok(xor_wires(ev, &notary_wires, &client_wires))
}

/// Asymmetric encoding of the single-block HMAC inner-message: the message
/// `m` is preceded by 64 bytes of `(K' XOR ipad)`, so the SHA-256 padded
/// "block 2" is `m || 0x80 || zeros || length_bits`. Total `(64 + m.len()) * 8`
/// bits.
///
/// Returns the **notary's** contribution: zeros where the client's message
/// bytes go, and the deterministic SHA padding suffix (`0x80 || zeros ||
/// length`) where the client puts zeros. The XOR of the two contributions
/// inside the circuit reconstructs the full padded block. With this split:
///   - The notary's input genuinely depends only on `msg_len` (it never sees
///     the message bytes).
///   - The client's input genuinely contains the message bytes.
fn notary_inner_padding(msg_len: usize) -> [u8; 64] {
    assert!(msg_len <= 55, "single-block HMAC requires msg ≤ 55 bytes");
    let mut block = [0u8; 64];
    block[msg_len] = 0x80;
    let total_bits = ((64 + msg_len) as u64) * 8;
    block[56..64].copy_from_slice(&total_bits.to_be_bytes());
    block
}

/// The client's contribution to the inner block-2 message: its bytes go in
/// positions `0..msg.len()`, everything else is zero.
fn client_inner_msg(msg: &[u8]) -> [u8; 64] {
    assert!(msg.len() <= 55, "single-block HMAC requires msg ≤ 55 bytes");
    let mut block = [0u8; 64];
    block[..msg.len()].copy_from_slice(msg);
    block
}

/// Build the suffix of the outer-block message: `0x80 || zeros || length`.
/// Combined with a wire-supplied 32-byte `h_inner` prefix this forms the
/// 64-byte block that goes through `compress(h_outer_1, ·)`.
fn outer_suffix_padding() -> [u8; 32] {
    let mut s = [0u8; 32];
    s[0] = 0x80;
    let total_bits: u64 = (64 + 32) * 8; // K_opad (64) + h_inner (32)
    s[24..32].copy_from_slice(&total_bits.to_be_bytes());
    s
}

// ── Public API: HMAC-SHA256 under 2PC ─────────────────────────────────────────

/// Notary side of 2PC HMAC-SHA256.
///
/// Inputs:
/// - `key_n`: notary's share of the 32-byte HMAC key. The real key is
///   `K = key_n XOR key_c`.
/// - `msg_len`: byte-length of the message the client will provide
///   (≤ 55 bytes). The notary needs the length to construct the
///   SHA-256 padding suffix; it never sees the message bytes themselves.
///
/// Returns the notary's byte share of the HMAC output.
pub fn notary_hmac_sha256(
    channel: &mut Channel,
    key_n: [u8; 32],
    msg_len: usize,
) -> SwankyResult<[u8; 32]> {
    let rng = SwankyRng::new();
    let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(channel, rng)?;
    let circ = sha256_compress_circuit();

    // K' XOR ipad / opad on the notary side (K_C contribution comes via OT later)
    let mut k_ipad_n = [0u8; 64];
    let mut k_opad_n = [0u8; 64];
    for i in 0..32 {
        k_ipad_n[i] = key_n[i] ^ IPAD;
        k_opad_n[i] = key_n[i] ^ OPAD;
    }
    for i in 32..64 {
        k_ipad_n[i] = IPAD;
        k_opad_n[i] = OPAD;
    }

    // ── Inner block 1: compress(std_IV, K' XOR ipad) ──────────────────────
    // IV is the standard SHA-256 IV (public). Both sides contribute: notary
    // provides std_IV, client provides zeros. XOR gives std_IV.
    let iv_wires = gb_split_bytes(&mut gb, channel, &SHA256_INITIAL_IV_BYTES)?;
    let msg_wires = gb_split_bytes(&mut gb, channel, &k_ipad_n)?;
    let mut inputs = iv_wires;
    inputs.extend(msg_wires);
    let h_inner_1 = circ.execute(&mut gb, &inputs, channel)?;

    // ── Inner block 2: compress(h_inner_1, msg_padded) ────────────────────
    // Notary contributes the deterministic SHA-padding suffix
    // (knows msg_len, not msg content). Client contributes the msg bytes.
    // XOR inside the circuit reconstructs the full padded block.
    let notary_pad = notary_inner_padding(msg_len);
    let msg_wires = gb_split_bytes(&mut gb, channel, &notary_pad)?;
    let mut inputs = h_inner_1.clone();
    inputs.extend(msg_wires);
    let h_inner_final = circ.execute(&mut gb, &inputs, channel)?;

    // ── Outer block 1: compress(std_IV, K' XOR opad) ──────────────────────
    let iv_wires = gb_split_bytes(&mut gb, channel, &SHA256_INITIAL_IV_BYTES)?;
    let msg_wires = gb_split_bytes(&mut gb, channel, &k_opad_n)?;
    let mut inputs = iv_wires;
    inputs.extend(msg_wires);
    let h_outer_1 = circ.execute(&mut gb, &inputs, channel)?;

    // ── Outer block 2: compress(h_outer_1, h_inner_final || padding) ──────
    let outer_suffix = outer_suffix_padding();
    let suffix_wires = gb_split_bytes(&mut gb, channel, &outer_suffix)?;
    let mut inputs = h_outer_1;
    inputs.extend(h_inner_final);
    inputs.extend(suffix_wires);
    let hmac_wires = circ.execute(&mut gb, &inputs, channel)?;

    // ── Share the output: garbler picks a random mask, XORs into output,
    //    reveals the masked value to the evaluator. Notary's share = mask.
    let mut m_n_bytes = [0u8; 32];
    rand::thread_rng().fill(&mut m_n_bytes);
    let mask_wires = gb.encode_many(
        &bytes_to_bits(&m_n_bytes),
        &vec![2u16; 256],
        channel,
    )?;
    let masked = xor_wires(&mut gb, &hmac_wires, &mask_wires);
    gb.outputs(&masked, channel)?;

    Ok(m_n_bytes)
}

/// Client side of 2PC HMAC-SHA256.
pub fn client_hmac_sha256(
    channel: &mut Channel,
    key_c: [u8; 32],
    msg: &[u8],
) -> SwankyResult<[u8; 32]> {
    let rng = SwankyRng::new();
    let mut ev = Evaluator::<SwankyRng, OtReceiver, WireMod2>::new(channel, rng)?;
    let circ = sha256_compress_circuit();

    let mut k_ipad_c = [0u8; 64];
    let mut k_opad_c = [0u8; 64];
    for i in 0..32 {
        k_ipad_c[i] = key_c[i]; // ipad XOR happens on the notary side (XOR with constant)
        k_opad_c[i] = key_c[i];
    }
    // Bytes 32..64 stay zero — only the notary contributes ipad/opad to that region.

    // Inner block 1
    let iv_wires = ev_split_bytes(&mut ev, channel, &[0u8; 32])?;
    let msg_wires = ev_split_bytes(&mut ev, channel, &k_ipad_c)?;
    let mut inputs = iv_wires;
    inputs.extend(msg_wires);
    let h_inner_1 = circ.execute(&mut ev, &inputs, channel)?;

    // Inner block 2 — client encodes the actual message bytes (zero-padded
    // to 64 bytes); notary encodes the SHA-padding suffix. XOR = msg||pad.
    let client_msg_block = client_inner_msg(msg);
    let msg_wires = ev_split_bytes(&mut ev, channel, &client_msg_block)?;
    let mut inputs = h_inner_1.clone();
    inputs.extend(msg_wires);
    let h_inner_final = circ.execute(&mut ev, &inputs, channel)?;

    // Outer block 1
    let iv_wires = ev_split_bytes(&mut ev, channel, &[0u8; 32])?;
    let msg_wires = ev_split_bytes(&mut ev, channel, &k_opad_c)?;
    let mut inputs = iv_wires;
    inputs.extend(msg_wires);
    let h_outer_1 = circ.execute(&mut ev, &inputs, channel)?;

    // Outer block 2
    let suffix_wires = ev_split_bytes(&mut ev, channel, &[0u8; 32])?;
    let mut inputs = h_outer_1;
    inputs.extend(h_inner_final);
    inputs.extend(suffix_wires);
    let hmac_wires = circ.execute(&mut ev, &inputs, channel)?;

    // Receive the mask wires from the notary (they hold the value secret)
    let mask_wires = ev.receive_many(&vec![2u16; 256], channel)?;
    let masked = xor_wires(&mut ev, &hmac_wires, &mask_wires);
    let vals = ev
        .outputs(&masked, channel)?
        .expect("evaluator always receives output");

    Ok(bits_to_bytes_32(&vals))
}

// ── HKDF-Extract ──────────────────────────────────────────────────────────────

/// HKDF-Extract(salt, IKM) = HMAC-SHA256(salt, IKM).
/// `salt` is the HMAC *key*: split between parties.
/// `ikm` is the HMAC *message*: provided by the client; the notary only
/// learns its length.
pub fn notary_hkdf_extract(
    channel: &mut Channel,
    salt_n: [u8; 32],
    ikm_len: usize,
) -> SwankyResult<[u8; 32]> {
    notary_hmac_sha256(channel, salt_n, ikm_len)
}

pub fn client_hkdf_extract(
    channel: &mut Channel,
    salt_c: [u8; 32],
    ikm: &[u8],
) -> SwankyResult<[u8; 32]> {
    client_hmac_sha256(channel, salt_c, ikm)
}

// ── HKDF-Expand-Label (TLS 1.3) ───────────────────────────────────────────────

/// Build the `HkdfLabel || 0x01` byte string used as the HMAC message for
/// the first (and only — we support outputs ≤ 32 bytes) iteration of HKDF-Expand.
///
/// `HkdfLabel = length(2) || "tls13 " + label(1+N) || context(1+M)` per RFC 8446 §7.1.
pub fn hkdf_expand_label_info(label: &str, context: &[u8], length: u16) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&length.to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    info.push(0x01); // T_1 counter
    info
}

/// HKDF-Expand-Label(secret, label, context, len) for `len ≤ 32`.
/// Returns the full 32-byte HMAC output share. Caller truncates after
/// reconstructing.
///
/// The label string is public protocol metadata; both parties pass it so the
/// notary can compute the right msg_len for SHA padding. The notary still
/// does NOT encode the label bytes into the circuit — only the client does.
pub fn notary_hkdf_expand_label(
    channel: &mut Channel,
    secret_n: [u8; 32],
    label: &str,
    context: &[u8],
    len: u16,
) -> SwankyResult<[u8; 32]> {
    let info_len = hkdf_expand_label_info(label, context, len).len();
    notary_hmac_sha256(channel, secret_n, info_len)
}

pub fn client_hkdf_expand_label(
    channel: &mut Channel,
    secret_c: [u8; 32],
    label: &str,
    context: &[u8],
    len: u16,
) -> SwankyResult<[u8; 32]> {
    let info = hkdf_expand_label_info(label, context, len);
    client_hmac_sha256(channel, secret_c, &info)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use swanky_channel::local::local_channel_pair;

    type HmacSha256 = Hmac<Sha256>;

    fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
        std::array::from_fn(|i| a[i] ^ b[i])
    }

    /// 2PC HMAC-SHA256 matches the `hmac` crate's HMAC-SHA256 for short messages
    /// when the parties' key shares are reconstructed as `K = K_N XOR K_C`.
    #[test]
    fn hmac_sha256_2pc_matches_reference() {
        // K = K_N XOR K_C
        let k_n: [u8; 32] = [0x2b; 32];
        let k_c: [u8; 32] = [
            0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
            0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let k = xor32(k_n, k_c);
        let msg = b"hello, hkdf";

        // Reference using the hmac crate
        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(msg);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();

        // 2PC: notary takes only the msg length; client provides the bytes.
        let (notary_share, client_share) = local_channel_pair(
            |ch| notary_hmac_sha256(ch, k_n, msg.len()),
            |ch| client_hmac_sha256(ch, k_c, msg),
        )
        .unwrap();

        let reconstructed = xor32(notary_share, client_share);
        assert_eq!(
            reconstructed, expected,
            "K_N XOR K_C HMAC output must equal reference HMAC(K, msg)"
        );
    }

    /// HKDF-Extract via 2PC matches the reference HKDF-Extract for a short IKM.
    #[test]
    fn hkdf_extract_2pc_matches_reference() {
        let salt_n: [u8; 32] = [0x11; 32];
        let salt_c: [u8; 32] = [0x22; 32];
        let salt = xor32(salt_n, salt_c);
        let ikm = b"shared-secret-from-X25519-ECDH"; // 30 bytes, fits in one block

        let mut mac = HmacSha256::new_from_slice(&salt).unwrap();
        mac.update(ikm);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();

        let (n_share, c_share) = local_channel_pair(
            |ch| notary_hkdf_extract(ch, salt_n, ikm.len()),
            |ch| client_hkdf_extract(ch, salt_c, ikm),
        )
        .unwrap();

        assert_eq!(xor32(n_share, c_share), expected);
    }

    /// HKDF-Expand-Label (RFC 8446 §7.1) for a TLS 1.3 traffic-key derivation
    /// matches the reference when reconstructed.
    #[test]
    fn hkdf_expand_label_matches_reference() {
        let secret_n: [u8; 32] = [0xa1; 32];
        let secret_c: [u8; 32] = [0xb2; 32];
        let secret = xor32(secret_n, secret_c);

        // "key" label, 16-byte output (typical for AES-128 in TLS 1.3)
        let label = "key";
        let context: &[u8] = &[];
        let length: u16 = 16;

        // Reference: HKDF-Expand-Label(secret, "key", "", 16)
        let info = hkdf_expand_label_info(label, context, length);
        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(&info);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();

        let (n_share, c_share) = local_channel_pair(
            |ch| notary_hkdf_expand_label(ch, secret_n, label, context, length),
            |ch| client_hkdf_expand_label(ch, secret_c, label, context, length),
        )
        .unwrap();

        assert_eq!(xor32(n_share, c_share), expected);
    }

    /// Larger context (32-byte transcript hash) for a TLS 1.3 traffic secret
    /// derivation — exercises the longest HKDF info we encounter (54 bytes + 0x01).
    #[test]
    fn hkdf_expand_label_traffic_secret() {
        let secret_n: [u8; 32] = [0x33; 32];
        let secret_c: [u8; 32] = [0x44; 32];
        let secret = xor32(secret_n, secret_c);

        let label = "c hs traffic";
        let context = [0x77u8; 32]; // transcript hash placeholder
        let length: u16 = 32;

        let info = hkdf_expand_label_info(label, &context, length);
        assert!(info.len() <= 55, "TLS 1.3 HKDF info must fit one block: {}", info.len());

        let mut mac = HmacSha256::new_from_slice(&secret).unwrap();
        mac.update(&info);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();

        let (n_share, c_share) = local_channel_pair(
            |ch| notary_hkdf_expand_label(ch, secret_n, label, &context, length),
            |ch| client_hkdf_expand_label(ch, secret_c, label, &context, length),
        )
        .unwrap();

        assert_eq!(xor32(n_share, c_share), expected);
    }
}
