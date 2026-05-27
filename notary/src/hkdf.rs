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
//!   `info` is a public label + context hash. **Exception:** [`notary_hmac_sha256_xor_msg`]
//!   / [`client_hmac_sha256_xor_msg`] for a **32-byte XOR-shared IKM** (TODO.md #1).
//! - The HMAC *key* is split between parties — this is what HKDF-Expand-Label
//!   needs (the secret PRK is split).
//!
//! Out of scope here: HMAC for `msg.len() > 55` (would need a multi-block inner SHA chain).
//! XOR-shared 32-byte messages (IKM) use [`notary_hmac_sha256_xor_msg`].

use fancy_garbling::{
    Fancy, FancyBinary,
    circuit::{BinaryCircuit, CircuitExecutor},
};
use rand::Rng;
use sha2::{Digest, Sha256};
use swanky_channel::Channel;
use swanky_error::Result as SwankyResult;
use swanky_ot_chou_orlandi::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator as SemiEv, Garbler as SemiGb};

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

fn sha256_compress_wrk17_circuit() -> crate::garble::SplitSharedInputMaskCircuit {
    crate::garble::SplitSharedInputMaskCircuit::new(
        sha256_compress_circuit(),
        768,
        crate::garble::OUTPUT_MASK_BITS,
    )
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
fn gb_split_bytes<F: FancyBinary>(
    gb: &mut F,
    channel: &mut Channel,
    notary_share: &[u8],
) -> SwankyResult<Vec<F::Item>> {
    let bits = bytes_to_bits(notary_share);
    let n = bits.len();
    let mod2 = vec![2u16; n];
    let notary_wires = gb.encode_many(&bits, &mod2, channel)?;
    let client_wires = gb.receive_many(&mod2, channel)?;
    Ok(xor_wires(gb, &notary_wires, &client_wires))
}

fn ev_split_bytes<F: FancyBinary>(
    ev: &mut F,
    channel: &mut Channel,
    client_share: &[u8],
) -> SwankyResult<Vec<F::Item>> {
    let bits = bytes_to_bits(client_share);
    let n = bits.len();
    let mod2 = vec![2u16; n];
    let notary_wires = ev.receive_many(&mod2, channel)?;
    let client_wires = ev.encode_many(&bits, &mod2, channel)?;
    Ok(xor_wires(ev, &notary_wires, &client_wires))
}

/// One SHA-256 compression round (WRK17 authenticated garbling).
fn notary_sha256_compress_xor(
    channel: &mut Channel,
    iv_n: [u8; 32],
    block_n: [u8; 64],
) -> SwankyResult<[u8; 32]> {
    notary_sha256_compress_xor_wrk17(channel, iv_n, block_n)
}

fn client_sha256_compress_xor(
    channel: &mut Channel,
    iv_c: [u8; 32],
    block_c: [u8; 64],
) -> SwankyResult<[u8; 32]> {
    client_sha256_compress_xor_wrk17(channel, iv_c, block_c)
}

fn compress_xor_notary<F: FancyBinary>(
    gb: &mut F,
    channel: &mut Channel,
    circ: &BinaryCircuit,
    iv_n: [u8; 32],
    block_n: [u8; 64],
) -> SwankyResult<[u8; 32]> {
    let iv_wires = gb_split_bytes(gb, channel, &iv_n)?;
    let block_wires = gb_split_bytes(gb, channel, &block_n)?;
    let mut inputs = iv_wires;
    inputs.extend(block_wires);
    let out = circ.execute(gb, &inputs, channel)?;
    notary_mask_output(gb, channel, &out)
}

fn compress_xor_client<F: FancyBinary>(
    ev: &mut F,
    channel: &mut Channel,
    circ: &BinaryCircuit,
    iv_c: [u8; 32],
    block_c: [u8; 64],
) -> SwankyResult<[u8; 32]> {
    let iv_wires = ev_split_bytes(ev, channel, &iv_c)?;
    let block_wires = ev_split_bytes(ev, channel, &block_c)?;
    let mut inputs = iv_wires;
    inputs.extend(block_wires);
    let out = circ.execute(ev, &inputs, channel)?;
    client_unmask_output(ev, channel, &out)
}

#[cfg(test)]
fn notary_sha256_compress_xor_semihonest(
    channel: &mut Channel,
    iv_n: [u8; 32],
    block_n: [u8; 64],
) -> SwankyResult<[u8; 32]> {
    use fancy_garbling::WireMod2;
    let rng = SwankyRng::new();
    let circ = sha256_compress_circuit();
    let mut gb = SemiGb::<SwankyRng, OtSender, WireMod2>::new(channel, rng)?;
    compress_xor_notary(&mut gb, channel, &circ, iv_n, block_n)
}

#[cfg(test)]
fn client_sha256_compress_xor_semihonest(
    channel: &mut Channel,
    iv_c: [u8; 32],
    block_c: [u8; 64],
) -> SwankyResult<[u8; 32]> {
    use fancy_garbling::WireMod2;
    let rng = SwankyRng::new();
    let circ = sha256_compress_circuit();
    let mut ev = SemiEv::<SwankyRng, OtReceiver, WireMod2>::new(channel, rng)?;
    compress_xor_client(&mut ev, channel, &circ, iv_c, block_c)
}

fn notary_mask_output<F: FancyBinary>(
    f: &mut F,
    channel: &mut Channel,
    wires: &[F::Item],
) -> SwankyResult<[u8; 32]> {
    let mut m_n = [0u8; 32];
    rand::thread_rng().fill(&mut m_n);
    let mask = f.encode_many(&bytes_to_bits(&m_n), &vec![2u16; 256], channel)?;
    let masked = xor_wires(f, wires, &mask);
    f.outputs(&masked, channel)?;
    Ok(m_n)
}

fn client_unmask_output<F: FancyBinary>(
    f: &mut F,
    channel: &mut Channel,
    wires: &[F::Item],
) -> SwankyResult<[u8; 32]> {
    let mask = f.receive_many(&vec![2u16; 256], channel)?;
    let masked = xor_wires(f, wires, &mask);
    let vals = f
        .outputs(&masked, channel)?
        .expect("evaluator always receives output");
    Ok(bits_to_bytes_32(&vals))
}

/// WRK17 compress: garbler/evaluator input regions + in-circuit XOR (one auth share per wire).
fn compress_xor_notary_wrk17(
    gb: &mut impl FancyBinary,
    channel: &mut Channel,
    circ: &crate::garble::SplitSharedInputMaskCircuit,
    iv_n: [u8; 32],
    block_n: [u8; 64],
) -> SwankyResult<[u8; 32]> {
    let mut m_n = [0u8; 32];
    rand::thread_rng().fill(&mut m_n);

    let mut gb_vals = Vec::with_capacity(circ.garbler_inputs());
    gb_vals.extend(bytes_to_bits(
        &[&iv_n[..], &block_n[..]].concat(),
    ));
    gb_vals.extend(bytes_to_bits(&m_n));

    let mod2 = vec![2u16; circ.garbler_inputs()];
    let mine = gb.encode_many(&gb_vals, &mod2, channel)?;
    let theirs = gb.receive_many(&vec![2u16; circ.evaluator_inputs()], channel)?;
    let mut inputs = mine;
    inputs.extend(theirs);

    let out = circ.execute(gb, &inputs, channel)?;
    gb.outputs(&out, channel)?;
    Ok(m_n)
}

fn compress_xor_client_wrk17(
    ev: &mut impl FancyBinary,
    channel: &mut Channel,
    circ: &crate::garble::SplitSharedInputMaskCircuit,
    iv_c: [u8; 32],
    block_c: [u8; 64],
) -> SwankyResult<[u8; 32]> {
    let mut ev_vals = Vec::with_capacity(circ.evaluator_inputs());
    ev_vals.extend(bytes_to_bits(
        &[&iv_c[..], &block_c[..]].concat(),
    ));
    ev_vals.extend(vec![0u16; crate::garble::OUTPUT_MASK_BITS]);

    let notary = ev.receive_many(&vec![2u16; circ.garbler_inputs()], channel)?;
    let mine = ev.encode_many(&ev_vals, &vec![2u16; circ.evaluator_inputs()], channel)?;
    let mut inputs = notary;
    inputs.extend(mine);

    let out = circ.execute(ev, &inputs, channel)?;
    let vals = ev
        .outputs(&out, channel)?
        .expect("WRK17 evaluator receives circuit output");
    Ok(bits_to_bytes_32(&vals))
}

fn notary_sha256_compress_xor_wrk17(
    channel: &mut Channel,
    iv_n: [u8; 32],
    block_n: [u8; 64],
) -> SwankyResult<[u8; 32]> {
    let rng = SwankyRng::new();
    let circ = sha256_compress_wrk17_circuit();
    let mut gb = crate::garble::Garbler::new(&circ, channel, rng)?;
    compress_xor_notary_wrk17(&mut gb, channel, &circ, iv_n, block_n)
}

fn client_sha256_compress_xor_wrk17(
    channel: &mut Channel,
    iv_c: [u8; 32],
    block_c: [u8; 64],
) -> SwankyResult<[u8; 32]> {
    let mut rng = SwankyRng::new();
    let circ = sha256_compress_wrk17_circuit();
    let mut ev = crate::garble::Evaluator::new(&circ, channel, &mut rng)?;
    compress_xor_client_wrk17(&mut ev, channel, &circ, iv_c, block_c)
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

    let h_inner_1_n =
        notary_sha256_compress_xor(channel, SHA256_INITIAL_IV_BYTES, k_ipad_n)?;
    let notary_pad = notary_inner_padding(msg_len);
    let h_inner_final_n = notary_sha256_compress_xor(channel, h_inner_1_n, notary_pad)?;
    let h_outer_1_n =
        notary_sha256_compress_xor(channel, SHA256_INITIAL_IV_BYTES, k_opad_n)?;

    let outer_suffix = outer_suffix_padding();
    let mut block_n = [0u8; 64];
    block_n[..32].copy_from_slice(&h_inner_final_n);
    block_n[32..].copy_from_slice(&outer_suffix);
    notary_sha256_compress_xor(channel, h_outer_1_n, block_n)
}

/// Client side of 2PC HMAC-SHA256.
pub fn client_hmac_sha256(
    channel: &mut Channel,
    key_c: [u8; 32],
    msg: &[u8],
) -> SwankyResult<[u8; 32]> {
    let mut k_ipad_c = [0u8; 64];
    let mut k_opad_c = [0u8; 64];
    for i in 0..32 {
        k_ipad_c[i] = key_c[i];
        k_opad_c[i] = key_c[i];
    }

    let h_inner_1_c = client_sha256_compress_xor(channel, [0u8; 32], k_ipad_c)?;
    let client_msg_block = client_inner_msg(msg);
    let h_inner_final_c = client_sha256_compress_xor(channel, h_inner_1_c, client_msg_block)?;
    let h_outer_1_c = client_sha256_compress_xor(channel, [0u8; 32], k_opad_c)?;

    let mut block_c = [0u8; 64];
    block_c[..32].copy_from_slice(&h_inner_final_c);
    client_sha256_compress_xor(channel, h_outer_1_c, block_c)
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

// ── XOR-shared 32-byte HMAC message (secret IKM) ─────────────────────────────

fn notary_xor_msg_block(notary_share: &[u8; 32]) -> [u8; 64] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(notary_share);
    block[32] = 0x80;
    let total_bits = (64 + 32) as u64 * 8;
    block[56..64].copy_from_slice(&total_bits.to_be_bytes());
    block
}

fn client_xor_msg_block(client_share: &[u8; 32]) -> [u8; 64] {
    let mut block = [0u8; 64];
    block[..32].copy_from_slice(client_share);
    block
}

/// Notary side of HMAC when the 32-byte message is XOR-shared (`msg = msg_n ⊕ msg_c`).
pub fn notary_hmac_sha256_xor_msg(
    channel: &mut Channel,
    key_n: [u8; 32],
    msg_n: [u8; 32],
) -> SwankyResult<[u8; 32]> {
    notary_hmac_sha256_xor_msg_inner(channel, key_n, msg_n)
}

fn notary_hmac_sha256_xor_msg_inner(
    channel: &mut Channel,
    key_n: [u8; 32],
    msg_n: [u8; 32],
) -> SwankyResult<[u8; 32]> {
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

    let h_inner_1_n =
        notary_sha256_compress_xor(channel, SHA256_INITIAL_IV_BYTES, k_ipad_n)?;
    let notary_pad = notary_xor_msg_block(&msg_n);
    let h_inner_final_n = notary_sha256_compress_xor(channel, h_inner_1_n, notary_pad)?;
    let h_outer_1_n =
        notary_sha256_compress_xor(channel, SHA256_INITIAL_IV_BYTES, k_opad_n)?;

    let outer_suffix = outer_suffix_padding();
    let mut block_n = [0u8; 64];
    block_n[..32].copy_from_slice(&h_inner_final_n);
    block_n[32..].copy_from_slice(&outer_suffix);
    notary_sha256_compress_xor(channel, h_outer_1_n, block_n)
}

/// Client side of [`notary_hmac_sha256_xor_msg`].
pub fn client_hmac_sha256_xor_msg(
    channel: &mut Channel,
    key_c: [u8; 32],
    msg_c: [u8; 32],
) -> SwankyResult<[u8; 32]> {
    client_hmac_sha256_xor_msg_inner(channel, key_c, msg_c)
}

fn client_hmac_sha256_xor_msg_inner(
    channel: &mut Channel,
    key_c: [u8; 32],
    msg_c: [u8; 32],
) -> SwankyResult<[u8; 32]> {
    let mut k_ipad_c = [0u8; 64];
    let mut k_opad_c = [0u8; 64];
    for i in 0..32 {
        k_ipad_c[i] = key_c[i];
        k_opad_c[i] = key_c[i];
    }

    let h_inner_1_c = client_sha256_compress_xor(channel, [0u8; 32], k_ipad_c)?;
    let client_block = client_xor_msg_block(&msg_c);
    let h_inner_final_c = client_sha256_compress_xor(channel, h_inner_1_c, client_block)?;
    let h_outer_1_c = client_sha256_compress_xor(channel, [0u8; 32], k_opad_c)?;

    let mut block_c = [0u8; 64];
    block_c[..32].copy_from_slice(&h_inner_final_c);
    client_sha256_compress_xor(channel, h_outer_1_c, block_c)
}

/// HKDF-Extract with XOR-shared 32-byte IKM (neither party holds full IKM).
pub fn notary_hkdf_extract_xor_ikm(
    channel: &mut Channel,
    salt_n: [u8; 32],
    ikm_n: [u8; 32],
) -> SwankyResult<[u8; 32]> {
    notary_hmac_sha256_xor_msg(channel, salt_n, ikm_n)
}

pub fn client_hkdf_extract_xor_ikm(
    channel: &mut Channel,
    salt_c: [u8; 32],
    ikm_c: [u8; 32],
) -> SwankyResult<[u8; 32]> {
    client_hmac_sha256_xor_msg(channel, salt_c, ikm_c)
}

// ── Reference TLS 1.3 key schedule (single-party oracle) ─────────────────────

pub fn reference_empty_hash() -> [u8; 32] {
    Sha256::digest([]).into()
}

pub fn reference_hkdf_extract(salt: &[u8; 32], ikm: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let mut mac = Hmac::<Sha256>::new_from_slice(salt).expect("HMAC key");
    mac.update(ikm);
    mac.finalize().into_bytes().into()
}

pub fn reference_hkdf_expand_label(prk: &[u8; 32], label: &str, context: &[u8], len: u16) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    let info = hkdf_expand_label_info(label, context, len);
    let mut mac = Hmac::<Sha256>::new_from_slice(prk).expect("HMAC key");
    mac.update(&info);
    mac.finalize().into_bytes().into()
}

/// Client traffic keys/IVs from full IKM + TLS 1.3 transcript hashes (RFC 8446 §7).
pub fn reference_tls13_client_traffic(
    ikm: &[u8; 32],
    transcript_after_sh: &[u8; 32],
    transcript_after_sf: &[u8; 32],
) -> ([u8; 16], [u8; 12], [u8; 16], [u8; 12]) {
    let empty = reference_empty_hash();
    let early = reference_hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let derived1 = reference_hkdf_expand_label(&early, "derived", &empty, 32);
    let hs = reference_hkdf_extract(&derived1, ikm);
    let _client_hs = reference_hkdf_expand_label(&hs, "c hs traffic", transcript_after_sh, 32);
    let derived2 = reference_hkdf_expand_label(&hs, "derived", &empty, 32);
    let master = reference_hkdf_extract(&derived2, &[0u8; 32]);
    let client_app = reference_hkdf_expand_label(&master, "c ap traffic", transcript_after_sf, 32);
    let server_app = reference_hkdf_expand_label(&master, "s ap traffic", transcript_after_sf, 32);
    let mut tx_key = [0u8; 16];
    let mut tx_iv = [0u8; 12];
    let mut rx_key = [0u8; 16];
    let mut rx_iv = [0u8; 12];
    tx_key.copy_from_slice(&reference_hkdf_expand_label(&client_app, "key", &[], 16)[..16]);
    tx_iv.copy_from_slice(&reference_hkdf_expand_label(&client_app, "iv", &[], 12)[..12]);
    rx_key.copy_from_slice(&reference_hkdf_expand_label(&server_app, "key", &[], 16)[..16]);
    rx_iv.copy_from_slice(&reference_hkdf_expand_label(&server_app, "iv", &[], 12)[..12]);
    (tx_key, tx_iv, rx_key, rx_iv)
}

/// XOR shares of client write/read traffic keys + public IVs from XOR-shared IKM.
#[derive(Debug, Clone, Copy)]
pub struct ClientTrafficShares {
    pub k_c_tx: [u8; 16],
    pub k_c_rx: [u8; 16],
    pub iv_tx: [u8; 12],
    pub iv_rx: [u8; 12],
}

#[derive(Debug, Clone, Copy)]
pub struct NotaryTrafficShares {
    pub k_n_tx: [u8; 16],
    pub k_n_rx: [u8; 16],
    pub iv_tx: [u8; 12],
    pub iv_rx: [u8; 12],
}

pub fn xor32(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

pub fn xor16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

pub fn notary_tls13_client_traffic_from_ikm_shares(
    channel: &mut Channel,
    ikm_n: [u8; 32],
    transcript_after_sh: [u8; 32],
    transcript_after_sf: [u8; 32],
) -> SwankyResult<NotaryTrafficShares> {
    let empty = reference_empty_hash();
    let early = reference_hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let derived1 = reference_hkdf_expand_label(&early, "derived", &empty, 32);

    let hs_n = notary_hkdf_extract_xor_ikm(channel, derived1, ikm_n)?;
    let _client_hs_n = notary_hkdf_expand_label(channel, hs_n, "c hs traffic", &transcript_after_sh, 32)?;
    let derived2_n = notary_hkdf_expand_label(channel, hs_n, "derived", &empty, 32)?;
    let master_n = notary_hkdf_extract(channel, derived2_n, 32)?;
    let client_app_n =
        notary_hkdf_expand_label(channel, master_n, "c ap traffic", &transcript_after_sf, 32)?;
    let server_app_n =
        notary_hkdf_expand_label(channel, master_n, "s ap traffic", &transcript_after_sf, 32)?;

    let mut k_n_tx = [0u8; 16];
    let mut k_n_rx = [0u8; 16];
    let tx_full = notary_hkdf_expand_label(channel, client_app_n, "key", &[], 16)?;
    let rx_full = notary_hkdf_expand_label(channel, server_app_n, "key", &[], 16)?;
    k_n_tx.copy_from_slice(&tx_full[..16]);
    k_n_rx.copy_from_slice(&rx_full[..16]);

    let iv_tx_share = notary_hkdf_expand_label(channel, client_app_n, "iv", &[], 12)?;
    let iv_rx_share = notary_hkdf_expand_label(channel, server_app_n, "iv", &[], 12)?;
    let mut iv_tx = [0u8; 12];
    let mut iv_rx = [0u8; 12];
    iv_tx.copy_from_slice(&iv_tx_share[..12]);
    iv_rx.copy_from_slice(&iv_rx_share[..12]);

    Ok(NotaryTrafficShares {
        k_n_tx,
        k_n_rx,
        iv_tx,
        iv_rx,
    })
}

/// Host side of [`notary_tls13_client_traffic_from_ikm_shares`].
pub fn client_tls13_client_traffic_from_ikm_shares(
    channel: &mut Channel,
    ikm_c: [u8; 32],
    transcript_after_sh: [u8; 32],
    transcript_after_sf: [u8; 32],
) -> SwankyResult<ClientTrafficShares> {
    let empty = reference_empty_hash();
    let early = reference_hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let _derived1 = reference_hkdf_expand_label(&early, "derived", &empty, 32);

    let hs_c = client_hkdf_extract_xor_ikm(channel, [0u8; 32], ikm_c)?;
    let _client_hs_c =
        client_hkdf_expand_label(channel, hs_c, "c hs traffic", &transcript_after_sh, 32)?;
    let derived2_c = client_hkdf_expand_label(channel, hs_c, "derived", &empty, 32)?;
    let master_c = client_hkdf_extract(channel, derived2_c, &[0u8; 32])?;
    let client_app_c =
        client_hkdf_expand_label(channel, master_c, "c ap traffic", &transcript_after_sf, 32)?;
    let server_app_c =
        client_hkdf_expand_label(channel, master_c, "s ap traffic", &transcript_after_sf, 32)?;

    let mut k_c_tx = [0u8; 16];
    let mut k_c_rx = [0u8; 16];
    let tx_full = client_hkdf_expand_label(channel, client_app_c, "key", &[], 16)?;
    let rx_full = client_hkdf_expand_label(channel, server_app_c, "key", &[], 16)?;
    k_c_tx.copy_from_slice(&tx_full[..16]);
    k_c_rx.copy_from_slice(&rx_full[..16]);

    let iv_tx_share = client_hkdf_expand_label(channel, client_app_c, "iv", &[], 12)?;
    let iv_rx_share = client_hkdf_expand_label(channel, server_app_c, "iv", &[], 12)?;
    let mut iv_tx = [0u8; 12];
    let mut iv_rx = [0u8; 12];
    iv_tx.copy_from_slice(&iv_tx_share[..12]);
    iv_rx.copy_from_slice(&iv_rx_share[..12]);

    Ok(ClientTrafficShares {
        k_c_tx,
        k_c_rx,
        iv_tx,
        iv_rx,
    })
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

    fn reference_sha256_compress(iv: [u8; 32], block: [u8; 64]) -> [u8; 32] {
        use sha2::compress256;
        use sha2::digest::generic_array::GenericArray;

        let mut state: [u32; 8] = std::array::from_fn(|i| {
            u32::from_be_bytes(iv[i * 4..i * 4 + 4].try_into().unwrap())
        });
        let block_ga = GenericArray::clone_from_slice(&block);
        compress256(&mut state, core::slice::from_ref(&block_ga));
        let mut out = [0u8; 32];
        for (i, w) in state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    #[test]
    fn sha256_compress_2pc_round_matches_reference() {
        let iv_n = SHA256_INITIAL_IV_BYTES;
        let iv_c = [0u8; 32];
        let block_n = [0x2bu8; 64];
        let block_c = [0x55u8; 64];
        let iv = xor32(iv_n, iv_c);
        let block = std::array::from_fn(|i| block_n[i] ^ block_c[i]);
        let expected = reference_sha256_compress(iv, block);

        let (n_share, c_share) = local_channel_pair(
            |ch| notary_sha256_compress_xor(ch, iv_n, block_n),
            |ch| client_sha256_compress_xor(ch, iv_c, block_c),
        )
        .unwrap();
        assert_eq!(xor32(n_share, c_share), expected);
    }

    #[test]
    fn sha256_compress_2pc_semihonest_round_matches_reference() {
        let iv_n = SHA256_INITIAL_IV_BYTES;
        let iv_c = [0u8; 32];
        let block_n = [0x2bu8; 64];
        let block_c = [0x55u8; 64];
        let iv = xor32(iv_n, iv_c);
        let block = std::array::from_fn(|i| block_n[i] ^ block_c[i]);
        let expected = reference_sha256_compress(iv, block);

        let (n_share, c_share) = local_channel_pair(
            |ch| notary_sha256_compress_xor_semihonest(ch, iv_n, block_n),
            |ch| client_sha256_compress_xor_semihonest(ch, iv_c, block_c),
        )
        .unwrap();
        assert_eq!(xor32(n_share, c_share), expected);
    }

    #[test]
    fn sha256_compress_2pc_auth_round_matches_reference() {
        let iv_n = SHA256_INITIAL_IV_BYTES;
        let iv_c = [0u8; 32];
        let block_n = [0x2bu8; 64];
        let block_c = [0x55u8; 64];
        let iv = xor32(iv_n, iv_c);
        let block = std::array::from_fn(|i| block_n[i] ^ block_c[i]);
        let expected = reference_sha256_compress(iv, block);

        let (n_share, c_share) = local_channel_pair(
            |ch| notary_sha256_compress_xor_wrk17(ch, iv_n, block_n),
            |ch| client_sha256_compress_xor_wrk17(ch, iv_c, block_c),
        )
        .unwrap();
        assert_eq!(xor32(n_share, c_share), expected);
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

    #[test]
    fn hmac_sha256_xor_msg_matches_reference() {
        let k_n = [0x11u8; 32];
        let k_c = [0x22u8; 32];
        let k = xor32(k_n, k_c);
        let msg_n = [0x33u8; 32];
        let msg_c = [0x44u8; 32];
        let msg: [u8; 32] = xor32(msg_n, msg_c);

        let mut mac = HmacSha256::new_from_slice(&k).unwrap();
        mac.update(&msg);
        let expected: [u8; 32] = mac.finalize().into_bytes().into();

        let (n_share, c_share) = local_channel_pair(
            |ch| notary_hmac_sha256_xor_msg(ch, k_n, msg_n),
            |ch| client_hmac_sha256_xor_msg(ch, k_c, msg_c),
        )
        .unwrap();

        assert_eq!(xor32(n_share, c_share), expected);
    }

    #[test]
    fn tls13_traffic_2pc_matches_reference() {
        let ikm: [u8; 32] = [0x5au8; 32];
        let ikm_n = [0xa1u8; 32];
        let ikm_c = xor32(ikm_n, ikm);
        let after_sh = [0x01u8; 32];
        let after_sf = [0x02u8; 32];

        let (tx, iv_tx, rx, iv_rx) = reference_tls13_client_traffic(&ikm, &after_sh, &after_sf);

        let (n_shares, c_shares) = local_channel_pair(
            |ch| {
                notary_tls13_client_traffic_from_ikm_shares(ch, ikm_n, after_sh, after_sf)
            },
            |ch| {
                client_tls13_client_traffic_from_ikm_shares(ch, ikm_c, after_sh, after_sf)
            },
        )
        .unwrap();

        assert_eq!(xor16(n_shares.k_n_tx, c_shares.k_c_tx), tx);
        assert_eq!(xor16(n_shares.k_n_rx, c_shares.k_c_rx), rx);
        assert_eq!(xor32(
            {
                let mut a = [0u8; 32];
                a[..12].copy_from_slice(&n_shares.iv_tx);
                a
            },
            {
                let mut b = [0u8; 32];
                b[..12].copy_from_slice(&c_shares.iv_tx);
                b
            },
        )[..12], iv_tx);
        assert_eq!(
            xor32(
                {
                    let mut a = [0u8; 32];
                    a[..12].copy_from_slice(&n_shares.iv_rx);
                    a
                },
                {
                    let mut b = [0u8; 32];
                    b[..12].copy_from_slice(&c_shares.iv_rx);
                    b
                },
            )[..12],
            iv_rx
        );
    }
}
