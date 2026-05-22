//! Split-key AES-GCM via two-party garbled circuit.
//!
//! Notary  = Garbler   — holds K_n, co-encrypts request but never sees plaintext
//! Client  = Evaluator — holds K_c and plaintext, receives ciphertext output
//!
//! Encrypt path (2PC):
//!   K = K_c XOR K_n  (free-XOR: zero AND gates)
//!   keystream = AES(K, nonce||ctr)   (~6800 AND gates via Bristol circuit)
//!   ciphertext = plaintext XOR keystream  (free)
//!
//! Decrypt path (no 2PC, response direction):
//!   notary commits H(response_ciphertext), then reveals K_n
//!   client reconstructs K = K_c XOR K_n, decrypts with standard AES-GCM

use fancy_garbling::{
    Fancy, FancyBinary, WireMod2,
    circuit::{BinaryCircuit, CircuitExecutor},
};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use swanky_channel::Channel;
use swanky_error::Result as SwankyResult;
use swanky_ot_chou_orlandi::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

// ── circuit ───────────────────────────────────────────────────────────────────

fn aes_circuit() -> BinaryCircuit {
    BinaryCircuit::parse(std::io::Cursor::new(include_bytes!(
        "../circuits/AES-non-expanded.txt"
    )))
    .expect("bundled AES Bristol circuit is valid")
}

// ── notary side (garbler) ─────────────────────────────────────────────────────

/// Notary co-encrypts one 16-byte block. Must be called in lockstep with
/// `client_encrypt_block` on the other side.
pub fn notary_encrypt_block(
    channel: &mut Channel,
    k_n: [u8; 16],
    nonce_ctr: [u8; 16], // nonce (12 B) || counter (4 B, big-endian)
) -> SwankyResult<()> {
    let rng = SwankyRng::new();
    let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(channel, rng)?;
    let mod2 = vec![2u16; 128];

    // Garbler encodes nonce_ctr (public, AES "plaintext" in CTR mode).
    // The Bristol AES circuit has nonce_ctr as its FIRST 128 input wires.
    let nonce_bits = gb.encode_many(&bytes_to_bits(&nonce_ctr), &mod2, channel)?;
    // Garbler encodes K_n — evaluator receives wire labels but cannot recover K_n.
    // K_n contributes to the AES key (second 128 circuit inputs after XOR with K_c).
    let k_n_bits = gb.encode_many(&bytes_to_bits(&k_n), &mod2, channel)?;
    // Client provides K_c and plaintext via OT — garbler never learns these values
    let k_c_bits = gb.receive_many(&mod2, channel)?;
    let pt_bits = gb.receive_many(&mod2, channel)?;

    // K = K_n XOR K_c — free with free-XOR (zero AND gates, no communication)
    let mut k_bits = Vec::with_capacity(128);
    for i in 0..128 {
        k_bits.push(gb.xor(&k_n_bits[i], &k_c_bits[i]));
    }

    // Bristol AES circuit input order: [nonce_ctr (128), K (128)]
    // i.e. AES-ECB("plaintext"=nonce_ctr, key=K) → keystream
    let circ = aes_circuit();
    let mut circuit_inputs = nonce_bits;
    circuit_inputs.extend_from_slice(&k_bits);
    let keystream = circ.execute(&mut gb, &circuit_inputs, channel)?;

    // ciphertext = plaintext XOR keystream — free (no communication)
    let mut ct_bits = Vec::with_capacity(128);
    for i in 0..128 {
        ct_bits.push(gb.xor(&pt_bits[i], &keystream[i]));
    }

    // Garbler sends output hashes to evaluator; garbler itself receives None
    gb.outputs(&ct_bits, channel)?;
    Ok(())
}

/// Drive the notary side for a full multi-block CTR encryption.
/// Called in lockstep with `client_encrypt`.
pub fn notary_encrypt(
    channel: &mut Channel,
    k_n: [u8; 16],
    nonce: [u8; 12],
    block_count: usize,
) -> SwankyResult<()> {
    for ctr in 1..=block_count {
        let nonce_ctr = make_nonce_ctr(nonce, ctr as u32);
        notary_encrypt_block(channel, k_n, nonce_ctr)?;
    }
    Ok(())
}

// ── client side (evaluator) ───────────────────────────────────────────────────

/// Client co-encrypts one 16-byte block. Paired with `notary_encrypt_block`.
pub fn client_encrypt_block(
    channel: &mut Channel,
    k_c: [u8; 16],
    plaintext: [u8; 16],
    // Semi-honest: garbler encodes nonce_ctr and evaluator receives those wire
    // labels via receive_many; this parameter keeps the two signatures symmetric.
    _nonce_ctr: [u8; 16],
) -> SwankyResult<[u8; 16]> {
    let rng = SwankyRng::new();
    let mut ev = Evaluator::<SwankyRng, OtReceiver, WireMod2>::new(channel, rng)?;
    let mod2 = vec![2u16; 128];

    // Receive garbler's nonce_ctr wire labels (first 128 circuit inputs)
    let nonce_bits = ev.receive_many(&mod2, channel)?;
    // Receive notary's K_n wire labels — evaluating them cannot expose K_n
    let k_n_bits = ev.receive_many(&mod2, channel)?;
    // Client provides K_c and plaintext via OT — notary never learns these
    let k_c_bits = ev.encode_many(&bytes_to_bits(&k_c), &mod2, channel)?;
    let pt_bits = ev.encode_many(&bytes_to_bits(&plaintext), &mod2, channel)?;

    // K = K_n XOR K_c (free, no communication)
    let mut k_bits = Vec::with_capacity(128);
    for i in 0..128 {
        k_bits.push(ev.xor(&k_n_bits[i], &k_c_bits[i]));
    }

    // Mirror garbler's circuit input order: [nonce_ctr (128), K (128)]
    let circ = aes_circuit();
    let mut circuit_inputs = nonce_bits;
    circuit_inputs.extend_from_slice(&k_bits);
    let keystream = circ.execute(&mut ev, &circuit_inputs, channel)?;

    let mut ct_bits = Vec::with_capacity(128);
    for i in 0..128 {
        ct_bits.push(ev.xor(&pt_bits[i], &keystream[i]));
    }

    let ct_vals = ev
        .outputs(&ct_bits, channel)?
        .expect("evaluator always receives output");
    Ok(bits_to_bytes_16(ct_vals))
}

/// Encrypt an arbitrary-length plaintext in CTR mode.
/// Call in lockstep with `notary_encrypt`.
pub fn client_encrypt(
    channel: &mut Channel,
    k_c: [u8; 16],
    plaintext: &[u8],
    nonce: [u8; 12],
) -> SwankyResult<Vec<u8>> {
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for (ctr, chunk) in plaintext.chunks(16).enumerate() {
        let mut block = [0u8; 16];
        block[..chunk.len()].copy_from_slice(chunk);
        let nonce_ctr = make_nonce_ctr(nonce, (ctr + 1) as u32);
        let ct_block = client_encrypt_block(channel, k_c, block, nonce_ctr)?;
        ciphertext.extend_from_slice(&ct_block[..chunk.len()]);
    }
    Ok(ciphertext)
}

// ── GCM helpers (generic over FancyBinary, work for Garbler/Evaluator/Dummy) ──

/// Run the AES Bristol circuit on existing wire labels.
/// Inputs: `plaintext` (128) followed by `key` (128) — Bristol convention.
fn aes_block<F: FancyBinary>(
    f: &mut F,
    channel: &mut Channel,
    circ: &BinaryCircuit,
    plaintext: &[F::Item],
    key: &[F::Item],
) -> SwankyResult<Vec<F::Item>>
where
    F::Item: Clone,
{
    debug_assert_eq!(plaintext.len(), 128);
    debug_assert_eq!(key.len(), 128);
    let mut inputs = plaintext.to_vec();
    inputs.extend_from_slice(key);
    circ.execute(f, &inputs, channel)
}

/// Bitwise XOR of two equal-length wire vectors (free in free-XOR garbling).
fn xor_blocks<F: FancyBinary>(f: &mut F, a: &[F::Item], b: &[F::Item]) -> Vec<F::Item> {
    debug_assert_eq!(a.len(), b.len());
    let mut out = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        out.push(f.xor(&a[i], &b[i]));
    }
    out
}

/// Multiplication in GF(2^128) with the GCM irreducible polynomial
/// (x^128 + x^7 + x^2 + x + 1). Implements NIST SP 800-38D §6.3 Algorithm 1
/// in MSB-first bit ordering: wire 0 = coefficient of x^0 (leftmost bit).
///
/// Costs 128 × 128 = 16384 AND gates per call.
fn ghash_mul<F: FancyBinary>(
    f: &mut F,
    channel: &mut Channel,
    x: &[F::Item],
    y: &[F::Item],
) -> SwankyResult<Vec<F::Item>>
where
    F::Item: Clone,
{
    debug_assert_eq!(x.len(), 128);
    debug_assert_eq!(y.len(), 128);

    let zero = f.constant(0, 2, channel)?;
    let mut z: Vec<F::Item> = (0..128).map(|_| zero.clone()).collect();
    let mut v: Vec<F::Item> = y.to_vec();

    for i in 0..128 {
        // z = z XOR (x[i] AND v) — conditional accumulator
        for j in 0..128 {
            let xv = f.and(&x[i], &v[j], channel)?;
            let new_zj = f.xor(&z[j], &xv);
            z[j] = new_zj;
        }
        // The bit at position 127 (LSB in MSB-first ordering) falls off on right-shift.
        let lsb = v[127].clone();
        // Right-shift V: v[0] := 0, v[k] := v[k-1] for k >= 1.
        let mut new_v = Vec::with_capacity(128);
        new_v.push(zero.clone());
        for k in 0..127 {
            new_v.push(v[k].clone());
        }
        v = new_v;
        // If the bit fell off, XOR with R = 0xe1 || 0^120 (bits 0,1,2,7 set).
        // Unconditional XOR with `lsb` at those positions does the right thing:
        // lsb=0 → no-op, lsb=1 → toggle (== XOR with R[r]=1).
        for &r in &[0usize, 1, 2, 7] {
            let new_vr = f.xor(&v[r], &lsb);
            v[r] = new_vr;
        }
    }
    Ok(z)
}

// ── notary side (garbler) for split-key AES-GCM ───────────────────────────────

/// Notary side of split-key AES-128-GCM with AAD + arbitrary-length plaintext.
///
/// Produces a real GCM ciphertext + 128-bit tag without ever learning K.
/// `aad` is authenticated but not encrypted; both parties must pass the same
/// AAD (the garbler encodes it as the source of truth).
/// `plaintext_len` is the byte-length of the plaintext the client will provide.
pub fn notary_encrypt_gcm(
    channel: &mut Channel,
    k_n: [u8; 16],
    nonce: [u8; 12],
    aad: &[u8],
    plaintext_len: usize,
) -> SwankyResult<()> {
    let rng = SwankyRng::new();
    let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(channel, rng)?;
    let mod2 = vec![2u16; 128];
    let circ = aes_circuit();

    let n_aad_blocks = aad.len().div_ceil(16);
    let n_pt_blocks = plaintext_len.div_ceil(16);
    let pt_last_bytes = if plaintext_len == 0 { 0 } else { ((plaintext_len - 1) % 16) + 1 };

    // K = K_n XOR K_c (free)
    let k_n_bits = gb.encode_many(&bytes_to_bits(&k_n), &mod2, channel)?;
    let k_c_bits = gb.receive_many(&mod2, channel)?;
    let k_bits = xor_blocks(&mut gb, &k_n_bits, &k_c_bits);

    // H = AES_K(0^128) and S = AES_K(J0)
    let zero_block_bits = gb.encode_many(&bytes_to_bits(&[0u8; 16]), &mod2, channel)?;
    let h_bits = aes_block(&mut gb, channel, &circ, &zero_block_bits, &k_bits)?;

    let j0 = make_nonce_ctr(nonce, 1);
    let j0_bits = gb.encode_many(&bytes_to_bits(&j0), &mod2, channel)?;
    let s_bits = aes_block(&mut gb, channel, &circ, &j0_bits, &k_bits)?;

    let zero = gb.constant(0, 2, channel)?;
    let mut x_acc: Vec<WireMod2> = (0..128).map(|_| zero.clone()).collect();

    // AAD blocks (last block zero-padded if AAD len not a multiple of 16)
    for blk in 0..n_aad_blocks {
        let mut aad_block = [0u8; 16];
        let start = blk * 16;
        let end = ((blk + 1) * 16).min(aad.len());
        aad_block[..end - start].copy_from_slice(&aad[start..end]);
        let aad_bits = gb.encode_many(&bytes_to_bits(&aad_block), &mod2, channel)?;
        let xored = xor_blocks(&mut gb, &x_acc, &aad_bits);
        x_acc = ghash_mul(&mut gb, channel, &xored, &h_bits)?;
    }

    // Plaintext blocks (CTR + GHASH); track output length per block
    let mut ct_blocks: Vec<(Vec<WireMod2>, usize)> = Vec::with_capacity(n_pt_blocks);
    for blk in 0..n_pt_blocks {
        let valid_bytes = if blk == n_pt_blocks - 1 { pt_last_bytes } else { 16 };
        let ctr_block = make_nonce_ctr(nonce, (blk as u32) + 2);
        let ctr_bits = gb.encode_many(&bytes_to_bits(&ctr_block), &mod2, channel)?;
        let keystream = aes_block(&mut gb, channel, &circ, &ctr_bits, &k_bits)?;
        // Client encodes a 16-byte block (zero-padded if last is partial)
        let pt_bits = gb.receive_many(&mod2, channel)?;
        let ct_bits = xor_blocks(&mut gb, &pt_bits, &keystream);

        // For GHASH: replace bytes [valid_bytes..16] with constant zero wires.
        // Since the mask is public, no AND gates needed — just wire substitution.
        let ct_for_ghash: Vec<WireMod2> = if valid_bytes < 16 {
            (0..128)
                .map(|i| {
                    if i / 8 < valid_bytes {
                        ct_bits[i].clone()
                    } else {
                        zero.clone()
                    }
                })
                .collect()
        } else {
            ct_bits.clone()
        };
        let xored = xor_blocks(&mut gb, &x_acc, &ct_for_ghash);
        x_acc = ghash_mul(&mut gb, channel, &xored, &h_bits)?;
        ct_blocks.push((ct_bits, valid_bytes));
    }

    // Length block uses actual BIT lengths of AAD and ciphertext
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..16].copy_from_slice(&((plaintext_len as u64) * 8).to_be_bytes());
    let len_bits = gb.encode_many(&bytes_to_bits(&len_block), &mod2, channel)?;
    let xored = xor_blocks(&mut gb, &x_acc, &len_bits);
    let x_final = ghash_mul(&mut gb, channel, &xored, &h_bits)?;

    let tag_bits = xor_blocks(&mut gb, &x_final, &s_bits);

    // Reveal: only the valid bits of each ciphertext block + tag
    let mut all_outputs: Vec<WireMod2> = Vec::new();
    for (ct_bits, valid_bytes) in &ct_blocks {
        all_outputs.extend_from_slice(&ct_bits[..valid_bytes * 8]);
    }
    all_outputs.extend(tag_bits);
    gb.outputs(&all_outputs, channel)?;

    Ok(())
}

// ── client side (evaluator) for split-key AES-GCM ─────────────────────────────

/// Client side of split-key AES-128-GCM with AAD + arbitrary-length plaintext.
/// Returns `(ciphertext, tag)`. The output `ciphertext || tag` is a valid
/// AES-128-GCM ciphertext per NIST SP 800-38D / RFC 5288, including AAD.
/// `aad` must match what the notary passes; the protocol relies on the notary
/// encoding it as the canonical source.
pub fn client_encrypt_gcm(
    channel: &mut Channel,
    k_c: [u8; 16],
    plaintext: &[u8],
    aad: &[u8],
    _nonce: [u8; 12],
) -> SwankyResult<(Vec<u8>, [u8; 16])> {
    let pt_len = plaintext.len();
    let n_aad_blocks = aad.len().div_ceil(16);
    let n_pt_blocks = pt_len.div_ceil(16);
    let pt_last_bytes = if pt_len == 0 { 0 } else { ((pt_len - 1) % 16) + 1 };

    let rng = SwankyRng::new();
    let mut ev = Evaluator::<SwankyRng, OtReceiver, WireMod2>::new(channel, rng)?;
    let mod2 = vec![2u16; 128];
    let circ = aes_circuit();

    let k_n_bits = ev.receive_many(&mod2, channel)?;
    let k_c_bits = ev.encode_many(&bytes_to_bits(&k_c), &mod2, channel)?;
    let k_bits = xor_blocks(&mut ev, &k_n_bits, &k_c_bits);

    let zero_block_bits = ev.receive_many(&mod2, channel)?;
    let h_bits = aes_block(&mut ev, channel, &circ, &zero_block_bits, &k_bits)?;

    let j0_bits = ev.receive_many(&mod2, channel)?;
    let s_bits = aes_block(&mut ev, channel, &circ, &j0_bits, &k_bits)?;

    let zero = ev.constant(0, 2, channel)?;
    let mut x_acc: Vec<WireMod2> = (0..128).map(|_| zero.clone()).collect();

    // AAD blocks
    for _ in 0..n_aad_blocks {
        let aad_bits = ev.receive_many(&mod2, channel)?;
        let xored = xor_blocks(&mut ev, &x_acc, &aad_bits);
        x_acc = ghash_mul(&mut ev, channel, &xored, &h_bits)?;
    }

    // Plaintext blocks — retain ct_bits per block to drive the final outputs() call
    let mut ct_blocks: Vec<(Vec<WireMod2>, usize)> = Vec::with_capacity(n_pt_blocks);
    for blk in 0..n_pt_blocks {
        let valid_bytes = if blk == n_pt_blocks - 1 { pt_last_bytes } else { 16 };
        let ctr_bits = ev.receive_many(&mod2, channel)?;
        let keystream = aes_block(&mut ev, channel, &circ, &ctr_bits, &k_bits)?;
        let mut pt_block = [0u8; 16];
        let start = blk * 16;
        let end = ((blk + 1) * 16).min(pt_len);
        pt_block[..end - start].copy_from_slice(&plaintext[start..end]);
        let pt_bits = ev.encode_many(&bytes_to_bits(&pt_block), &mod2, channel)?;
        let ct_bits = xor_blocks(&mut ev, &pt_bits, &keystream);

        let ct_for_ghash: Vec<WireMod2> = if valid_bytes < 16 {
            (0..128)
                .map(|i| {
                    if i / 8 < valid_bytes {
                        ct_bits[i].clone()
                    } else {
                        zero.clone()
                    }
                })
                .collect()
        } else {
            ct_bits.clone()
        };
        let xored = xor_blocks(&mut ev, &x_acc, &ct_for_ghash);
        x_acc = ghash_mul(&mut ev, channel, &xored, &h_bits)?;

        ct_blocks.push((ct_bits, valid_bytes));
    }

    let len_bits = ev.receive_many(&mod2, channel)?;
    let xored = xor_blocks(&mut ev, &x_acc, &len_bits);
    let x_final = ghash_mul(&mut ev, channel, &xored, &h_bits)?;
    let tag_bits = xor_blocks(&mut ev, &x_final, &s_bits);

    // Mirror the garbler's output ordering: per-block valid bits, then tag.
    let mut all_outputs: Vec<WireMod2> = Vec::new();
    for (ct_bits, valid_bytes) in &ct_blocks {
        all_outputs.extend_from_slice(&ct_bits[..valid_bytes * 8]);
    }
    all_outputs.extend(tag_bits);

    let vals = ev
        .outputs(&all_outputs, channel)?
        .expect("evaluator always receives output");

    let mut ciphertext = Vec::with_capacity(pt_len);
    let mut cursor = 0;
    for (_, valid_bytes) in &ct_blocks {
        let chunk: Vec<u16> = vals[cursor..cursor + valid_bytes * 8].to_vec();
        ciphertext.extend_from_slice(&bits_to_bytes_partial(chunk, *valid_bytes));
        cursor += valid_bytes * 8;
    }
    let tag_vals: Vec<u16> = vals[cursor..].to_vec();
    let tag = bits_to_bytes_16(tag_vals);

    Ok((ciphertext, tag))
}

/// Decode a variable-length bit vector (MSB-first per byte) into bytes.
fn bits_to_bytes_partial(bits: Vec<u16>, n_bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; n_bytes];
    for (i, chunk) in bits.chunks(8).enumerate().take(n_bytes) {
        for (j, &bit) in chunk.iter().enumerate() {
            out[i] |= (bit as u8) << (7 - j);
        }
    }
    out
}

// ── commit-reveal decrypt (no circuit needed) ─────────────────────────────────

/// Notary commitment to the response ciphertext.
/// Must be signed before K_n is revealed — the ordering is the security argument.
pub struct NotaryCommit {
    pub ciphertext_hash: [u8; 32], // SHA-256(ciphertext || nonce || session_id)
    pub signature: Vec<u8>,        // HMAC-SHA256 over ciphertext_hash with notary's long-term key
}

impl NotaryCommit {
    /// Create and sign a commitment. Call this before revealing K_n to the client.
    pub fn new(
        ciphertext: &[u8],
        nonce: &[u8; 12],
        session_id: &[u8],
        signing_key: &[u8],
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ciphertext);
        hasher.update(nonce);
        hasher.update(session_id);
        let ciphertext_hash: [u8; 32] = hasher.finalize().into();

        let mut mac =
            Hmac::<Sha256>::new_from_slice(signing_key).expect("HMAC accepts any key length");
        mac.update(&ciphertext_hash);
        let signature = mac.finalize().into_bytes().to_vec();

        NotaryCommit { ciphertext_hash, signature }
    }

    /// Verify the commitment matches `ciphertext` and was produced with `signing_key`.
    /// Comparisons are constant-time to prevent timing side-channels.
    pub fn verify(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        session_id: &[u8],
        signing_key: &[u8],
    ) -> bool {
        let expected = Self::new(ciphertext, nonce, session_id, signing_key);
        let hash_ok = self
            .ciphertext_hash
            .iter()
            .zip(expected.ciphertext_hash.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0;
        let sig_ok = self.signature.len() == expected.signature.len()
            && self
                .signature
                .iter()
                .zip(expected.signature.iter())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0;
        hash_ok && sig_ok
    }
}

/// Client reconstructs K and decrypts the server's response after the notary
/// commits to the ciphertext and reveals K_n. Standard AES-GCM — no circuit.
pub fn client_decrypt(
    k_c: [u8; 16],
    k_n_revealed: [u8; 16],
    ciphertext: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, aes_gcm::Error> {
    use aes_gcm::{
        aead::{Aead, KeyInit},
        Aes128Gcm, Key, Nonce,
    };
    let k: [u8; 16] = std::array::from_fn(|i| k_c[i] ^ k_n_revealed[i]);
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&k));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
}

// ── helpers ───────────────────────────────────────────────────────────────────

// Bristol AES-non-expanded uses MSB-first bit ordering within each byte.
// Wire 0 = bit 7 (MSB) of byte 0, wire 7 = bit 0 (LSB) of byte 0, etc.

pub(crate) fn bytes_to_bits(bytes: &[u8]) -> Vec<u16> {
    bytes
        .iter()
        .flat_map(|&b| (0..8u8).rev().map(move |i| ((b >> i) & 1) as u16))
        .collect()
}

pub(crate) fn bits_to_bytes_16(bits: Vec<u16>) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, chunk) in bits.chunks(8).enumerate().take(16) {
        for (j, &bit) in chunk.iter().enumerate() {
            out[i] |= (bit as u8) << (7 - j);
        }
    }
    out
}

pub(crate) fn make_nonce_ctr(nonce: [u8; 12], counter: u32) -> [u8; 16] {
    let mut nonce_ctr = [0u8; 16];
    nonce_ctr[..12].copy_from_slice(&nonce);
    nonce_ctr[12..].copy_from_slice(&counter.to_be_bytes());
    nonce_ctr
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // K_N XOR K_C = K (the combined AES key used in reference computations)
    const K_N: [u8; 16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    const K_C: [u8; 16] = [
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    ];
    const K: [u8; 16] = {
        let mut k = [0u8; 16];
        let mut i = 0;
        while i < 16 { k[i] = K_N[i] ^ K_C[i]; i += 1; }
        k
    };
    const NONCE: [u8; 12] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
    ];
    const PLAINTEXT: [u8; 16] = *b"Hello, notary!!!";
    const SESSION_ID: &[u8] = b"session-42";
    const SIGNING_KEY: &[u8] = b"notary-long-term-key";

    // ── circuit correctness ───────────────────────────────────────────────────

    /// Verify Bristol AES circuit matches FIPS 197 Appendix B test vector.
    /// Confirms: MSB-first encoding, plaintext-first / key-second input ordering.
    #[test]
    fn test_circuit_fips197() {
        use fancy_garbling::dummy::Dummy;

        let key = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
            0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        ];
        let pt = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
            0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
        ];
        let expected = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
            0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
        ];

        // Circuit: inputs[0..128] = plaintext, inputs[128..256] = key
        let mut inputs = bytes_to_bits(&pt);
        inputs.extend(bytes_to_bits(&key));

        let circ = aes_circuit();
        let ct = bits_to_bytes_16(Dummy::eval(&circ, &inputs).unwrap());
        assert_eq!(ct, expected);
    }

    // ── helper correctness ────────────────────────────────────────────────────

    #[test]
    fn test_bytes_to_bits_roundtrip() {
        let input = [0xde, 0xad, 0xbe, 0xef, 0x00, 0xff];
        let bits = bytes_to_bits(&input);
        assert_eq!(bits.len(), input.len() * 8);
        let recovered: Vec<u8> = bits
            .chunks(8)
            .map(|chunk| chunk.iter().enumerate()
                .fold(0u8, |b, (i, &bit)| b | ((bit as u8) << (7 - i))))
            .collect();
        assert_eq!(recovered.as_slice(), &input);
    }

    #[test]
    fn test_bits_to_bytes_16_roundtrip() {
        let bits = bytes_to_bits(&PLAINTEXT);
        assert_eq!(bits_to_bytes_16(bits), PLAINTEXT);
    }

    #[test]
    fn test_make_nonce_ctr() {
        let nc = make_nonce_ctr(NONCE, 1);
        assert_eq!(&nc[..12], &NONCE);
        assert_eq!(&nc[12..], &[0u8, 0, 0, 1]);
        assert_eq!(&make_nonce_ctr(NONCE, 0x01020304)[12..], &[0x01u8, 0x02, 0x03, 0x04]);
    }

    // ── decrypt (no circuit) ──────────────────────────────────────────────────

    #[test]
    fn test_client_decrypt_roundtrip() {
        use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Key, Nonce};
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&K));
        let ciphertext = cipher.encrypt(Nonce::from_slice(&NONCE), PLAINTEXT.as_ref()).unwrap();
        let plaintext = client_decrypt(K_C, K_N, &ciphertext, &NONCE).unwrap();
        assert_eq!(plaintext, PLAINTEXT);
    }

    #[test]
    fn test_client_decrypt_wrong_key_fails() {
        use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Key, Nonce};
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&K));
        let ciphertext = cipher.encrypt(Nonce::from_slice(&NONCE), PLAINTEXT.as_ref()).unwrap();
        let mut bad_k_n = K_N;
        bad_k_n[0] ^= 0x01;
        assert!(client_decrypt(K_C, bad_k_n, &ciphertext, &NONCE).is_err());
    }

    // ── commit ────────────────────────────────────────────────────────────────

    #[test]
    fn test_notary_commit_verify() {
        let ct = b"response ciphertext bytes";
        let commit = NotaryCommit::new(ct, &NONCE, SESSION_ID, SIGNING_KEY);
        assert!(commit.verify(ct, &NONCE, SESSION_ID, SIGNING_KEY));
        assert!(!commit.verify(b"tampered ciphertext bytes", &NONCE, SESSION_ID, SIGNING_KEY));
        assert!(!commit.verify(ct, &[0xffu8; 12], SESSION_ID, SIGNING_KEY));
        assert!(!commit.verify(ct, &NONCE, SESSION_ID, b"wrong-key"));
    }

    #[test]
    fn test_notary_commit_deterministic() {
        let ct = b"response ciphertext bytes";
        let c1 = NotaryCommit::new(ct, &NONCE, SESSION_ID, SIGNING_KEY);
        let c2 = NotaryCommit::new(ct, &NONCE, SESSION_ID, SIGNING_KEY);
        assert_eq!(c1.ciphertext_hash, c2.ciphertext_hash);
        assert_eq!(c1.signature, c2.signature);
    }

    // ── 2PC integration ───────────────────────────────────────────────────────

    /// Encrypt one block via the garbled circuit and verify against AES-ECB + XOR.
    #[test]
    fn test_2pc_encrypt_block_integration() {
        use aes::cipher::{BlockEncrypt, KeyInit};
        use aes::Aes128;

        let nonce_ctr = make_nonce_ctr(NONCE, 1);

        // Reference: AES_ECB(K, nonce_ctr) XOR plaintext
        let expected: [u8; 16] = {
            let mut block = aes::Block::clone_from_slice(&nonce_ctr);
            Aes128::new(aes::Block::from_slice(&K)).encrypt_block(&mut block);
            std::array::from_fn(|i| PLAINTEXT[i] ^ block[i])
        };

        let ((), ct) = swanky_channel::local::local_channel_pair(
            |ch| notary_encrypt_block(ch, K_N, nonce_ctr),
            |ch| client_encrypt_block(ch, K_C, PLAINTEXT, nonce_ctr),
        ).unwrap();

        assert_eq!(ct, expected,
            "2PC ciphertext must equal AES-CTR(K_n XOR K_c, nonce_ctr, plaintext)");
    }

    /// Encrypt 3 blocks via 2PC and verify each block against the reference.
    #[test]
    fn test_2pc_encrypt_multiblock() {
        use aes::cipher::{BlockEncrypt, KeyInit};
        use aes::Aes128;

        let plaintext = b"Block-0 data!!!!Block-1 data!!!!Block-2 data!!!!";
        assert_eq!(plaintext.len(), 48);

        let mut expected = Vec::new();
        for (ctr, chunk) in plaintext.chunks(16).enumerate() {
            let nonce_ctr = make_nonce_ctr(NONCE, (ctr + 1) as u32);
            let mut block = aes::Block::clone_from_slice(&nonce_ctr);
            Aes128::new(aes::Block::from_slice(&K)).encrypt_block(&mut block);
            for (i, &pt) in chunk.iter().enumerate() {
                expected.push(pt ^ block[i]);
            }
        }

        let block_count = plaintext.chunks(16).count();
        let ((), ct) = swanky_channel::local::local_channel_pair(
            |ch| notary_encrypt(ch, K_N, NONCE, block_count),
            |ch| client_encrypt(ch, K_C, plaintext, NONCE),
        ).unwrap();

        assert_eq!(ct, expected);
    }

    // ── 2PC AES-GCM (full split-key AEAD, not just CTR) ───────────────────────

    /// The defining test: split-key 2PC produces a GCM ciphertext byte-identical
    /// to what the `aes-gcm` crate produces with the full key K.
    /// Validates: AES_K(0^128) for H, AES_K(J0) for S, CTR keystream, GHASH,
    /// length-block, tag XOR.
    #[test]
    fn test_2pc_gcm_matches_aes_gcm_crate() {
        use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Key, Nonce};

        // 32 bytes = 2 blocks (the smallest interesting size: exercises both
        // ciphertext-block GHASH muls and the length-block GHASH mul).
        let plaintext: [u8; 32] = *b"32-byte aligned plaintext data!!";

        // Reference: standard AES-128-GCM with the full key K = K_N XOR K_C
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&K));
        let reference = cipher
            .encrypt(Nonce::from_slice(&NONCE), plaintext.as_ref())
            .unwrap();
        // reference = ciphertext (32 B) || tag (16 B)
        let ref_ct = &reference[..plaintext.len()];
        let ref_tag: [u8; 16] = reference[plaintext.len()..].try_into().unwrap();

        // 2PC: neither party knows the full key
        let ((), (ct_2pc, tag_2pc)) = swanky_channel::local::local_channel_pair(
            |ch| notary_encrypt_gcm(ch, K_N, NONCE, b"", plaintext.len()),
            |ch| client_encrypt_gcm(ch, K_C, &plaintext, b"", NONCE),
        )
        .unwrap();

        assert_eq!(ct_2pc, ref_ct, "2PC ciphertext must match aes-gcm crate");
        assert_eq!(tag_2pc, ref_tag, "2PC tag must match aes-gcm crate");

        // The 2PC output is a real GCM ciphertext: the standard decryptor accepts it.
        let mut combined = ct_2pc.clone();
        combined.extend_from_slice(&tag_2pc);
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&NONCE), combined.as_slice())
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// TLS 1.3 record encrypted via split-key 2PC AES-GCM. The output is a
    /// valid TLS record ciphertext that any RFC 8446 implementation would
    /// accept and decrypt with the full key K.
    #[test]
    fn test_tls13_record_via_2pc_gcm() {
        use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Key, Nonce};

        // TLS 1.3 nonce = static_iv XOR (0^32 || seq_num) — RFC 8446 §5.3
        let static_iv: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce,
            0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let seq_num: u64 = 42;
        let tls_nonce: [u8; 12] = {
            let mut n = static_iv;
            let seq_bytes = seq_num.to_be_bytes();
            for i in 0..8 {
                n[4 + i] ^= seq_bytes[i];
            }
            n
        };

        // Application data padded to a 16-byte multiple
        let app_data: [u8; 48] = *b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n\0\0\0\0\0\0\0\0\0\0\0";

        // 2PC encrypt: notary holds K_N, client holds K_C, neither learns K
        let ((), (ct, tag)) = swanky_channel::local::local_channel_pair(
            |ch| notary_encrypt_gcm(ch, K_N, tls_nonce, b"", app_data.len()),
            |ch| client_encrypt_gcm(ch, K_C, &app_data, b"", tls_nonce),
        )
        .unwrap();

        // A TLS implementation receiving this record (with the full key K) decrypts it.
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&K));
        let mut record = ct.clone();
        record.extend_from_slice(&tag);
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&tls_nonce), record.as_slice())
            .unwrap();
        assert_eq!(decrypted, app_data);

        // The notary commits to the response ciphertext (different K_N from the
        // request would be used in practice; here we reuse for test brevity).
        let commit = NotaryCommit::new(&record, &tls_nonce, b"tls-session-1", SIGNING_KEY);
        assert!(commit.verify(&record, &tls_nonce, b"tls-session-1", SIGNING_KEY));
    }

    /// AAD + partial-block: a 23-byte plaintext (1 full block + 7 partial)
    /// with 17 bytes of AAD (1 full block + 1 partial).
    #[test]
    fn test_2pc_gcm_partial_and_aad() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes128Gcm, Key, Nonce};

        let plaintext = b"23-byte unaligned input"; // 23 bytes
        assert_eq!(plaintext.len(), 23);
        let aad = b"17-byte AAD here!"; // 17 bytes
        assert_eq!(aad.len(), 17);

        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&K));
        let reference = cipher
            .encrypt(
                Nonce::from_slice(&NONCE),
                Payload { msg: plaintext, aad },
            )
            .unwrap();
        let ref_ct = &reference[..plaintext.len()];
        let ref_tag: [u8; 16] = reference[plaintext.len()..].try_into().unwrap();

        let ((), (ct_2pc, tag_2pc)) = swanky_channel::local::local_channel_pair(
            |ch| notary_encrypt_gcm(ch, K_N, NONCE, aad, plaintext.len()),
            |ch| client_encrypt_gcm(ch, K_C, plaintext, aad, NONCE),
        )
        .unwrap();

        assert_eq!(ct_2pc, ref_ct);
        assert_eq!(tag_2pc, ref_tag);

        // aes-gcm crate accepts the 2PC output as a real GCM ciphertext
        let mut combined = ct_2pc.clone();
        combined.extend_from_slice(&tag_2pc);
        let decrypted = cipher
            .decrypt(Nonce::from_slice(&NONCE), Payload { msg: &combined, aad })
            .unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// AAD only (no plaintext) — degenerate but legal in GCM.
    #[test]
    fn test_2pc_gcm_aad_only() {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        use aes_gcm::{Aes128Gcm, Key, Nonce};

        let aad = b"only authenticated, not encrypted";

        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&K));
        let reference = cipher
            .encrypt(Nonce::from_slice(&NONCE), Payload { msg: &[], aad })
            .unwrap();
        // Empty plaintext → reference is just the 16-byte tag
        assert_eq!(reference.len(), 16);
        let ref_tag: [u8; 16] = reference.as_slice().try_into().unwrap();

        let ((), (ct_2pc, tag_2pc)) = swanky_channel::local::local_channel_pair(
            |ch| notary_encrypt_gcm(ch, K_N, NONCE, aad, 0),
            |ch| client_encrypt_gcm(ch, K_C, &[], aad, NONCE),
        )
        .unwrap();

        assert!(ct_2pc.is_empty());
        assert_eq!(tag_2pc, ref_tag);
    }
}
