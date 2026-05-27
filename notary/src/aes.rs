//! Split-key AES-GCM via two-party garbled circuit.
//!
//! Notary  = Garbler   — holds K_n
//! Client  = Evaluator — holds K_c
//! K = K_n XOR K_c (never assembled in the clear)

use fancy_garbling::{
    Fancy, FancyBinary, WireMod2,
    circuit::{BinaryCircuit, CircuitExecutor},
};
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

pub fn notary_encrypt_block(
    channel: &mut Channel,
    k_n: [u8; 16],
    nonce_ctr: [u8; 16],
) -> SwankyResult<()> {
    let rng = SwankyRng::new();
    let circ = aes_circuit();
    let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(channel, rng)?;
    let mod2 = vec![2u16; 128];

    let nonce_bits = gb.encode_many(&bytes_to_bits(&nonce_ctr), &mod2, channel)?;
    let k_n_bits = gb.encode_many(&bytes_to_bits(&k_n), &mod2, channel)?;
    let k_c_bits = gb.receive_many(&mod2, channel)?;
    let pt_bits = gb.receive_many(&mod2, channel)?;

    let mut k_bits = Vec::with_capacity(128);
    for i in 0..128 {
        k_bits.push(gb.xor(&k_n_bits[i], &k_c_bits[i]));
    }

    let mut circuit_inputs = nonce_bits;
    circuit_inputs.extend_from_slice(&k_bits);
    let keystream = circ.execute(&mut gb, &circuit_inputs, channel)?;

    let mut ct_bits = Vec::with_capacity(128);
    for i in 0..128 {
        ct_bits.push(gb.xor(&pt_bits[i], &keystream[i]));
    }

    gb.outputs(&ct_bits, channel)?;
    Ok(())
}

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

pub fn client_encrypt_block(
    channel: &mut Channel,
    k_c: [u8; 16],
    plaintext: [u8; 16],
    _nonce_ctr: [u8; 16],
) -> SwankyResult<[u8; 16]> {
    let rng = SwankyRng::new();
    let mut ev = Evaluator::<SwankyRng, OtReceiver, WireMod2>::new(channel, rng)?;
    let mod2 = vec![2u16; 128];

    let nonce_bits = ev.receive_many(&mod2, channel)?;
    let k_n_bits = ev.receive_many(&mod2, channel)?;
    let k_c_bits = ev.encode_many(&bytes_to_bits(&k_c), &mod2, channel)?;
    let pt_bits = ev.encode_many(&bytes_to_bits(&plaintext), &mod2, channel)?;

    let mut k_bits = Vec::with_capacity(128);
    for i in 0..128 {
        k_bits.push(ev.xor(&k_n_bits[i], &k_c_bits[i]));
    }

    let circ = aes_circuit();
    let mut circuit_inputs = nonce_bits;
    circuit_inputs.extend_from_slice(&k_bits);
    let keystream = circ.execute(&mut ev, &circuit_inputs, channel)?;

    let mut ct_bits = Vec::with_capacity(128);
    for i in 0..128 {
        ct_bits.push(ev.xor(&pt_bits[i], &keystream[i]));
    }

    let ct_vals = ev.outputs(&ct_bits, channel)?.expect("evaluator receives output");
    Ok(bits_to_bytes_16(ct_vals))
}

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

// ── GCM helpers ───────────────────────────────────────────────────────────────

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
    let mut inputs = plaintext.to_vec();
    inputs.extend_from_slice(key);
    circ.execute(f, &inputs, channel)
}

fn xor_blocks<F: FancyBinary>(f: &mut F, a: &[F::Item], b: &[F::Item]) -> Vec<F::Item> {
    let mut out = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        out.push(f.xor(&a[i], &b[i]));
    }
    out
}

fn ghash_mul<F: FancyBinary>(
    f: &mut F,
    channel: &mut Channel,
    x: &[F::Item],
    y: &[F::Item],
) -> SwankyResult<Vec<F::Item>>
where
    F::Item: Clone,
{
    let zero = f.constant(0, 2, channel)?;
    let mut z: Vec<F::Item> = (0..128).map(|_| zero.clone()).collect();
    let mut v: Vec<F::Item> = y.to_vec();

    for i in 0..128 {
        for j in 0..128 {
            let xv = f.and(&x[i], &v[j], channel)?;
            let new_zj = f.xor(&z[j], &xv);
            z[j] = new_zj;
        }
        let lsb = v[127].clone();
        let mut new_v = Vec::with_capacity(128);
        new_v.push(zero.clone());
        for k in 0..127 {
            new_v.push(v[k].clone());
        }
        v = new_v;
        for &r in &[0usize, 1, 2, 7] {
            let new_vr = f.xor(&v[r], &lsb);
            v[r] = new_vr;
        }
    }
    Ok(z)
}

// ── split-key AES-GCM (notary / client) ───────────────────────────────────────

pub fn notary_encrypt_gcm(
    channel: &mut Channel,
    k_n: [u8; 16],
    nonce: [u8; 12],
    aad: &[u8],
    plaintext_len: usize,
) -> SwankyResult<()> {
    let rng = SwankyRng::new();
    let circ = aes_circuit();
    let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(channel, rng)?;
    let mod2 = vec![2u16; 128];

    let n_aad_blocks = aad.len().div_ceil(16);
    let n_pt_blocks = plaintext_len.div_ceil(16);
    let pt_last_bytes = if plaintext_len == 0 { 0 } else { ((plaintext_len - 1) % 16) + 1 };

    let k_n_bits = gb.encode_many(&bytes_to_bits(&k_n), &mod2, channel)?;
    let k_c_bits = gb.receive_many(&mod2, channel)?;
    let k_bits = xor_blocks(&mut gb, &k_n_bits, &k_c_bits);

    let zero_block_bits = gb.encode_many(&bytes_to_bits(&[0u8; 16]), &mod2, channel)?;
    let h_bits = aes_block(&mut gb, channel, &circ, &zero_block_bits, &k_bits)?;

    let j0 = make_nonce_ctr(nonce, 1);
    let j0_bits = gb.encode_many(&bytes_to_bits(&j0), &mod2, channel)?;
    let s_bits = aes_block(&mut gb, channel, &circ, &j0_bits, &k_bits)?;

    let zero = gb.constant(0, 2, channel)?;
    let mut x_acc: Vec<WireMod2> = (0..128).map(|_| zero.clone()).collect();

    for blk in 0..n_aad_blocks {
        let mut aad_block = [0u8; 16];
        let start = blk * 16;
        let end = ((blk + 1) * 16).min(aad.len());
        aad_block[..end - start].copy_from_slice(&aad[start..end]);
        let aad_bits = gb.encode_many(&bytes_to_bits(&aad_block), &mod2, channel)?;
        let xored = xor_blocks(&mut gb, &x_acc, &aad_bits);
        x_acc = ghash_mul(&mut gb, channel, &xored, &h_bits)?;
    }

    let mut ct_blocks: Vec<(Vec<WireMod2>, usize)> = Vec::with_capacity(n_pt_blocks);
    for blk in 0..n_pt_blocks {
        let valid_bytes = if blk == n_pt_blocks - 1 { pt_last_bytes } else { 16 };
        let ctr_block = make_nonce_ctr(nonce, (blk as u32) + 2);
        let ctr_bits = gb.encode_many(&bytes_to_bits(&ctr_block), &mod2, channel)?;
        let keystream = aes_block(&mut gb, channel, &circ, &ctr_bits, &k_bits)?;
        let pt_bits = gb.receive_many(&mod2, channel)?;
        let ct_bits = xor_blocks(&mut gb, &pt_bits, &keystream);

        let ct_for_ghash: Vec<WireMod2> = if valid_bytes < 16 {
            (0..128)
                .map(|i| if i / 8 < valid_bytes { ct_bits[i].clone() } else { zero.clone() })
                .collect()
        } else {
            ct_bits.clone()
        };
        let xored = xor_blocks(&mut gb, &x_acc, &ct_for_ghash);
        x_acc = ghash_mul(&mut gb, channel, &xored, &h_bits)?;
        ct_blocks.push((ct_bits, valid_bytes));
    }

    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..16].copy_from_slice(&((plaintext_len as u64) * 8).to_be_bytes());
    let len_bits = gb.encode_many(&bytes_to_bits(&len_block), &mod2, channel)?;
    let xored = xor_blocks(&mut gb, &x_acc, &len_bits);
    let x_final = ghash_mul(&mut gb, channel, &xored, &h_bits)?;

    let tag_bits = xor_blocks(&mut gb, &x_final, &s_bits);

    let mut all_outputs: Vec<WireMod2> = Vec::new();
    for (ct_bits, valid_bytes) in &ct_blocks {
        all_outputs.extend_from_slice(&ct_bits[..valid_bytes * 8]);
    }
    all_outputs.extend(tag_bits);
    gb.outputs(&all_outputs, channel)?;
    Ok(())
}

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

    for _ in 0..n_aad_blocks {
        let aad_bits = ev.receive_many(&mod2, channel)?;
        let xored = xor_blocks(&mut ev, &x_acc, &aad_bits);
        x_acc = ghash_mul(&mut ev, channel, &xored, &h_bits)?;
    }

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
                .map(|i| if i / 8 < valid_bytes { ct_bits[i].clone() } else { zero.clone() })
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

    let mut all_outputs: Vec<WireMod2> = Vec::new();
    for (ct_bits, valid_bytes) in &ct_blocks {
        all_outputs.extend_from_slice(&ct_bits[..valid_bytes * 8]);
    }
    all_outputs.extend(tag_bits);

    let vals = ev.outputs(&all_outputs, channel)?.expect("evaluator receives output");

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

// ── split-key AES-GCM DECRYPT (notary / client) ───────────────────────────────

/// Notary side of split-key AES-128-GCM **decrypt**.
///
/// Takes only the byte-lengths of AAD and ciphertext; the client provides the
/// actual bytes via OT inside the circuit. The notary never sees the
/// ciphertext or AAD content — only their lengths (needed for GHASH structure
/// and counter blocks).
pub fn notary_decrypt_gcm(
    channel: &mut Channel,
    k_n: [u8; 16],
    nonce: [u8; 12],
    aad_len: usize,
    ciphertext_len: usize,
) -> SwankyResult<()> {
    let rng = SwankyRng::new();
    let circ = aes_circuit();
    let mut gb = Garbler::<SwankyRng, OtSender, WireMod2>::new(channel, rng)?;
    let mod2 = vec![2u16; 128];

    let n_aad_blocks = aad_len.div_ceil(16);
    let n_ct_blocks = ciphertext_len.div_ceil(16);
    let ct_last_bytes = if ciphertext_len == 0 { 0 } else { ((ciphertext_len - 1) % 16) + 1 };

    // K = K_N XOR K_C
    let k_n_bits = gb.encode_many(&bytes_to_bits(&k_n), &mod2, channel)?;
    let k_c_bits = gb.receive_many(&mod2, channel)?;
    let k_bits = xor_blocks(&mut gb, &k_n_bits, &k_c_bits);

    // H = AES_K(0^128); S = AES_K(J0)
    let zero_block_bits = gb.encode_many(&bytes_to_bits(&[0u8; 16]), &mod2, channel)?;
    let h_bits = aes_block(&mut gb, channel, &circ, &zero_block_bits, &k_bits)?;

    let j0 = make_nonce_ctr(nonce, 1);
    let j0_bits = gb.encode_many(&bytes_to_bits(&j0), &mod2, channel)?;
    let s_bits = aes_block(&mut gb, channel, &circ, &j0_bits, &k_bits)?;

    let zero = gb.constant(0, 2, channel)?;
    let mut x_acc: Vec<WireMod2> = (0..128).map(|_| zero.clone()).collect();

    // AAD blocks — client contributes the bytes; notary contributes zeros.
    for _ in 0..n_aad_blocks {
        let aad_n_bits = gb.encode_many(&bytes_to_bits(&[0u8; 16]), &mod2, channel)?;
        let aad_c_bits = gb.receive_many(&mod2, channel)?;
        let aad_block = xor_blocks(&mut gb, &aad_n_bits, &aad_c_bits);
        let xored = xor_blocks(&mut gb, &x_acc, &aad_block);
        x_acc = ghash_mul(&mut gb, channel, &xored, &h_bits)?;
    }

    // Ciphertext blocks
    let mut pt_blocks: Vec<(Vec<WireMod2>, usize)> = Vec::with_capacity(n_ct_blocks);
    for blk in 0..n_ct_blocks {
        let valid_bytes = if blk == n_ct_blocks - 1 { ct_last_bytes } else { 16 };

        // CTR keystream block
        let ctr_block = make_nonce_ctr(nonce, (blk as u32) + 2);
        let ctr_bits = gb.encode_many(&bytes_to_bits(&ctr_block), &mod2, channel)?;
        let keystream = aes_block(&mut gb, channel, &circ, &ctr_bits, &k_bits)?;

        // Client contributes ciphertext bytes; notary contributes zeros.
        let ct_n_bits = gb.encode_many(&bytes_to_bits(&[0u8; 16]), &mod2, channel)?;
        let ct_c_bits = gb.receive_many(&mod2, channel)?;
        let ct_bits = xor_blocks(&mut gb, &ct_n_bits, &ct_c_bits);

        // plaintext = ciphertext XOR keystream (free)
        let pt_bits = xor_blocks(&mut gb, &ct_bits, &keystream);

        // GHASH includes ciphertext, zero-padded beyond valid_bytes
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

        pt_blocks.push((pt_bits, valid_bytes));
    }

    // GCM length block: aad_bits || ciphertext_bits, both u64 BE
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad_len as u64) * 8).to_be_bytes());
    len_block[8..16].copy_from_slice(&((ciphertext_len as u64) * 8).to_be_bytes());
    let len_bits = gb.encode_many(&bytes_to_bits(&len_block), &mod2, channel)?;
    let xored = xor_blocks(&mut gb, &x_acc, &len_bits);
    let x_final = ghash_mul(&mut gb, channel, &xored, &h_bits)?;

    // Expected tag = GHASH XOR S
    let expected_tag_bits = xor_blocks(&mut gb, &x_final, &s_bits);

    // Output plaintext + expected_tag to the evaluator; the evaluator compares
    // expected_tag with the received tag in constant time outside the circuit.
    let mut all_outputs: Vec<WireMod2> = Vec::new();
    for (pt_bits, valid_bytes) in &pt_blocks {
        all_outputs.extend_from_slice(&pt_bits[..valid_bytes * 8]);
    }
    all_outputs.extend(expected_tag_bits);
    gb.outputs(&all_outputs, channel)?;
    Ok(())
}

/// Client side of split-key AES-128-GCM **decrypt**.
///
/// On success returns the plaintext. On tag mismatch returns
/// `swanky_error::ErrorKind::OtherError` ("AES-GCM authentication failed").
pub fn client_decrypt_gcm_2pc(
    channel: &mut Channel,
    k_c: [u8; 16],
    ciphertext: &[u8],
    aad: &[u8],
    received_tag: [u8; 16],
    _nonce: [u8; 12],
) -> SwankyResult<Vec<u8>> {
    let pt_len = ciphertext.len();
    let n_aad_blocks = aad.len().div_ceil(16);
    let n_ct_blocks = pt_len.div_ceil(16);
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

    // AAD blocks — client encodes aad bytes (zero-padded)
    for blk in 0..n_aad_blocks {
        let mut aad_block = [0u8; 16];
        let start = blk * 16;
        let end = ((blk + 1) * 16).min(aad.len());
        aad_block[..end - start].copy_from_slice(&aad[start..end]);
        let aad_n_bits = ev.receive_many(&mod2, channel)?;
        let aad_c_bits = ev.encode_many(&bytes_to_bits(&aad_block), &mod2, channel)?;
        let aad_combined = xor_blocks(&mut ev, &aad_n_bits, &aad_c_bits);
        let xored = xor_blocks(&mut ev, &x_acc, &aad_combined);
        x_acc = ghash_mul(&mut ev, channel, &xored, &h_bits)?;
    }

    let mut pt_blocks: Vec<(Vec<WireMod2>, usize)> = Vec::with_capacity(n_ct_blocks);
    for blk in 0..n_ct_blocks {
        let valid_bytes = if blk == n_ct_blocks - 1 { pt_last_bytes } else { 16 };

        let ctr_bits = ev.receive_many(&mod2, channel)?;
        let keystream = aes_block(&mut ev, channel, &circ, &ctr_bits, &k_bits)?;

        // Client encodes the ciphertext bytes (zero-padded if partial)
        let mut ct_block = [0u8; 16];
        let start = blk * 16;
        let end = ((blk + 1) * 16).min(pt_len);
        ct_block[..end - start].copy_from_slice(&ciphertext[start..end]);
        let ct_n_bits = ev.receive_many(&mod2, channel)?;
        let ct_c_bits = ev.encode_many(&bytes_to_bits(&ct_block), &mod2, channel)?;
        let ct_bits = xor_blocks(&mut ev, &ct_n_bits, &ct_c_bits);

        let pt_bits = xor_blocks(&mut ev, &ct_bits, &keystream);

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

        pt_blocks.push((pt_bits, valid_bytes));
    }

    let len_bits = ev.receive_many(&mod2, channel)?;
    let xored = xor_blocks(&mut ev, &x_acc, &len_bits);
    let x_final = ghash_mul(&mut ev, channel, &xored, &h_bits)?;
    let expected_tag_bits = xor_blocks(&mut ev, &x_final, &s_bits);

    let mut all_outputs: Vec<WireMod2> = Vec::new();
    for (pt_bits, valid_bytes) in &pt_blocks {
        all_outputs.extend_from_slice(&pt_bits[..valid_bytes * 8]);
    }
    all_outputs.extend(expected_tag_bits);

    let vals = ev
        .outputs(&all_outputs, channel)?
        .expect("evaluator receives output");

    let mut plaintext = Vec::with_capacity(pt_len);
    let mut cursor = 0;
    for (_, valid_bytes) in &pt_blocks {
        let chunk: Vec<u16> = vals[cursor..cursor + valid_bytes * 8].to_vec();
        plaintext.extend_from_slice(&bits_to_bytes_partial(chunk, *valid_bytes));
        cursor += valid_bytes * 8;
    }
    let tag_vals: Vec<u16> = vals[cursor..].to_vec();
    let expected_tag = bits_to_bytes_16(tag_vals);

    // Constant-time tag comparison
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= expected_tag[i] ^ received_tag[i];
    }
    if diff != 0 {
        swanky_error::bail!(
            swanky_error::ErrorKind::OtherError,
            "AES-GCM authentication failed"
        );
    }

    Ok(plaintext)
}

// ── Commit-before-reveal + decrypt ────────────────────────────────────────────

pub struct NotaryCommit {
    pub ciphertext_hash: [u8; 32],
    pub signature: Vec<u8>,
}

impl NotaryCommit {
    pub fn new(
        ciphertext: &[u8],
        nonce: &[u8; 12],
        session_id: &[u8],
        signing_key: &[u8],
    ) -> Self {
        use sha2::{Digest, Sha256};
        use hmac::{Hmac, Mac};

        let mut hasher = Sha256::new();
        hasher.update(ciphertext);
        hasher.update(nonce);
        hasher.update(session_id);
        let ciphertext_hash: [u8; 32] = hasher.finalize().into();

        let mut mac = Hmac::<Sha256>::new_from_slice(signing_key).unwrap();
        mac.update(&ciphertext_hash);
        let signature = mac.finalize().into_bytes().to_vec();

        NotaryCommit { ciphertext_hash, signature }
    }

    pub fn verify(
        &self,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        session_id: &[u8],
        signing_key: &[u8],
    ) -> bool {
        let expected = Self::new(ciphertext, nonce, session_id, signing_key);
        self.ciphertext_hash == expected.ciphertext_hash && self.signature == expected.signature
    }
}

pub fn client_decrypt(
    k_c: [u8; 16],
    k_n_revealed: [u8; 16],
    ciphertext: &[u8],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, aes_gcm::Error> {
    use aes_gcm::{aead::{Aead, KeyInit}, Aes128Gcm, Key, Nonce};
    let k: [u8; 16] = std::array::from_fn(|i| k_c[i] ^ k_n_revealed[i]);
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&k));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
}

// ── helpers ───────────────────────────────────────────────────────────────────

pub(crate) fn bytes_to_bits(bytes: &[u8]) -> Vec<u16> {
    bytes.iter().flat_map(|&b| (0..8u8).rev().map(move |i| ((b >> i) & 1) as u16)).collect()
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

/// Decode a variable-length bit vector (MSB-first per byte) into `n_bytes` bytes.
/// Used for the partial last ciphertext block in `client_encrypt_gcm`.
pub(crate) fn bits_to_bytes_partial(bits: Vec<u16>, n_bytes: usize) -> Vec<u8> {
    let mut out = vec![0u8; n_bytes];
    for (i, chunk) in bits.chunks(8).enumerate().take(n_bytes) {
        for (j, &bit) in chunk.iter().enumerate() {
            out[i] |= (bit as u8) << (7 - j);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use swanky_channel::local::local_channel_pair;

    /// Round-trip: 2PC encrypt → 2PC decrypt with same split key recovers plaintext.
    #[test]
    fn decrypt_2pc_round_trip() {
        let k_n = [0x2bu8; 16];
        let k_c = [0x60u8; 16];
        let nonce = [0xcau8; 12];
        let aad = b"some-aad-bytes";
        let plaintext = b"23-byte unaligned input"; // 23 bytes — partial last block

        // First encrypt via 2PC
        let ((), (ct, tag)) = local_channel_pair(
            |ch| notary_encrypt_gcm(ch, k_n, nonce, aad, plaintext.len()),
            |ch| client_encrypt_gcm(ch, k_c, plaintext, aad, nonce),
        )
        .unwrap();

        // Decrypt via 2PC — should return the original plaintext
        let ((), recovered) = local_channel_pair(
            |ch| notary_decrypt_gcm(ch, k_n, nonce, aad.len(), ct.len()),
            |ch| client_decrypt_gcm_2pc(ch, k_c, &ct, aad, tag, nonce),
        )
        .unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// 2PC decrypt rejects a forged ciphertext (tag verification fires inside the
    /// client side after the circuit returns the expected tag).
    #[test]
    fn decrypt_2pc_rejects_tampered_ciphertext() {
        let k_n = [0x11u8; 16];
        let k_c = [0x22u8; 16];
        let nonce = [0x33u8; 12];
        let plaintext = b"some plaintext data";

        let ((), (mut ct, tag)) = local_channel_pair(
            |ch| notary_encrypt_gcm(ch, k_n, nonce, b"", plaintext.len()),
            |ch| client_encrypt_gcm(ch, k_c, plaintext, b"", nonce),
        )
        .unwrap();

        // Flip one byte of the ciphertext
        ct[0] ^= 0x80;

        let result = local_channel_pair(
            |ch| notary_decrypt_gcm(ch, k_n, nonce, 0, ct.len()),
            |ch| client_decrypt_gcm_2pc(ch, k_c, &ct, b"", tag, nonce),
        );
        // Local channel pair returns an error if either side errored
        assert!(result.is_err(), "tampered ciphertext must fail tag check");
    }

    /// 2PC decrypt output matches `aes-gcm` crate decrypt with `K = K_N XOR K_C`.
    #[test]
    fn decrypt_2pc_matches_aes_gcm_crate() {
        use aes_gcm::{
            aead::{Aead, KeyInit, Payload},
            Aes128Gcm, Key, Nonce,
        };
        let k_n = [0x2bu8; 16];
        let k_c = [0x60u8; 16];
        let k: [u8; 16] = std::array::from_fn(|i| k_n[i] ^ k_c[i]);
        let nonce = [0xcau8; 12];
        let plaintext = b"hello, 2PC AES-GCM decrypt!";
        let aad = b"record-header";

        // Reference encrypt with the aes-gcm crate
        let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&k));
        let reference = cipher
            .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad })
            .unwrap();
        let ct = &reference[..plaintext.len()];
        let tag: [u8; 16] = reference[plaintext.len()..].try_into().unwrap();

        // Decrypt via 2PC
        let ((), recovered) = local_channel_pair(
            |ch| notary_decrypt_gcm(ch, k_n, nonce, aad.len(), ct.len()),
            |ch| client_decrypt_gcm_2pc(ch, k_c, ct, aad, tag, nonce),
        )
        .unwrap();

        assert_eq!(recovered, plaintext);
    }
}
