//! Split-key AES-GCM via two-party garbled circuit.
//!
//! Notary  = Garbler   — holds K_n
//! Client  = Evaluator — holds K_c
//! K = K_n XOR K_c (never assembled in the clear)
//!
//! **Garbling split:** each AES block runs in its own WRK17 session; the full GHASH
//! chain for a record runs in one unrolled WRK17 session. OT extension is reused via
//! [`crate::garble::Wrk17NotarySession`] / [`crate::garble::Wrk17ClientSession`].

use fancy_garbling::{
    Fancy, FancyBinary, WireMod2,
    circuit::{BinaryCircuit, CircuitExecutor},
};
use swanky_channel::Channel;
use swanky_error::Result as SwankyResult;
use swanky_ot_chou_orlandi::{Receiver as OtReceiver, Sender as OtSender};
use swanky_rng::SwankyRng;
use swanky_twopac::semihonest::{Evaluator, Garbler};

use crate::garble::{Wrk17ClientSession, Wrk17NotarySession};
use crate::ghash::{
    client_ghash_chain_wrk17, ct_eq16, notary_ghash_chain_wrk17, xor_bytes16, zero_pad_block,
};

// ── circuit ───────────────────────────────────────────────────────────────────

fn aes_circuit() -> BinaryCircuit {
    BinaryCircuit::parse(std::io::Cursor::new(include_bytes!(
        "../circuits/AES-non-expanded.txt"
    )))
    .expect("bundled AES Bristol circuit is valid")
}

fn aes_wrk17_circuit() -> crate::garble::SplitSharedInputMaskCircuit {
    crate::garble::SplitSharedInputMaskCircuit::new(
        aes_circuit(),
        crate::garble::AES_SHARED_INPUTS,
        crate::garble::AES_OUTPUT_BITS,
    )
}

/// WRK17 AES-128 block: returns the notary's XOR-share of the output (mask `m_n`).
fn notary_aes_block_wrk17(
    channel: &mut Channel,
    block_n: [u8; 16],
    key_n: [u8; 16],
    session: &mut Wrk17NotarySession,
) -> SwankyResult<[u8; 16]> {
    let circ = aes_wrk17_circuit();
    let mut gb_bits = bytes_to_bits(&block_n);
    gb_bits.extend(bytes_to_bits(&key_n));
    let mask = crate::garble::wrk17_notary_masked_run(channel, &circ, &gb_bits, session)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&mask);
    Ok(out)
}

/// WRK17 AES-128 block: returns the client's XOR-share of the masked output.
fn client_aes_block_wrk17(
    channel: &mut Channel,
    block_c: [u8; 16],
    key_c: [u8; 16],
    session: &mut Wrk17ClientSession,
) -> SwankyResult<[u8; 16]> {
    let circ = aes_wrk17_circuit();
    let mut ev_bits = bytes_to_bits(&block_c);
    ev_bits.extend(bytes_to_bits(&key_c));
    let share = crate::garble::wrk17_client_masked_run(channel, &circ, &ev_bits, session)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&share);
    Ok(out)
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

    let ct_vals = ev
        .outputs(&ct_bits, channel)?
        .expect("evaluator receives output");
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

// ── split-key AES-GCM (notary / client) ───────────────────────────────────────

pub fn notary_encrypt_gcm(
    channel: &mut Channel,
    k_n: [u8; 16],
    nonce: [u8; 12],
    aad: &[u8],
    plaintext_len: usize,
    session: &mut Wrk17NotarySession,
) -> SwankyResult<()> {
    let n_aad_blocks = aad.len().div_ceil(16);
    let n_pt_blocks = plaintext_len.div_ceil(16);
    let pt_last_bytes = if plaintext_len == 0 {
        0
    } else {
        ((plaintext_len - 1) % 16) + 1
    };

    let h_n = notary_aes_block_wrk17(channel, [0u8; 16], k_n, session)?;
    let j0 = make_nonce_ctr(nonce, 1);
    let s_n = notary_aes_block_wrk17(channel, j0, k_n, session)?;

    let mut ghash_blocks_n = Vec::with_capacity(n_aad_blocks + n_pt_blocks + 1);

    for blk in 0..n_aad_blocks {
        let mut aad_block = [0u8; 16];
        let start = blk * 16;
        let end = ((blk + 1) * 16).min(aad.len());
        aad_block[..end - start].copy_from_slice(&aad[start..end]);
        ghash_blocks_n.push(aad_block);
    }

    for blk in 0..n_pt_blocks {
        let valid_bytes = if blk == n_pt_blocks - 1 {
            pt_last_bytes
        } else {
            16
        };
        let ctr_block = make_nonce_ctr(nonce, (blk as u32) + 2);
        let ks_n = notary_aes_block_wrk17(channel, ctr_block, k_n, session)?;
        channel.write(&ks_n)?;
        ghash_blocks_n.push(zero_pad_block(ks_n, valid_bytes));
    }

    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..16].copy_from_slice(&((plaintext_len as u64) * 8).to_be_bytes());
    ghash_blocks_n.push(len_block);

    let x_acc_n = notary_ghash_chain_wrk17(channel, &ghash_blocks_n, h_n, session)?;
    let tag_n = xor_bytes16(x_acc_n, s_n);
    channel.write(&tag_n)?;
    Ok(())
}

pub fn client_encrypt_gcm(
    channel: &mut Channel,
    k_c: [u8; 16],
    plaintext: &[u8],
    aad: &[u8],
    _nonce: [u8; 12],
    session: &mut Wrk17ClientSession,
) -> SwankyResult<(Vec<u8>, [u8; 16])> {
    let pt_len = plaintext.len();
    let n_aad_blocks = aad.len().div_ceil(16);
    let n_pt_blocks = pt_len.div_ceil(16);
    let pt_last_bytes = if pt_len == 0 {
        0
    } else {
        ((pt_len - 1) % 16) + 1
    };

    let h_c = client_aes_block_wrk17(channel, [0u8; 16], k_c, session)?;
    let s_c = client_aes_block_wrk17(channel, [0u8; 16], k_c, session)?;

    let mut ghash_blocks_c = Vec::with_capacity(n_aad_blocks + n_pt_blocks + 1);

    for _ in 0..n_aad_blocks {
        ghash_blocks_c.push([0u8; 16]);
    }

    let mut ciphertext = Vec::with_capacity(pt_len);
    for blk in 0..n_pt_blocks {
        let valid_bytes = if blk == n_pt_blocks - 1 {
            pt_last_bytes
        } else {
            16
        };
        let ks_n: [u8; 16] = channel.read()?;
        let ks_c = client_aes_block_wrk17(channel, [0u8; 16], k_c, session)?;
        let mut pt_block = [0u8; 16];
        let start = blk * 16;
        let end = ((blk + 1) * 16).min(pt_len);
        pt_block[..end - start].copy_from_slice(&plaintext[start..end]);
        let ct_c = xor_bytes16(pt_block, ks_c);
        let ct = xor_bytes16(ct_c, ks_n);
        ciphertext.extend_from_slice(&ct[..valid_bytes]);
        ghash_blocks_c.push(zero_pad_block(ct_c, valid_bytes));
    }

    ghash_blocks_c.push([0u8; 16]);

    let x_acc_c = client_ghash_chain_wrk17(channel, &ghash_blocks_c, h_c, session)?;

    let tag_n: [u8; 16] = channel.read()?;
    let tag = xor_bytes16(tag_n, xor_bytes16(x_acc_c, s_c));

    Ok((ciphertext, tag))
}

fn ev_len_block(aad_len: usize, pt_len: usize) -> [u8; 16] {
    let mut len_block = [0u8; 16];
    len_block[0..8].copy_from_slice(&((aad_len as u64) * 8).to_be_bytes());
    len_block[8..16].copy_from_slice(&((pt_len as u64) * 8).to_be_bytes());
    len_block
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
    session: &mut Wrk17NotarySession,
) -> SwankyResult<()> {
    let n_aad_blocks = aad_len.div_ceil(16);
    let n_ct_blocks = ciphertext_len.div_ceil(16);
    let ct_last_bytes = if ciphertext_len == 0 {
        0
    } else {
        ((ciphertext_len - 1) % 16) + 1
    };

    let h_n = notary_aes_block_wrk17(channel, [0u8; 16], k_n, session)?;
    let j0 = make_nonce_ctr(nonce, 1);
    let s_n = notary_aes_block_wrk17(channel, j0, k_n, session)?;

    let mut ghash_blocks_n = Vec::with_capacity(n_aad_blocks + n_ct_blocks + 1);

    for _ in 0..n_aad_blocks {
        ghash_blocks_n.push([0u8; 16]);
    }

    for blk in 0..n_ct_blocks {
        let valid_bytes = if blk == n_ct_blocks - 1 {
            ct_last_bytes
        } else {
            16
        };
        let ctr_block = make_nonce_ctr(nonce, (blk as u32) + 2);
        let ks_n = notary_aes_block_wrk17(channel, ctr_block, k_n, session)?;
        let ct_c: [u8; 16] = channel.read()?;
        ghash_blocks_n.push([0u8; 16]);
        let pt_n = xor_bytes16(ct_c, ks_n);
        channel.write(&pt_n)?;
        let _ = valid_bytes;
    }

    let len_block = ev_len_block(aad_len, ciphertext_len);
    ghash_blocks_n.push(len_block);

    let x_acc_n = notary_ghash_chain_wrk17(channel, &ghash_blocks_n, h_n, session)?;
    let tag_n = xor_bytes16(x_acc_n, s_n);
    channel.write(&tag_n)?;
    Ok(())
}

pub fn client_decrypt_gcm_2pc(
    channel: &mut Channel,
    k_c: [u8; 16],
    ciphertext: &[u8],
    aad: &[u8],
    received_tag: [u8; 16],
    _nonce: [u8; 12],
    session: &mut Wrk17ClientSession,
) -> SwankyResult<Vec<u8>> {
    let pt_len = ciphertext.len();
    let n_aad_blocks = aad.len().div_ceil(16);
    let n_ct_blocks = pt_len.div_ceil(16);
    let pt_last_bytes = if pt_len == 0 {
        0
    } else {
        ((pt_len - 1) % 16) + 1
    };

    let h_c = client_aes_block_wrk17(channel, [0u8; 16], k_c, session)?;
    let s_c = client_aes_block_wrk17(channel, [0u8; 16], k_c, session)?;

    let mut ghash_blocks_c = Vec::with_capacity(n_aad_blocks + n_ct_blocks + 1);

    for blk in 0..n_aad_blocks {
        let mut aad_block = [0u8; 16];
        let start = blk * 16;
        let end = ((blk + 1) * 16).min(aad.len());
        aad_block[..end - start].copy_from_slice(&aad[start..end]);
        ghash_blocks_c.push(aad_block);
    }

    let mut plaintext = Vec::with_capacity(pt_len);
    for blk in 0..n_ct_blocks {
        let valid_bytes = if blk == n_ct_blocks - 1 {
            pt_last_bytes
        } else {
            16
        };
        let mut ct_block = [0u8; 16];
        let start = blk * 16;
        let end = ((blk + 1) * 16).min(pt_len);
        ct_block[..end - start].copy_from_slice(&ciphertext[start..end]);
        channel.write(&ct_block)?;
        let ks_c = client_aes_block_wrk17(channel, [0u8; 16], k_c, session)?;
        ghash_blocks_c.push(zero_pad_block(ct_block, valid_bytes));
        let pt_n: [u8; 16] = channel.read()?;
        let pt_c = xor_bytes16(ct_block, ks_c);
        let pt = xor_bytes16(pt_n, pt_c);
        plaintext.extend_from_slice(&pt[..valid_bytes]);
    }

    ghash_blocks_c.push([0u8; 16]);

    let x_acc_c = client_ghash_chain_wrk17(channel, &ghash_blocks_c, h_c, session)?;

    let tag_n: [u8; 16] = channel.read()?;
    let expected_tag = xor_bytes16(tag_n, xor_bytes16(x_acc_c, s_c));

    if !ct_eq16(expected_tag, received_tag) {
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
    pub fn new(ciphertext: &[u8], nonce: &[u8; 12], session_id: &[u8], signing_key: &[u8]) -> Self {
        use hmac::{Hmac, Mac};
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(ciphertext);
        hasher.update(nonce);
        hasher.update(session_id);
        let ciphertext_hash: [u8; 32] = hasher.finalize().into();

        let mut mac = Hmac::<Sha256>::new_from_slice(signing_key).unwrap();
        mac.update(&ciphertext_hash);
        let signature = mac.finalize().into_bytes().to_vec();

        NotaryCommit {
            ciphertext_hash,
            signature,
        }
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
    use aes_gcm::{
        Aes128Gcm, Key, Nonce,
        aead::{Aead, KeyInit},
    };
    let k: [u8; 16] = std::array::from_fn(|i| k_c[i] ^ k_n_revealed[i]);
    let cipher = Aes128Gcm::new(Key::<Aes128Gcm>::from_slice(&k));
    cipher.decrypt(Nonce::from_slice(nonce), ciphertext)
}

// ── helpers ───────────────────────────────────────────────────────────────────

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::garble::{Wrk17ClientSession, Wrk17NotarySession};
    use swanky_channel::local::local_channel_pair;

    /// Round-trip: 2PC encrypt → 2PC decrypt with same split key recovers plaintext.
    /// Slow: several WRK17 AES-128 blocks per direction (~minutes in debug).
    #[test]
    #[ignore = "WRK17 per-block AES; run with `cargo test --release decrypt_2pc -- --ignored`"]
    fn decrypt_2pc_round_trip() {
        let k_n = [0x2bu8; 16];
        let k_c = [0x60u8; 16];
        let nonce = [0xcau8; 12];
        let aad = b"some-aad-bytes";
        let plaintext = b"23-byte unaligned input"; // 23 bytes — partial last block

        // First encrypt via 2PC
        let ((), (ct, tag)) = local_channel_pair(
            |ch| {
                let mut session = Wrk17NotarySession::init(ch)?;
                notary_encrypt_gcm(ch, k_n, nonce, aad, plaintext.len(), &mut session)
            },
            |ch| {
                let mut session = Wrk17ClientSession::init(ch)?;
                client_encrypt_gcm(ch, k_c, plaintext, aad, nonce, &mut session)
            },
        )
        .unwrap();

        let ((), recovered) = local_channel_pair(
            |ch| {
                let mut session = Wrk17NotarySession::init(ch)?;
                notary_decrypt_gcm(ch, k_n, nonce, aad.len(), ct.len(), &mut session)
            },
            |ch| {
                let mut session = Wrk17ClientSession::init(ch)?;
                client_decrypt_gcm_2pc(ch, k_c, &ct, aad, tag, nonce, &mut session)
            },
        )
        .unwrap();
        assert_eq!(recovered, plaintext);
    }

    /// 2PC decrypt rejects a forged ciphertext (tag verification fires inside the
    /// client side after the circuit returns the expected tag).
    #[test]
    #[ignore = "WRK17 per-block AES; run with `cargo test --release decrypt_2pc -- --ignored`"]
    fn decrypt_2pc_rejects_tampered_ciphertext() {
        let k_n = [0x11u8; 16];
        let k_c = [0x22u8; 16];
        let nonce = [0x33u8; 12];
        let plaintext = b"some plaintext data";

        let ((), (mut ct, tag)) = local_channel_pair(
            |ch| {
                let mut session = Wrk17NotarySession::init(ch)?;
                notary_encrypt_gcm(ch, k_n, nonce, b"", plaintext.len(), &mut session)
            },
            |ch| {
                let mut session = Wrk17ClientSession::init(ch)?;
                client_encrypt_gcm(ch, k_c, plaintext, b"", nonce, &mut session)
            },
        )
        .unwrap();

        ct[0] ^= 0x80;

        let result = local_channel_pair(
            |ch| {
                let mut session = Wrk17NotarySession::init(ch)?;
                notary_decrypt_gcm(ch, k_n, nonce, 0, ct.len(), &mut session)
            },
            |ch| {
                let mut session = Wrk17ClientSession::init(ch)?;
                client_decrypt_gcm_2pc(ch, k_c, &ct, b"", tag, nonce, &mut session)
            },
        );
        // Local channel pair returns an error if either side errored
        assert!(result.is_err(), "tampered ciphertext must fail tag check");
    }

    /// 2PC decrypt output matches `aes-gcm` crate decrypt with `K = K_N XOR K_C`.
    #[test]
    #[ignore = "WRK17 per-block AES; run with `cargo test --release decrypt_2pc -- --ignored`"]
    fn decrypt_2pc_matches_aes_gcm_crate() {
        use aes_gcm::{
            Aes128Gcm, Key, Nonce,
            aead::{Aead, KeyInit, Payload},
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
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .unwrap();
        let ct = &reference[..plaintext.len()];
        let tag: [u8; 16] = reference[plaintext.len()..].try_into().unwrap();

        // Decrypt via 2PC
        let ((), recovered) = local_channel_pair(
            |ch| {
                let mut session = Wrk17NotarySession::init(ch)?;
                notary_decrypt_gcm(ch, k_n, nonce, aad.len(), ct.len(), &mut session)
            },
            |ch| {
                let mut session = Wrk17ClientSession::init(ch)?;
                client_decrypt_gcm_2pc(ch, k_c, ct, aad, tag, nonce, &mut session)
            },
        )
        .unwrap();

        assert_eq!(recovered, plaintext);
    }
}
