//! GHASH multiplication in GF(2^128) for AES-GCM — WRK17 authenticated garbling.
//!
//! One unrolled [`GhashChainWrk17Circuit`] per record chains all GHASH steps in a
//! single WRK17 `execute` (AAD + ciphertext + length blocks).

use fancy_garbling::circuit::CircuitExecutor;
use fancy_garbling::{Fancy, FancyBinary};
use rand::Rng;
use swanky_channel::Channel;
use swanky_error::Result as SwankyResult;

use crate::garble::{
    Wrk17ClientSession, Wrk17NotarySession, wrk17_client_evaluator, wrk17_notary_garbler,
};

fn bytes_to_bits(bytes: &[u8]) -> Vec<u16> {
    bytes
        .iter()
        .flat_map(|&b| (0..8u8).rev().map(move |i| ((b >> i) & 1) as u16))
        .collect()
}

fn bits_to_bytes_16(bits: Vec<u16>) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (i, chunk) in bits.chunks(8).enumerate().take(16) {
        for (j, &bit) in chunk.iter().enumerate() {
            out[i] |= (bit as u8) << (7 - j);
        }
    }
    out
}

/// GF(2^128) multiply: 128-bit `x` × 128-bit `y` → 128-bit (GCM bit-serial algorithm).
pub struct GhashMulCircuit;

const GHASH_BLOCK_BITS: usize = 128;
const GHASH_H_BITS: usize = 128;

impl GhashMulCircuit {
    fn execute_on<F: FancyBinary>(
        backend: &mut F,
        channel: &mut Channel,
        x: &[F::Item],
        y: &[F::Item],
    ) -> SwankyResult<Vec<F::Item>>
    where
        F::Item: Clone,
    {
        debug_assert_eq!(x.len(), GHASH_BLOCK_BITS);
        debug_assert_eq!(y.len(), GHASH_H_BITS);

        let zero = backend.constant(0, 2, channel)?;
        let mut z: Vec<F::Item> = (0..GHASH_BLOCK_BITS).map(|_| zero.clone()).collect();
        let mut v = y.to_vec();

        for xi in x.iter().take(GHASH_BLOCK_BITS) {
            for j in 0..GHASH_BLOCK_BITS {
                let xv = backend.and(xi, &v[j], channel)?;
                z[j] = backend.xor(&z[j], &xv);
            }
            let lsb = v[127].clone();
            let mut new_v = Vec::with_capacity(GHASH_BLOCK_BITS);
            new_v.push(zero.clone());
            new_v.extend(v[..127].iter().cloned());
            v = new_v;
            for &r in &[0usize, 1, 2, 7] {
                v[r] = backend.xor(&v[r], &lsb);
            }
        }
        Ok(z)
    }
}

impl<F: FancyBinary> CircuitExecutor<F> for GhashMulCircuit {
    fn execute(
        &self,
        backend: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> SwankyResult<Vec<F::Item>> {
        debug_assert_eq!(inputs.len(), 256);
        Self::execute_on(backend, channel, &inputs[..128], &inputs[128..])
    }

    fn ninputs(&self) -> usize {
        256
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

/// Chains `n_blocks` GHASH steps: `acc ← (acc ⊕ block_i) · H`.
pub struct GhashChainCircuit {
    n_blocks: usize,
}

impl GhashChainCircuit {
    pub fn new(n_blocks: usize) -> Self {
        Self { n_blocks }
    }

    pub fn shared_inputs(&self) -> usize {
        GHASH_H_BITS + self.n_blocks * GHASH_BLOCK_BITS
    }
}

impl<F: FancyBinary> CircuitExecutor<F> for GhashChainCircuit {
    fn execute(
        &self,
        backend: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> SwankyResult<Vec<F::Item>> {
        debug_assert_eq!(inputs.len(), self.shared_inputs());
        let h = &inputs[..GHASH_H_BITS];
        let zero = backend.constant(0, 2, channel)?;
        let mut acc: Vec<F::Item> = (0..GHASH_BLOCK_BITS).map(|_| zero.clone()).collect();

        for blk in 0..self.n_blocks {
            let start = GHASH_H_BITS + blk * GHASH_BLOCK_BITS;
            let block = &inputs[start..start + GHASH_BLOCK_BITS];
            let x: Vec<F::Item> = acc
                .iter()
                .zip(block.iter())
                .map(|(a, b)| backend.xor(a, b))
                .collect();
            acc = GhashMulCircuit::execute_on(backend, channel, &x, h)?;
        }
        Ok(acc)
    }

    fn ninputs(&self) -> usize {
        self.shared_inputs()
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

/// WRK17 wrapper for a full GHASH chain on XOR-shared inputs + garbler output mask.
pub struct GhashChainWrk17Circuit {
    inner: GhashChainCircuit,
}

impl GhashChainWrk17Circuit {
    pub fn new(n_blocks: usize) -> Self {
        Self {
            inner: GhashChainCircuit::new(n_blocks),
        }
    }

    pub fn shared_inputs(&self) -> usize {
        self.inner.shared_inputs()
    }

    const MASK_BITS: usize = GHASH_BLOCK_BITS;

    fn garbler_inputs(&self) -> usize {
        self.shared_inputs() + Self::MASK_BITS
    }

    fn evaluator_inputs(&self) -> usize {
        self.shared_inputs() + Self::MASK_BITS
    }
}

impl<F: FancyBinary> CircuitExecutor<F> for GhashChainWrk17Circuit {
    fn execute(
        &self,
        backend: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> SwankyResult<Vec<F::Item>> {
        let gb = self.garbler_inputs();
        let ev = self.evaluator_inputs();
        debug_assert_eq!(inputs.len(), gb + ev);

        let shared = self.shared_inputs();
        let mut combined = Vec::with_capacity(shared);
        for i in 0..shared {
            combined.push(backend.xor(&inputs[i], &inputs[gb + i]));
        }

        let outputs = self.inner.execute(backend, &combined, channel)?;
        debug_assert_eq!(outputs.len(), Self::MASK_BITS);

        Ok(outputs
            .iter()
            .enumerate()
            .map(|(i, out)| {
                let mask = backend.xor(&inputs[shared + i], &inputs[gb + shared + i]);
                backend.xor(out, &mask)
            })
            .collect())
    }

    fn ninputs(&self) -> usize {
        self.garbler_inputs() + self.evaluator_inputs()
    }

    fn modulus(&self, _: usize) -> u16 {
        2
    }
}

fn run_notary_ghash_chain(
    channel: &mut Channel,
    circ: &GhashChainWrk17Circuit,
    garbler_shared_bits: &[u16],
    session: &mut Wrk17NotarySession,
) -> SwankyResult<Vec<u8>> {
    debug_assert_eq!(garbler_shared_bits.len(), circ.shared_inputs());
    let mut mask = [0u8; 16];
    rand::thread_rng().fill(&mut mask);

    let mut gb_vals = garbler_shared_bits.to_vec();
    for &b in &mask {
        for i in (0..8u8).rev() {
            gb_vals.push(((b >> i) & 1) as u16);
        }
    }

    let mut gb = wrk17_notary_garbler(channel, circ, Some(session))?;
    let mine = gb.encode_many(&gb_vals, &vec![2u16; circ.garbler_inputs()], channel)?;
    let theirs = gb.receive_many(&vec![2u16; circ.evaluator_inputs()], channel)?;
    let mut inputs = mine;
    inputs.extend(theirs);
    let out = circ.execute(&mut gb, &inputs, channel)?;
    gb.outputs(&out, channel)?;
    Ok(mask.to_vec())
}

fn run_client_ghash_chain(
    channel: &mut Channel,
    circ: &GhashChainWrk17Circuit,
    evaluator_shared_bits: &[u16],
    session: &mut Wrk17ClientSession,
) -> SwankyResult<Vec<u8>> {
    debug_assert_eq!(evaluator_shared_bits.len(), circ.shared_inputs());
    let mut ev_vals = evaluator_shared_bits.to_vec();
    ev_vals.extend(vec![0u16; GhashChainWrk17Circuit::MASK_BITS]);

    let mut ev = wrk17_client_evaluator(channel, circ, Some(session))?;
    let notary = ev.receive_many(&vec![2u16; circ.garbler_inputs()], channel)?;
    let mine = ev.encode_many(&ev_vals, &vec![2u16; circ.evaluator_inputs()], channel)?;
    let mut inputs = notary;
    inputs.extend(mine);
    let out = circ.execute(&mut ev, &inputs, channel)?;
    let vals = ev
        .outputs(&out, channel)?
        .expect("WRK17 evaluator receives circuit output");
    Ok(bits_to_bytes_16(vals.to_vec()).to_vec())
}

/// Reference GHASH multiply (matches [`GhashMulCircuit`]).
pub fn ghash_mul_reference(x: [u8; 16], y: [u8; 16]) -> [u8; 16] {
    let x_bits = bytes_to_bits(&x);
    let y_bits = bytes_to_bits(&y);
    let mut z = [0u16; 128];
    let mut v = y_bits.clone();

    for xi in x_bits.iter().take(128) {
        if *xi == 1 {
            for (j, vj) in v.iter().enumerate().take(128) {
                if *vj == 1 {
                    z[j] ^= 1;
                }
            }
        }
        let lsb = v[127];
        let mut new_v = vec![0u16; 128];
        new_v[1..128].copy_from_slice(&v[..127]);
        v = new_v;
        if lsb == 1 {
            for &r in &[0usize, 1, 2, 7] {
                v[r] ^= 1;
            }
        }
    }
    bits_to_bytes_16(z.to_vec())
}

pub fn ghash_chain_reference(h: [u8; 16], blocks: &[[u8; 16]]) -> [u8; 16] {
    let mut acc = [0u8; 16];
    for block in blocks {
        acc = ghash_mul_reference(xor_bytes16(acc, *block), h);
    }
    acc
}

pub fn xor_bytes16(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

pub fn zero_pad_block(mut block: [u8; 16], valid_bytes: usize) -> [u8; 16] {
    if valid_bytes < 16 {
        for b in block.iter_mut().skip(valid_bytes) {
            *b = 0;
        }
    }
    block
}

/// Full GHASH chain for one record in one WRK17 session.
pub fn notary_ghash_chain_wrk17(
    channel: &mut Channel,
    blocks_n: &[[u8; 16]],
    h_n: [u8; 16],
    session: &mut Wrk17NotarySession,
) -> SwankyResult<[u8; 16]> {
    let circ = GhashChainWrk17Circuit::new(blocks_n.len());
    let mut gb_bits = bytes_to_bits(&h_n);
    for block in blocks_n {
        gb_bits.extend(bytes_to_bits(block));
    }
    let mask = run_notary_ghash_chain(channel, &circ, &gb_bits, session)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&mask);
    Ok(out)
}

/// Full GHASH chain for one record in one WRK17 session.
pub fn client_ghash_chain_wrk17(
    channel: &mut Channel,
    blocks_c: &[[u8; 16]],
    h_c: [u8; 16],
    session: &mut Wrk17ClientSession,
) -> SwankyResult<[u8; 16]> {
    let circ = GhashChainWrk17Circuit::new(blocks_c.len());
    let mut ev_bits = bytes_to_bits(&h_c);
    for block in blocks_c {
        ev_bits.extend(bytes_to_bits(block));
    }
    let share = run_client_ghash_chain(channel, &circ, &ev_bits, session)?;
    let mut out = [0u8; 16];
    out.copy_from_slice(&share);
    Ok(out)
}

/// Constant-time 16-byte equality (for tag check on the client).
pub fn ct_eq16(a: [u8; 16], b: [u8; 16]) -> bool {
    let mut diff = 0u8;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::garble::{Wrk17ClientSession, Wrk17NotarySession};
    use swanky_channel::local::local_channel_pair;

    #[test]
    fn ghash_mul_reference_nonzero() {
        let x = [0x2bu8; 16];
        let y = [0x60u8; 16];
        let z = ghash_mul_reference(x, y);
        assert_ne!(z, [0u8; 16]);
    }

    #[test]
    fn ghash_chain_reference_matches_stepwise() {
        let h = [0x60u8; 16];
        let blocks = [[0x2bu8; 16], [0x11u8; 16], [0x22u8; 16]];
        let mut acc = [0u8; 16];
        for b in &blocks {
            acc = ghash_mul_reference(xor_bytes16(acc, *b), h);
        }
        assert_eq!(acc, ghash_chain_reference(h, &blocks));
    }

    #[test]
    fn ghash_chain_wrk17_matches_reference() {
        let h_n = [0x60u8; 16];
        let h_c = [0x01u8; 16];
        let blocks_n = [[0x2bu8; 16], [0x00u8; 16]];
        let blocks_c = [[0x00u8; 16], [0x11u8; 16]];
        let h = xor_bytes16(h_n, h_c);
        let blocks: Vec<[u8; 16]> = blocks_n
            .iter()
            .zip(blocks_c.iter())
            .map(|(a, b)| xor_bytes16(*a, *b))
            .collect();
        let expected = ghash_chain_reference(h, &blocks);

        let (n_share, c_share) = local_channel_pair(
            |ch| {
                let mut session = Wrk17NotarySession::init(ch)?;
                notary_ghash_chain_wrk17(ch, &blocks_n, h_n, &mut session)
            },
            |ch| {
                let mut session = Wrk17ClientSession::init(ch)?;
                client_ghash_chain_wrk17(ch, &blocks_c, h_c, &mut session)
            },
        )
        .unwrap();
        assert_eq!(xor_bytes16(n_share, c_share), expected);
    }
}
