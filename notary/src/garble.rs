//! Authenticated malicious garbling (WRK17) — integration in progress.
//!
//! **Constraint:** one `circ.execute` per Garbler/Evaluator session. HMAC/GCM need
//! multiple sessions with byte-share handoff between rounds (see `hkdf` compress helpers).
//!
//! **WRK17 XOR-shared inputs:** each circuit input wire gets one preprocessed auth
//! share. Do not XOR-combine party encodings outside the circuit (`gb_split_bytes`).
//! Use [`SplitSharedInputMaskCircuit`]: garbler-owned inputs, then evaluator-owned
//! inputs, XOR pairs in-circuit, then XOR output with garbler mask inputs.
//!
//! **Status:**
//! - WRK17 per-compress HMAC (`hkdf`).
//! - WRK17 per-block AES + one unrolled GHASH chain per record (`aes`, `ghash`).
//! - OT extension reused via [`Wrk17NotarySession`] / [`Wrk17ClientSession`] on a channel.

pub use swanky_authenticated_garbling::ps::{PartyEvaluator, PartyGarbler};
pub use swanky_authenticated_garbling::{Evaluator, Garbler, preprocess_circuit};

use fancy_garbling::circuit::{BinaryCircuit, CircuitExecutor};
use fancy_garbling::circuit_analyzer::CircuitAnalyzer;
use fancy_garbling::{Fancy, FancyBinary};
use rand::Rng;
use sp1_demo_common::SessionBinding;
use swanky_authenticated_bits::and_triples::AndTripleGenerator;
use swanky_channel::Channel;
use swanky_error::Result as SwankyResult;
use swanky_rng::SwankyRng;

use crate::circuits::{GARBLING_FULL_AUTH, circuit_aes_sha256, circuit_sha256_compress_sha256};
use swanky_authenticated_garbling::WirePreProcessor;

/// AES block + key inputs (128 + 128 bits).
pub const AES_SHARED_INPUTS: usize = 256;
/// AES block output width.
pub const AES_OUTPUT_BITS: usize = 128;

/// Output XOR-mask width for SHA-256 compress (256-bit digest).
pub const OUTPUT_MASK_BITS: usize = 256;

/// WRK17 circuit wrapper for XOR-shared compress inputs + garbler output mask.
///
/// Input layout (garbler region then evaluator region, swanky convention):
/// - `[0 .. shared_inputs)`: notary XOR-shares for the inner circuit inputs
/// - `[shared_inputs .. shared_inputs + mask_bits)`: garbler output mask `m_n`
/// - `[shared_inputs + mask_bits .. 2*shared_inputs + mask_bits)`: client XOR-shares
/// - `[2*shared_inputs + mask_bits ..)`: client mask shares (zero for compress)
pub struct SplitSharedInputMaskCircuit {
    inner: BinaryCircuit,
    shared_inputs: usize,
    mask_bits: usize,
}

impl SplitSharedInputMaskCircuit {
    pub fn new(inner: BinaryCircuit, shared_inputs: usize, mask_bits: usize) -> Self {
        Self {
            inner,
            shared_inputs,
            mask_bits,
        }
    }

    pub fn garbler_inputs(&self) -> usize {
        self.shared_inputs + self.mask_bits
    }

    pub fn evaluator_inputs(&self) -> usize {
        self.shared_inputs + self.mask_bits
    }

    pub fn mask_bits(&self) -> usize {
        self.mask_bits
    }

    pub fn shared_inputs(&self) -> usize {
        self.shared_inputs
    }
}

impl<F> CircuitExecutor<F> for SplitSharedInputMaskCircuit
where
    F: FancyBinary,
{
    fn execute(
        &self,
        backend: &mut F,
        inputs: &[F::Item],
        channel: &mut Channel,
    ) -> SwankyResult<Vec<F::Item>> {
        let gb = self.garbler_inputs();
        let ev = self.evaluator_inputs();
        debug_assert_eq!(inputs.len(), gb + ev);

        let mut combined = Vec::with_capacity(self.shared_inputs);
        for i in 0..self.shared_inputs {
            combined.push(backend.xor(&inputs[i], &inputs[gb + i]));
        }

        let outputs = self.inner.execute(backend, &combined, channel)?;
        debug_assert_eq!(outputs.len(), self.mask_bits);

        Ok(outputs
            .iter()
            .enumerate()
            .map(|(i, out)| {
                let mask = backend.xor(
                    &inputs[self.shared_inputs + i],
                    &inputs[gb + self.shared_inputs + i],
                );
                backend.xor(out, &mask)
            })
            .collect())
    }

    fn ninputs(&self) -> usize {
        self.garbler_inputs() + self.evaluator_inputs()
    }

    fn modulus(&self, i: usize) -> u16 {
        let _ = i;
        2
    }
}

fn bits_to_bytes<const N: usize>(bits: &[u16]) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, chunk) in bits.chunks(8).enumerate().take(N) {
        for (j, &bit) in chunk.iter().enumerate() {
            out[i] |= (bit as u8) << (7 - j);
        }
    }
    out
}

/// Reused KOS / authenticated-bit OT for many WRK17 circuits on one channel.
pub struct Wrk17NotarySession {
    and_gen: AndTripleGenerator<PartyGarbler>,
}

/// Client-side counterpart to [`Wrk17NotarySession`].
pub struct Wrk17ClientSession {
    and_gen: AndTripleGenerator<PartyEvaluator>,
}

impl Wrk17NotarySession {
    /// One-time OT extension bootstrap (notary / garbler role).
    pub fn init(channel: &mut Channel) -> SwankyResult<Self> {
        let mut rng = SwankyRng::new();
        Ok(Self {
            and_gen: AndTripleGenerator::new(channel, &mut rng)?,
        })
    }
}

impl Wrk17ClientSession {
    /// One-time OT extension bootstrap (client / evaluator role).
    pub fn init(channel: &mut Channel) -> SwankyResult<Self> {
        let mut rng = SwankyRng::new();
        Ok(Self {
            and_gen: AndTripleGenerator::new(channel, &mut rng)?,
        })
    }
}

pub(crate) fn wrk17_notary_garbler<C>(
    channel: &mut Channel,
    circuit: &C,
    session: Option<&mut Wrk17NotarySession>,
) -> SwankyResult<Garbler<SwankyRng>>
where
    C: CircuitExecutor<CircuitAnalyzer> + CircuitExecutor<WirePreProcessor<PartyGarbler>>,
{
    let rng = SwankyRng::new();
    match session {
        Some(s) => Garbler::new_with_and_generator(circuit, channel, rng, &mut s.and_gen),
        None => Garbler::new(circuit, channel, rng),
    }
}

pub(crate) fn wrk17_client_evaluator<C>(
    channel: &mut Channel,
    circuit: &C,
    session: Option<&mut Wrk17ClientSession>,
) -> SwankyResult<Evaluator>
where
    C: CircuitExecutor<CircuitAnalyzer> + CircuitExecutor<WirePreProcessor<PartyEvaluator>>,
{
    let mut rng = SwankyRng::new();
    match session {
        Some(s) => Evaluator::new_with_and_generator(circuit, channel, &mut rng, &mut s.and_gen),
        None => Evaluator::new(circuit, channel, &mut rng),
    }
}

/// One WRK17 garbler session: garbler region = shared-input XOR-shares + random output mask.
/// Returns the garbler's byte-share of the masked output (the mask `m_n`).
pub fn wrk17_notary_masked_run(
    channel: &mut Channel,
    circ: &SplitSharedInputMaskCircuit,
    garbler_shared_bits: &[u16],
    session: &mut Wrk17NotarySession,
) -> SwankyResult<Vec<u8>> {
    debug_assert_eq!(garbler_shared_bits.len(), circ.shared_inputs);
    let mask_bytes = circ.mask_bits() / 8;
    let mut mask = vec![0u8; mask_bytes];
    rand::thread_rng().fill(&mut mask[..]);

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
    Ok(mask)
}

/// One WRK17 evaluator session; returns the evaluator's byte-share of the masked output.
pub fn wrk17_client_masked_run(
    channel: &mut Channel,
    circ: &SplitSharedInputMaskCircuit,
    evaluator_shared_bits: &[u16],
    session: &mut Wrk17ClientSession,
) -> SwankyResult<Vec<u8>> {
    debug_assert_eq!(evaluator_shared_bits.len(), circ.shared_inputs);
    let mut ev_vals = evaluator_shared_bits.to_vec();
    ev_vals.extend(vec![0u16; circ.mask_bits()]);

    let mut ev = wrk17_client_evaluator(channel, circ, Some(session))?;
    let notary = ev.receive_many(&vec![2u16; circ.garbler_inputs()], channel)?;
    let mine = ev.encode_many(&ev_vals, &vec![2u16; circ.evaluator_inputs()], channel)?;
    let mut inputs = notary;
    inputs.extend(mine);
    let out = circ.execute(&mut ev, &inputs, channel)?;
    let vals = ev
        .outputs(&out, channel)?
        .expect("WRK17 evaluator receives circuit output");
    let full = bits_to_bytes::<32>(&vals);
    Ok(full[..circ.mask_bits() / 8].to_vec())
}

/// Import a byte XOR-share into a semi-honest garbler session wire bundle.
pub fn semi_gb_split_bytes<F: FancyBinary>(
    gb: &mut F,
    channel: &mut Channel,
    notary_share: &[u8],
) -> SwankyResult<Vec<F::Item>> {
    let bits: Vec<u16> = notary_share
        .iter()
        .flat_map(|&b| (0..8u8).rev().map(move |i| ((b >> i) & 1) as u16))
        .collect();
    let n = bits.len();
    let mod2 = vec![2u16; n];
    let notary_wires = gb.encode_many(&bits, &mod2, channel)?;
    let client_wires = gb.receive_many(&mod2, channel)?;
    Ok(notary_wires
        .iter()
        .zip(client_wires.iter())
        .map(|(a, b)| gb.xor(a, b))
        .collect())
}

/// Import a byte XOR-share into a semi-honest evaluator session wire bundle.
pub fn semi_ev_split_bytes<F: FancyBinary>(
    ev: &mut F,
    channel: &mut Channel,
    client_share: &[u8],
) -> SwankyResult<Vec<F::Item>> {
    let bits: Vec<u16> = client_share
        .iter()
        .flat_map(|&b| (0..8u8).rev().map(move |i| ((b >> i) & 1) as u16))
        .collect();
    let n = bits.len();
    let mod2 = vec![2u16; n];
    let notary_wires = ev.receive_many(&mod2, channel)?;
    let client_wires = ev.encode_many(&bits, &mod2, channel)?;
    Ok(notary_wires
        .iter()
        .zip(client_wires.iter())
        .map(|(a, b)| ev.xor(a, b))
        .collect())
}

/// Default binding fields for circuit identity + garbling mode.
pub fn production_session_binding() -> SessionBinding {
    SessionBinding {
        circuit_aes_sha256: circuit_aes_sha256(),
        circuit_sha256_compress_sha256: circuit_sha256_compress_sha256(),
        garbling_mode: GARBLING_FULL_AUTH,
        ..SessionBinding::default()
    }
}
