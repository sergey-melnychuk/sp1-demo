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
//! - Semi-honest per-compress HMAC chaining works (`hkdf::notary_sha256_compress_xor`).
//! - WRK17 per-compress round uses split-input + in-circuit mask (`hkdf` auth path).
//! - AES-GCM record layer still uses one semi-honest garbler for GHASH + multiple
//!   `execute` calls; needs split before full WRK17 there.

pub use swanky_authenticated_garbling::{Evaluator, Garbler};

use fancy_garbling::circuit::{BinaryCircuit, CircuitExecutor};
use fancy_garbling::{Fancy, FancyBinary};
use sp1_demo_common::SessionBinding;
use swanky_channel::Channel;
use swanky_error::Result as SwankyResult;

use crate::circuits::{
    GARBLING_HKDF_AUTH, circuit_aes_sha256, circuit_sha256_compress_sha256,
};

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

/// Default binding fields for circuit identity + garbling mode.
pub fn production_session_binding() -> SessionBinding {
    SessionBinding {
        circuit_aes_sha256: circuit_aes_sha256(),
        circuit_sha256_compress_sha256: circuit_sha256_compress_sha256(),
        garbling_mode: GARBLING_HKDF_AUTH,
        ..SessionBinding::default()
    }
}
