use crate::preprocesser::{preprocess_circuit, WirePreProcessor};
use crate::ps::PartyGarbler;
use crate::wire::AuthenticatedWireMod2;
use fancy_garbling::circuit::CircuitExecutor;
use fancy_garbling::circuit_analyzer::CircuitAnalyzer;
use fancy_garbling::{Fancy, FancyBinary, WireLabel, WireMod2};

use rand::{CryptoRng, RngCore};
use swanky_authenticated_bits::and_triples::AndTripleGenerator;
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_error::WrapErr;
use swanky_error::{ensure, ErrorKind, Result};
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F2};
use vectoreyes::U8x16;

type AuthenticatedWire = AuthenticatedWireMod2<PartyGarbler>;

/// The authenticated garbler.
pub struct Garbler<RNG> {
    // The garbler's Δ.
    delta: WireMod2,
    // A random wirelabel denoting zero. Used to make negations free.
    zero: WireMod2,
    // The index of the current AND gate. Used as the tweak when hashing
    // wirelabels in the AND gate garbling.
    and_gate_index: usize,
    // A vector of authenticated shares, one per input wire and AND gate output.
    // Corresponds to〈r_w, s_w〉from the paper.
    auth_shares: Vec<AuthShare<PartyGarbler>>,
    // The index of the current authenticated share we're using.
    auth_shares_index: usize,
    // A vector of fixed authenticated shares for AND gate wires. Each share is
    // set such that it is equal to the AND of the incoming wire shares.
    // Corresponds to〈r_w^*, s_w^*〉from the paper.
    and_auth_shares: Vec<AuthShare<PartyGarbler>>,
    // The index of the current AND authenticated share we're using.
    and_auth_shares_index: usize,
    rng: RNG,
}

impl<RNG: CryptoRng + RngCore> Garbler<RNG> {
    /// Create a new garbler for a given circuit.
    pub fn new<
        C: CircuitExecutor<CircuitAnalyzer> + CircuitExecutor<WirePreProcessor<PartyGarbler>>,
    >(
        circuit: &C,
        channel: &mut Channel,
        mut rng: RNG,
    ) -> swanky_error::Result<Self> {
        let delta = AndTripleGenerator::<PartyGarbler>::generate_valid_delta(&mut rng);
        let zero = WireMod2::rand(&mut rng, 2);
        let one = WireMod2::from_repr(zero.to_repr() ^ delta, 2);

        let mut and_generator = AndTripleGenerator::new_with_delta(delta, channel, &mut rng)?;
        let (auth_shares, known_triples) =
            preprocess_circuit(circuit, &mut and_generator, channel, &mut rng)?;

        channel.write(&one.to_repr())?;
        Ok(Garbler {
            delta: WireMod2::from_repr(delta, 2),
            zero,
            and_gate_index: 0,
            auth_shares,
            auth_shares_index: 0,
            and_auth_shares: known_triples,
            and_auth_shares_index: 0,
            rng,
        })
    }

    /// Create a garbler while reusing OT material from `and_generator`.
    pub fn new_with_and_generator<
        C: CircuitExecutor<CircuitAnalyzer> + CircuitExecutor<WirePreProcessor<PartyGarbler>>,
    >(
        circuit: &C,
        channel: &mut Channel,
        mut rng: RNG,
        and_generator: &mut AndTripleGenerator<PartyGarbler>,
    ) -> swanky_error::Result<Self> {
        let delta = and_generator.delta();
        let zero = WireMod2::rand(&mut rng, 2);
        let one = WireMod2::from_repr(zero.to_repr() ^ delta, 2);
        let (auth_shares, known_triples) =
            preprocess_circuit(circuit, and_generator, channel, &mut rng)?;
        channel.write(&one.to_repr())?;
        Ok(Garbler {
            delta: WireMod2::from_repr(delta, 2),
            zero,
            and_gate_index: 0,
            auth_shares,
            auth_shares_index: 0,
            and_auth_shares: known_triples,
            and_auth_shares_index: 0,
            rng,
        })
    }

    fn next_and_gate_index(&mut self) -> usize {
        let current = self.and_gate_index;
        self.and_gate_index += 1;
        current
    }

    fn next_auth_share(&mut self) -> AuthShare<PartyGarbler> {
        let share = self.auth_shares[self.auth_shares_index];
        self.auth_shares_index += 1;
        share
    }

    fn next_and_auth_share(&mut self) -> AuthShare<PartyGarbler> {
        let share = self.and_auth_shares[self.and_auth_shares_index];
        self.and_auth_shares_index += 1;
        share
    }

    // Create wirelabels `L_0` and `L_1`, sending the wirelabel `L_b` associated
    // with the masked value `b` to the evaluator, and returning a vector of the
    // corresponding `AuthenticatedWireMod2` values.
    //
    // This corresponds to pieces of Steps 3 and 4 in Figure 3 of the paper.
    fn encode_wirelabels(
        &mut self,
        masked_values: Vec<F2>,
        auth_shares: Vec<AuthShare<PartyGarbler>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<AuthenticatedWire>> {
        // Compute zero wirelabels `L_{w,0}`.
        let zeros = (0..masked_values.len())
            .map(|_| WireMod2::rand(&mut self.rng, 2))
            .collect::<Vec<_>>();

        // Use masked values `x_w + λ_w` and zero wirelabels `L_0` to create
        // wirelabels `L_{x_w + λ_w}`, and send these to the evaluator.
        for (masked_value, zero) in masked_values.iter().zip(zeros.iter()) {
            let wirelabel = *zero
                + WireMod2::from_repr(
                    U8x16::from(*masked_value * F128b::from(self.delta.to_repr())),
                    2,
                );
            channel.write(&wirelabel.to_repr())?;
        }

        Ok(masked_values
            .into_iter()
            .zip(zeros.into_iter().zip(auth_shares))
            .map(|(masked_value, (zero, auth_share))| {
                AuthenticatedWire::new(masked_value, zero, auth_share)
            })
            .collect())
    }
}

impl<RNG> FancyBinary for Garbler<RNG>
where
    RNG: RngCore + CryptoRng,
{
    fn and(
        &mut self,
        la0: &Self::Item,
        lb0: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        // This index is called γ in the paper
        let index = self.next_and_gate_index();
        // This is the share for wire label L_{γ,0}
        let lc_share = self.next_auth_share();
        // This is the and triple share for wire label L_{γ,0}
        let lc_triple = self.next_and_auth_share();

        // Compute l1 from l0 for both inputs
        //
        // This wire label is L_{α,1} = L_{α,0} + Δ
        let la1 = la0.wire_label() + self.delta;
        // This wire label is L_{β,1} = L_{β,0} + Δ
        let lb1 = lb0.wire_label() + self.delta;

        // Hash l0 and l1 from both inputs and use the current index as a tweak
        //
        // This is H(L_{α,0}, γ) in the paper
        let h_la0 = la0.wire_label().hash(index as u128);
        // This is H(L_{β,0}, γ) in the paper
        let h_lb0 = lb0.wire_label().hash(index as u128);
        // This is H(L_{α,1}, γ) in the paper
        let h_la1 = la1.hash(index as u128);
        // This is H(L_{β,1}, γ) in the paper
        let h_lb1 = lb1.hash(index as u128);

        // Extract the share keys for the inputs, the current gate share, and the and triple
        // This is K[s_α] in the paper
        let key_a = la0.auth_share().key();
        // This is K[s_β] in the paper
        let key_b = lb0.auth_share().key();
        // This is K[s_γ] in the paper
        let key_c = lc_share.key();
        // This is K[s*_γ] in the paper
        let key_c_triple = lc_triple.key();

        // Compute Δ_rα := Δ x r_α: if r_α is 0, then this value is 0, otherwise its Δ
        let delta_bit_a = U8x16::from(la0.auth_share().bit() * F128b::from(self.delta.to_repr()));
        // Compute Δ_rβ := Δ x r_β: if r_β is 0, then this value is 0, otherwise its Δ
        let delta_bit_b = U8x16::from(lb0.auth_share().bit() * F128b::from(self.delta.to_repr()));
        // Compute Δ_rγ := Δ x r_γ: if r_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c = U8x16::from(lc_share.bit() * F128b::from(self.delta.to_repr()));
        // Compute Δ_r*γ := Δ x r*_γ: if r*_γ is 0, then this value is 0, otherwise its Δ
        let delta_bit_c_triple = U8x16::from(lc_triple.bit() * F128b::from(self.delta.to_repr()));

        // Gate_{γ,0} = H(L_{α,0}, γ) + H(L_{α,1}, γ) + K[s_β] + Δ_rβ
        let gate0 = h_la0 ^ h_la1 ^ key_b ^ delta_bit_b;
        // Gate_{γ,1} = H(L_{β,0}, γ) + H(L_{β,1}, γ) + K[s_α] + Δ_rα + L_{α,0}
        let gate1 = h_lb0 ^ h_lb1 ^ key_a ^ delta_bit_a ^ la0.wire_label().to_repr();
        // L_{γ,0} = H(L_{α,0}, γ) + H(L_{β,0}, γ) + K[s_γ] + Δ_rγ + K[s*_γ] + Δ_r*γ
        let lc0 = h_la0 ^ h_lb0 ^ key_c ^ delta_bit_c ^ key_c_triple ^ delta_bit_c_triple;
        // b_γ = lsb(L_{γ,0})
        let bit_c = F128b::from(lc0).lsb();

        channel.write(&gate0)?;
        channel.write(&gate1)?;
        channel.write(&bit_c)?;

        // z'α := z_α + λ_α, where z_α is the actual wire value of the input
        // wire with label L_α and λ_α is the mask of that value
        let la_value = la0.masked_value();
        // The Garbler's authenticated share of λ_α
        let la_lambda = la0.auth_share();
        // z'β := z_β + λ_β, where z_β is the actual wire value of the input
        // wire with label L_β and λ_β is the mask of that value
        let lb_value = lb0.masked_value();
        // The Garbler's authenticated share of λ_β
        let lb_lambda = lb0.auth_share();

        // The Garbler receives the value z'γ from the Evaluator so that
        // they can locally compute their share of c_γ
        let lc_value: F2 = channel.read()?;

        // The Garbler computes its share of the validation bit
        // c_γ :=  (z'α ⊕ λ_α) ∧ (z'β ⊕ λ_β ) ⊕ (z'γ ⊕ λ_γ )
        //     := (z'α z'β ⊕ z'β λ_α ⊕ z'α λ_β ⊕ λ_α λ_β) ⊕ (z'γ ⊕ λ_γ )
        //     := (z'α z'β ⊕ z'γ ) ⊕ (z'β λ_α ⊕ z'α λ_β ⊕ λ*_γ ⊕ λ_γ)

        // The Garbler first creates the constant share of (z'α z'β ⊕ z'γ )
        let share_masks = AuthShareGenerator::constant_with_delta(
            la_value * lb_value + lc_value,
            self.delta.to_repr(),
        );
        // Then they create their share of the validation bit
        // c_γ := (z'α z'β ⊕ z'γ ) ⊕ (z'β λ_α ⊕ z'α λ_β ⊕ λ*_γ ⊕ λ_γ)
        let validation_share = share_masks
            ^ la_lambda.mul_with_const(lb_value)
            ^ lb_lambda.mul_with_const(la_value)
            ^ lc_triple
            ^ lc_share;

        let mut validation_bit = Vec::with_capacity(1);
        // The parties then open the share c_γ
        AuthShareGenerator::open_with_delta(
            &[validation_share],
            self.delta.to_repr(),
            &mut validation_bit,
            channel,
        )?;

        ensure!(
            validation_bit[0] == F2::ZERO,
            ErrorKind::OtherError,
            "Garbler's authentication validation check failed at index {index}"
        );

        Ok(AuthenticatedWire::new(
            lc_value,
            WireMod2::from_repr(lc0, 2),
            lc_share,
        ))
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        AuthenticatedWire::new(
            x.masked_value() + y.masked_value(),
            x.wire_label() + y.wire_label(),
            x.auth_share() ^ y.auth_share(),
        )
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWire::new(
            x.masked_value() + F2::ONE,
            WireMod2::from_repr(x.wire_label().to_repr() ^ self.zero.to_repr(), 2),
            x.auth_share(),
        )
    }
}

impl<RNG: RngCore + CryptoRng> Fancy for Garbler<RNG> {
    type Item = AuthenticatedWire;

    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<<Self as Fancy>::Item>> {
        assert_eq!(values.len(), moduli.len());

        // Grab authenticated shares for each of the inputs.
        let my_auth_shares = (0..values.len())
            .map(|_| self.next_auth_share())
            .collect::<Vec<_>>();

        // Open the evaluator's shares `[s_w]` using these shares.
        let mut their_bits = Vec::with_capacity(values.len());
        AuthShareGenerator::open_their_shares_with_delta(
            &my_auth_shares,
            self.delta.to_repr(),
            &mut their_bits,
            channel,
        )?;

        // Compute masked values `x_w ⊕ λ_w := x_w ⊕ (s_w ⊕ r_w)`.
        let my_masked_values = their_bits
            .into_iter()
            .zip(my_auth_shares.iter().zip(values.iter()))
            .map(|(theirs, (mine, value))| {
                F2::try_from(*value)
                    .wrap_err(ErrorKind::OtherError, "Invalid value, must be boolean")
                    .map(|value| theirs + mine.bit() + value)
            })
            .collect::<Result<Vec<_>>>()?;

        // Send `x_w ⊕ λ_w` to the evaluator.
        for masked_value in my_masked_values.iter() {
            channel.write(masked_value)?;
        }

        self.encode_wirelabels(my_masked_values, my_auth_shares, channel)
    }

    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        // Grab authenticated shares for each of the inputs.
        let my_auth_shares = (0..moduli.len())
            .map(|_| self.next_auth_share())
            .collect::<Vec<_>>();

        // Open the garbler's shares `[r_w]` using these shares.
        AuthShareGenerator::open_my_shares(&my_auth_shares, channel)?;

        // Receive `y_w ⊕ λ_w := y_w ⊕ (s_w ⊕ r_w)` from the evaluator.
        let their_masked_values = (0..moduli.len())
            .map(|_| channel.read())
            .collect::<Result<Vec<_>>>()?;

        self.encode_wirelabels(their_masked_values, my_auth_shares, channel)
    }

    fn constant(
        &mut self,
        value: u16,
        _q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<AuthenticatedWire> {
        let constant = F2::try_from(value).expect("constant must be boolean");
        let share = AuthShareGenerator::constant_with_delta(F2::ZERO, self.delta.to_repr());

        let zero = WireMod2::rand(&mut self.rng, 2);
        let wirelabel = zero + self.delta * value;
        channel.write(&wirelabel.to_repr())?;

        Ok(AuthenticatedWire::new(constant, zero, share))
    }

    fn output(
        &mut self,
        x: &AuthenticatedWire,
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<u16>> {
        Ok(self
            .outputs(core::slice::from_ref(x), channel)?
            .map(|xs| xs[0]))
    }

    fn outputs(
        &mut self,
        x: &[AuthenticatedWire],
        channel: &mut Channel,
    ) -> swanky_error::Result<Option<Vec<u16>>> {
        let auth_shares = x.iter().map(|wire| wire.auth_share()).collect::<Vec<_>>();
        AuthShareGenerator::open_my_shares(&auth_shares, channel)?;
        Ok(None)
    }
}
