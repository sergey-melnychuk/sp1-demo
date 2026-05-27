use crate::{
    preprocesser::{preprocess_circuit, WirePreProcessor},
    ps::PartyEvaluator,
    wire::AuthenticatedWireMod2,
};
use fancy_garbling::{
    circuit::CircuitExecutor, circuit_analyzer::CircuitAnalyzer, Fancy, FancyBinary, WireLabel,
    WireMod2,
};
use rand::{CryptoRng, RngCore};
use swanky_authenticated_bits::{
    and_triples::AndTripleGenerator,
    authshares::{AuthShare, AuthShareGenerator},
};
use swanky_channel::Channel;
use swanky_error::{ensure, ErrorKind};
use swanky_field::FiniteRing;
use swanky_field_binary::{F128b, F2};
use vectoreyes::U8x16;

type AuthenticatedWire = AuthenticatedWireMod2<PartyEvaluator>;

/// The authenticated evaluator.
pub struct Evaluator {
    // The evaluator's Δ, used to validate the authenticated shares and AND
    // triples.
    delta: U8x16,
    /// A wirelabel denoting one. Used to make negations free.
    one: WireMod2,
    // The index of the current AND gate. Used as the tweak when hashing
    // wirelabels in the AND gate garbling.
    and_wire_index: usize,
    // A vector of authenticated shares, one per input wire and AND gate output.
    // Corresponds to〈r_w, s_w〉from the paper.
    auth_shares: Vec<AuthShare<PartyEvaluator>>,
    // The index of the current authenticated share we're using.
    auth_shares_index: usize,
    // A vector of fixed authenticated shares for AND gate wires. Each share is
    // set such that it is equal to the AND of the incoming wire shares.
    // Corresponds to〈r_w^*, s_w^*〉from the paper.
    and_auth_shares: Vec<AuthShare<PartyEvaluator>>,
    // The index of the current AND authenticated share we're using.
    and_auth_shares_index: usize,
}

impl Evaluator {
    /// Create a new evaluator for the given circuit.
    pub fn new<
        C: CircuitExecutor<CircuitAnalyzer> + CircuitExecutor<WirePreProcessor<PartyEvaluator>>,
        RNG: CryptoRng + RngCore,
    >(
        circuit: &C,
        channel: &mut Channel,
        rng: &mut RNG,
    ) -> swanky_error::Result<Self> {
        let delta = AndTripleGenerator::<PartyEvaluator>::generate_valid_delta(rng);

        let mut and_generator = AndTripleGenerator::new_with_delta(delta, channel, rng)?;
        let (auth_shares, and_auth_shares) =
            preprocess_circuit(circuit, &mut and_generator, channel, rng)?;

        let one = channel.read::<U8x16>()?;
        Ok(Evaluator {
            delta,
            one: WireMod2::from_repr(one, 2),
            and_wire_index: 0,
            auth_shares,
            auth_shares_index: 0,
            and_auth_shares,
            and_auth_shares_index: 0,
        })
    }

    /// Create an evaluator while reusing OT material from `and_generator`.
    pub fn new_with_and_generator<
        C: CircuitExecutor<CircuitAnalyzer> + CircuitExecutor<WirePreProcessor<PartyEvaluator>>,
        RNG: CryptoRng + RngCore,
    >(
        circuit: &C,
        channel: &mut Channel,
        rng: &mut RNG,
        and_generator: &mut AndTripleGenerator<PartyEvaluator>,
    ) -> swanky_error::Result<Self> {
        let delta = and_generator.delta();
        let (auth_shares, and_auth_shares) =
            preprocess_circuit(circuit, and_generator, channel, rng)?;
        let one = channel.read::<U8x16>()?;
        Ok(Evaluator {
            delta,
            one: WireMod2::from_repr(one, 2),
            and_wire_index: 0,
            auth_shares,
            auth_shares_index: 0,
            and_auth_shares,
            and_auth_shares_index: 0,
        })
    }

    /// The current output index of the garbling computation.
    fn next_and_wire_index(&mut self) -> usize {
        let current = self.and_wire_index;
        self.and_wire_index += 1;
        current
    }

    fn next_auth_share(&mut self) -> AuthShare<PartyEvaluator> {
        let share = self.auth_shares[self.auth_shares_index];
        self.auth_shares_index += 1;
        share
    }

    fn next_and_auth_share(&mut self) -> AuthShare<PartyEvaluator> {
        let share = self.and_auth_shares[self.and_auth_shares_index];
        self.and_auth_shares_index += 1;
        share
    }

    /// Receive wirelabel `L_w` from the garbler, where `w` represents the
    /// masked value of the wire.
    ///
    /// This corresponds to pieces of Steps 3 and 4 in Figure 3 of the paper.
    fn receive_wirelabels(
        &mut self,
        masked_values: Vec<F2>,
        auth_shares: Vec<AuthShare<PartyEvaluator>>,
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<AuthenticatedWire>> {
        let mut wires: Vec<AuthenticatedWire> = Vec::with_capacity(masked_values.len());
        for (masked_value, auth_share) in masked_values.into_iter().zip(auth_shares) {
            // The Evaluator retrieves the wire labels for their own input
            let wire_label = WireMod2::from_repr(channel.read()?, 2);
            // The Evaluator constructs authenticated values for all their input wires
            wires.push(AuthenticatedWire::new(masked_value, wire_label, auth_share));
        }
        Ok(wires)
    }
}

impl FancyBinary for Evaluator {
    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        AuthenticatedWire::new(
            x.masked_value() + F2::ONE,
            x.wire_label() + self.one,
            x.auth_share(),
        )
    }

    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        AuthenticatedWire::new(
            x.masked_value() + y.masked_value(),
            x.wire_label() + y.wire_label(),
            x.auth_share() ^ y.auth_share(),
        )
    }

    fn and(
        &mut self,
        la: &Self::Item,
        lb: &Self::Item,
        channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        // This index is called γ in the paper
        let index = self.next_and_wire_index();
        // This is the current wire's authenticated share
        let lc_share = self.next_auth_share();
        // This is the current wire's authenticated triple
        let lc_triple = self.next_and_auth_share();

        // This is the MAC associated with the current wire's authenticated share: M[s_γ]
        let mac_share = lc_share.mac();
        // This is the MAC associated with the current wire's authenticated triple: M[s*_γ]
        let mac_triple = lc_triple.mac();

        // This is the value: Gate_{γ,0}
        let gate_c0: U8x16 = channel.read()?;
        // This is the value: Gate_{γ,1}
        let gate_c1: U8x16 = channel.read()?;
        // This is the value: b_γ
        let bit_c: F2 = channel.read()?;

        // This is the value: Gate_0 = Gate_{γ,0} + M[s_β]
        let gate0 = gate_c0 ^ lb.auth_share().mac();
        // This is the value: Gate_1 = Gate_{γ,1} + M[s_α]
        let gate1 = gate_c1 ^ la.auth_share().mac();

        // This is the value H(L_{α, z_α + λ_α}, γ)
        let h_la = la.wire_label().hash(index as u128);
        // This is the value H(L_{β, z_β + λ_β}, γ)
        let h_lb = lb.wire_label().hash(index as u128);

        // z'α := z_α + λ_α, where z_α is the actual wire value of the input
        // wire with label L_α and λ_α is the mask of that value
        let la_value = la.masked_value();
        // The Evaluator's authenticated share of λ_α
        let la_lambda = la.auth_share();
        // z'β := z_β + λ_β, where z_β is the actual wire value of the input
        // wire with label L_β and λ_β is the mask of that value
        let lb_value = lb.masked_value();
        // The Evaluator's authenticated share of λ_β
        let lb_lambda = lb.auth_share();

        // This is the value (z_α + λ_α)Gate_0
        let gate0_muxed = U8x16::from(la_value * F128b::from(gate0));
        // This is the value (z_β + λ_β)(Gate_1 + L_{α, z_α + λ_α})
        let gate1_muxed = U8x16::from(lb_value * F128b::from(gate1 ^ la.wire_label().to_repr()));

        // This the value:
        //  L_{γ, z_γ + λ_γ} := H(L_{α, z_α + λ_α}, γ) + H(L_{β, z_β + λ_β}, γ) + M[s_γ]
        //                      + M[s*_γ] + (z_α + λ_α)Gate_0 + (z_β + λ_β)(Gate_1 + L_{α, z_α + λ_α})
        let lc_label = h_la ^ h_lb ^ mac_share ^ mac_triple ^ gate0_muxed ^ gate1_muxed;

        // The current masked value of the wire is:
        // z'γ := z_γ + λ_γ := b_γ + lsb(L_{γ, z_γ + λ_γ})
        let lc_value = F128b::from(lc_label).lsb() + bit_c;

        // The Evaluator sends out the masked bit z'γ so that the Garbler
        // can locally compute their share of c_γ
        channel.write(&lc_value)?;

        // The Evaluator computes its share of the validation bit
        // c_γ :=  (z'α ⊕ λ_α) ∧ (z'β ⊕ λ_β ) ⊕ (z'γ ⊕ λ_γ )
        //     := (z'α z'β ⊕ z'β λ_α ⊕ z'α λ_β ⊕ λ_α λ_β) ⊕ (z'γ ⊕ λ_γ )
        //     := (z'α z'β ⊕ z'γ ) ⊕ (z'β λ_α ⊕ z'α λ_β ⊕ λ*_γ ⊕ λ_γ)

        // The Evaluator first creates the constant share of (z'α z'β ⊕ z'γ )
        let share_masks =
            AuthShareGenerator::constant_with_delta(la_value * lb_value + lc_value, self.delta);
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
            self.delta,
            &mut validation_bit,
            channel,
        )?;

        ensure!(
            validation_bit[0] == F2::ZERO,
            ErrorKind::OtherError,
            "Evaluator's authentication validation check failed at index {index}"
        );

        Ok(AuthenticatedWire::new(
            lc_value,
            WireMod2::from_repr(lc_label, 2),
            lc_share,
        ))
    }
}

impl Fancy for Evaluator {
    type Item = AuthenticatedWire;

    fn encode_many(
        &mut self,
        values: &[u16],
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        assert_eq!(values.len(), moduli.len());

        // Grab authenticated shares for each of the inputs.
        let my_auth_shares = (0..moduli.len())
            .map(|_| self.next_auth_share())
            .collect::<Vec<_>>();

        // Open the garbler's shares `[r_w]`.
        let mut their_bits = Vec::with_capacity(moduli.len());
        AuthShareGenerator::open_their_shares_with_delta(
            &my_auth_shares,
            self.delta,
            &mut their_bits,
            channel,
        )?;

        // Compute masked values `y_w ⊕ λ_w := y_w ⊕ (s_w ⊕ r_w)`.
        let my_masked_values = their_bits
            .into_iter()
            .zip(my_auth_shares.iter().zip(values.iter()))
            .map(|(theirs, (mine, value))| {
                F2::try_from(*value).expect("Invalid value, must be boolean") + mine.bit() + theirs
            })
            .collect::<Vec<_>>();
        for masked_value in my_masked_values.iter() {
            channel.write(masked_value)?;
        }

        self.receive_wirelabels(my_masked_values, my_auth_shares, channel)
    }

    fn receive_many(
        &mut self,
        moduli: &[u16],
        channel: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        // Grab authenticated shares for each of the inputs.
        let my_auth_shares = (0..moduli.len())
            .map(|_i| self.next_auth_share())
            .collect::<Vec<_>>();

        // Open the evaluator's shares `[s_w]`.
        AuthShareGenerator::open_my_shares(&my_auth_shares, channel)?;

        // Receive `x_w ⊕ λ_w` from the garbler.
        let masked_values = (0..moduli.len())
            .map(|_| channel.read::<F2>())
            .collect::<swanky_error::Result<Vec<_>>>()?;

        self.receive_wirelabels(masked_values, my_auth_shares, channel)
    }

    fn constant(
        &mut self,
        value: u16,
        _q: u16,
        channel: &mut Channel,
    ) -> swanky_error::Result<AuthenticatedWire> {
        let constant = F2::try_from(value).expect("constant must be boolean");
        let share = AuthShareGenerator::constant_with_delta(F2::ZERO, self.delta);

        let wirelabel = WireMod2::from_repr(channel.read()?, 2);

        Ok(AuthenticatedWire::new(constant, wirelabel, share))
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
        let mut masks = Vec::with_capacity(x.len());
        AuthShareGenerator::open_their_shares_with_delta(
            &auth_shares,
            self.delta,
            &mut masks,
            channel,
        )?;
        let outputs = masks
            .into_iter()
            .zip(x)
            .map(|(mask, out)| (mask + out.masked_value() + out.auth_share().bit()).into())
            .collect::<Vec<_>>();
        Ok(Some(outputs))
    }
}
