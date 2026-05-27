use fancy_garbling::{Fancy, FancyBinary, HasModulus};
use swanky_authenticated_bits::authshares::{AuthShare, AuthShareGenerator};
use swanky_channel::Channel;
use swanky_field::FiniteRing;
use swanky_field_binary::F2;
use swanky_party::GenericParty;
use vectoreyes::U8x16;

/// A thin wrapper around an [`AuthShare`] for use as a [`Fancy`] object.
///
/// This is used to determine the [`AuthShare`] inputs to AND gates. This is
/// important because one of the assumptions that KRRW18 makes and does not
/// explicitly state is that once the authenticate shares are generated during
/// pre-processing, the garbler has to construct the authenticated share of XOR
/// and Negation gates during pre-processing in order to correctly produce known
/// AND gates.
#[derive(Clone, Copy)]
pub struct PreProcessedWire<P: GenericParty> {
    auth_share: AuthShare<P>,
}

impl<P: GenericParty> PreProcessedWire<P> {
    /// Construct a new [`PreProcessedWire`] from an authenticated share.
    pub(crate) fn new(auth_share: AuthShare<P>) -> Self {
        PreProcessedWire { auth_share }
    }
}

impl<P: GenericParty> HasModulus for PreProcessedWire<P> {
    fn modulus(&self) -> u16 {
        2
    }
}
/// A struct which allows us to correctly correlate the indices
/// of the input wires of an AND gate, to the index of the output
/// wire of that gate. This is required in order to figure out how
/// to turn random and triples into known ones since it allows us to
/// figure out which pairs of wires need to be correlated together.
#[derive(Clone)]
pub struct WirePreProcessor<P: GenericParty> {
    auth_shares: Vec<AuthShare<P>>,
    auth_shares_index: usize,
    and_gate_left_inputs: Vec<AuthShare<P>>,
    and_gate_right_inputs: Vec<AuthShare<P>>,
    delta: U8x16,
}

impl<P: GenericParty> WirePreProcessor<P> {
    /// Construct a new [`WirePreProcessor`] using a vector of [`AuthShare`]s
    /// which equals the number of AND, Input, and Constant gates in the
    /// circuit.
    pub(crate) fn new(auth_shares: Vec<AuthShare<P>>, delta: U8x16) -> WirePreProcessor<P> {
        WirePreProcessor {
            auth_shares,
            auth_shares_index: 0,
            and_gate_left_inputs: Vec::new(),
            and_gate_right_inputs: Vec::new(),
            delta,
        }
    }
    /// Return the [`AuthShare`]s associated with the input wires of each AND
    /// gate, consuming itself. These shares are split according to whether they
    /// are the left or right wires of a gate.
    pub(crate) fn into_and_gate_input_shares(self) -> (Vec<AuthShare<P>>, Vec<AuthShare<P>>) {
        (self.and_gate_left_inputs, self.and_gate_right_inputs)
    }

    /// Return the next [`AuthShare`] from the vector of authenticated shares.
    fn next_auth_share(&mut self) -> AuthShare<P> {
        let authshare = self.auth_shares[self.auth_shares_index];
        self.auth_shares_index += 1;
        authshare
    }
}

impl<P: GenericParty> FancyBinary for WirePreProcessor<P> {
    fn xor(&mut self, x: &Self::Item, y: &Self::Item) -> Self::Item {
        PreProcessedWire::new(x.auth_share ^ y.auth_share)
    }

    fn and(
        &mut self,
        x: &Self::Item,
        y: &Self::Item,
        _channel: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        self.and_gate_left_inputs.push(x.auth_share);
        self.and_gate_right_inputs.push(y.auth_share);

        let authshare = self.next_auth_share();
        Ok(PreProcessedWire::new(authshare))
    }

    fn negate(&mut self, x: &Self::Item) -> Self::Item {
        *x
    }
}

impl<P: GenericParty> Fancy for WirePreProcessor<P> {
    type Item = PreProcessedWire<P>;

    fn receive_many(
        &mut self,
        moduli: &[u16],
        _: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        Ok((0..moduli.len())
            .map(|_| {
                let auth_share = self.next_auth_share();
                PreProcessedWire::new(auth_share)
            })
            .collect())
    }

    fn encode_many(
        &mut self,
        _: &[u16],
        _: &[u16],
        _: &mut Channel,
    ) -> swanky_error::Result<Vec<Self::Item>> {
        unimplemented!("Preprocessor cannot encode values");
    }

    fn constant(
        &mut self,
        value: u16,
        modulus: u16,
        _: &mut Channel,
    ) -> swanky_error::Result<Self::Item> {
        assert!(value == 0 || value == 1);
        assert_eq!(modulus, 2);

        let authshare = AuthShareGenerator::constant_with_delta(F2::ZERO, self.delta);
        Ok(PreProcessedWire::new(authshare))
    }

    fn output(&mut self, _: &Self::Item, _: &mut Channel) -> swanky_error::Result<Option<u16>> {
        Ok(None)
    }
}
