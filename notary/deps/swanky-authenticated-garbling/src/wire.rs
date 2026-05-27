//! Wirelabel representation for authenticated garbling.

use fancy_garbling::{HasModulus, WireMod2};
use swanky_authenticated_bits::authshares::AuthShare;
use swanky_field_binary::F2;
use swanky_party::GenericParty;

/// Wirelabel representation for authenticated garbling.
///
/// An authenticated garbling wirelabel is a wirelabel $`L`$ alongside (1) an
/// [`AuthShare`] $`\lambda`$ of $`L`$s color bit, and (2) an optional value
/// representing the masked value $`w \oplus \lambda`$, where $`w`$ is the
/// actual bit represented by the wirelabel.
#[derive(Clone)]
pub struct AuthenticatedWireMod2<P: GenericParty> {
    /// Masked value $`w \oplus \lambda`$.
    masked_value: F2,
    /// The wirelabel $`L`$.
    wire_label: WireMod2,
    /// Sharing of the color bit $`\lambda`$.
    auth_share: AuthShare<P>,
}

impl<P: GenericParty> AuthenticatedWireMod2<P> {
    /// Create a new `AuthenticatedWireMod2` given a masked value, the underlying wirelabel
    /// $`L`$, and its associated color bit share $`\langle \lambda \rangle`$.
    pub(crate) fn new(masked_value: F2, wire_label: WireMod2, auth_share: AuthShare<P>) -> Self {
        AuthenticatedWireMod2 {
            masked_value,
            wire_label,
            auth_share,
        }
    }

    /// The masked value associated with this wire.
    pub(crate) fn masked_value(&self) -> F2 {
        self.masked_value
    }

    /// The wirelabel $`L`$ associated with this wire.
    pub(crate) fn wire_label(&self) -> WireMod2 {
        self.wire_label
    }

    /// The authenticated share $`\langle \lambda \rangle`$ associated with this
    /// wire.
    pub(crate) fn auth_share(&self) -> AuthShare<P> {
        self.auth_share
    }
}

impl<P: GenericParty> HasModulus for AuthenticatedWireMod2<P> {
    fn modulus(&self) -> u16 {
        2
    }
}
