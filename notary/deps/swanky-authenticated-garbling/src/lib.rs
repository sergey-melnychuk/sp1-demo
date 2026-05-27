#![deny(missing_docs)]
//! Authenticated malicious garbling in the presence of a malicious garbler and evaluator

use swanky_party::party_system;

mod evaluator;
pub use evaluator::Evaluator;
mod garbler;
pub use garbler::Garbler;
mod preprocesser;
pub use preprocesser::{preprocess_circuit, WirePreProcessor};
mod tests;
mod wire;
pub use wire::AuthenticatedWireMod2;

// Party system type aliases for the garbler and evaluator
party_system! {
    pub mod ps {
        ///Type alias for the Garbler
        PartyGarbler,
        ///Type alias for the Evaluator
        PartyEvaluator,
    }
}
