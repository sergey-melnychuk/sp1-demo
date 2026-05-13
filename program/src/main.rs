#![no_main]
sp1_zkvm::entrypoint!(main);

use serde_json::Value;

pub fn main() {
    // --- Inputs from the host prover ---

    // Raw HTTP response body (UTF-8 JSON string)
    let body: String = sp1_zkvm::io::read();

    // JSON pointer to the field, e.g. "/price" or "/data/result"
    // Uses RFC 6901 JSON Pointer syntax supported by serde_json.
    let field_pointer: String = sp1_zkvm::io::read();

    // The threshold value to assert against
    let threshold: f64 = sp1_zkvm::io::read();

    // --- Parse ---

    let json: Value = serde_json::from_str(&body)
        .expect("response is not valid JSON");

    let field_value = json
        .pointer(&field_pointer)
        .unwrap_or_else(|| panic!("field '{}' not found in response", field_pointer))
        .as_str()
        .unwrap_or_else(|| panic!("field '{}' not a string literal", field_pointer));

    let field_value: f64 = field_value.parse().expect("field is not a number");

    // --- Assert ---

    assert!(
        field_value > threshold,
        "assertion failed: {} = {} is not > {}",
        field_pointer,
        field_value,
        threshold
    );

    // --- Commit public outputs ---
    // These are visible to the verifier on-chain / off-chain.

    sp1_zkvm::io::commit(&field_pointer);
    sp1_zkvm::io::commit(&threshold);
    sp1_zkvm::io::commit(&field_value);
}
