#![cfg(test)]

use crate::garbler::Garbler;
use crate::ps::{PartyEvaluator, PartyGarbler};
use crate::{evaluator::Evaluator, preprocesser::WirePreProcessor};

use fancy_garbling::{
    circuit::{circuits, CircuitExecutor},
    circuit_analyzer::CircuitAnalyzer,
    dummy::Dummy,
    Fancy,
};
use rand::Rng;
use swanky_rng::SwankyRng;

#[test]
fn test_party_construction_passes() {
    let input_size = 400;
    let circuit = circuits::binary::TestAndGateFanN(input_size);
    swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            Garbler::new(&circuit, c, rng)
        },
        |c| {
            let mut rng = SwankyRng::new();
            Evaluator::new(&circuit, c, &mut rng)
        },
    )
    .unwrap();
}

fn test_circuit<
    C: CircuitExecutor<CircuitAnalyzer>
        + CircuitExecutor<WirePreProcessor<PartyGarbler>>
        + CircuitExecutor<WirePreProcessor<PartyEvaluator>>
        + CircuitExecutor<Garbler<SwankyRng>>
        + CircuitExecutor<Evaluator>
        + CircuitExecutor<Dummy>
        + Sync,
>(
    ninputs_gb: usize,
    ninputs_ev: usize,
    circuit: &C,
) {
    assert_eq!(
        ninputs_gb + ninputs_ev,
        <C as CircuitExecutor<Dummy>>::ninputs(circuit)
    );

    let mut rng = SwankyRng::new();
    let inputs_gb: Vec<u16> = (0..ninputs_gb).map(|_| rng.r#gen::<u16>() % 2).collect();
    let inputs_ev: Vec<u16> = (0..ninputs_ev).map(|_| rng.r#gen::<u16>() % 2).collect();

    let inputs = [inputs_gb.clone(), inputs_ev.clone()].concat();
    let expected = Dummy::eval(circuit, &inputs).unwrap();

    let (outputs_gb, outputs_ev) = swanky_channel::local::local_channel_pair(
        |c| {
            let rng = SwankyRng::new();
            let mut gb = Garbler::new(circuit, c, rng)?;
            let mut inputs = gb.encode_many(&inputs_gb, &vec![2; ninputs_gb], c)?;
            let theirs = gb.receive_many(&vec![2; ninputs_ev], c)?;
            inputs.extend(theirs);
            let outputs = circuit.execute(&mut gb, &inputs, c)?;
            gb.outputs(&outputs, c)
        },
        |c| {
            let mut rng = SwankyRng::new();
            let mut ev = Evaluator::new(circuit, c, &mut rng)?;
            let mut inputs = ev.receive_many(&vec![2; ninputs_gb], c)?;
            let mine = ev.encode_many(&inputs_ev, &vec![2; ninputs_ev], c)?;
            inputs.extend(mine);
            let outputs = circuit.execute(&mut ev, &inputs, c)?;
            ev.outputs(&outputs, c)
        },
    )
    .unwrap();
    assert!(outputs_gb.is_none());
    let outputs = outputs_ev.unwrap();
    assert_eq!(outputs, expected)
}

#[test]
fn test_input_output_garbler() {
    let ninputs_gb = 128;
    let ninputs_ev = 0;
    let circuit = circuits::fancy::TestBinaryOutputs(ninputs_gb + ninputs_ev);

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_input_output_evaluator() {
    let ninputs_gb = 0;
    let ninputs_ev = 128;
    let circuit = circuits::fancy::TestBinaryOutputs(ninputs_gb + ninputs_ev);

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_input_output() {
    let ninputs_gb = 128;
    let ninputs_ev = 128;
    let circuit = circuits::fancy::TestBinaryOutputs(ninputs_gb + ninputs_ev);

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_and_gate() {
    let ninputs_gb = 1;
    let ninputs_ev = 1;
    let circuit = circuits::binary::TestAndGate;

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_negate_gate_garbler() {
    let ninputs_gb = 1;
    let ninputs_ev = 0;
    let circuit = circuits::binary::TestNegateGate;

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_negate_gate_evaluator() {
    let ninputs_gb = 0;
    let ninputs_ev = 1;
    let circuit = circuits::binary::TestNegateGate;

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_constant_gates() {
    let circuit = circuits::fancy::TestBinaryConstant;

    test_circuit(0, 0, &circuit);
}

#[test]
fn test_and_gate_fan_n() {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = circuits::binary::TestAndGateFanN(ninputs_gb + ninputs_ev);

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_or_gate_fan_n() {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = circuits::binary::TestOrGateFanN(ninputs_gb + ninputs_ev);

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_xor_gate_fan_n() {
    let ninputs_gb = 400;
    let ninputs_ev = 400;
    let circuit = circuits::binary::TestXorGateFanN(ninputs_gb + ninputs_ev);

    test_circuit(ninputs_gb, ninputs_ev, &circuit);
}

#[test]
fn test_binary_addition() {
    let ninputs = 400;
    let circuit = circuits::binary_gadgets::TestBinaryAddition(ninputs);

    test_circuit(ninputs, ninputs, &circuit);
}

#[test]
fn test_binary_negate() {
    let ninputs = 64;
    let circuit = circuits::binary::TestBinaryNegate(ninputs);

    test_circuit(ninputs / 2, ninputs / 2, &circuit);
}

#[test]
fn test_constant_bundle() {
    let circuit = circuits::binary_gadgets::TestConstantBundle(1, 64);

    test_circuit(0, 0, &circuit);
}

#[test]
fn test_bin_addition_no_carry() {
    let ninputs = 64;
    let circuit = circuits::binary_gadgets::TestBinaryAdditionNoCarry(ninputs);

    test_circuit(ninputs, ninputs, &circuit);
}

#[test]
fn test_bin_twos_complement() {
    let ninputs = 64;
    let circuit = circuits::binary_gadgets::TestBinaryTwosComplement(ninputs);

    test_circuit(ninputs, 0, &circuit);
}

#[test]
fn test_binary_subtraction() {
    let ninputs = 64;
    let circuit = circuits::binary_gadgets::TestBinarySubtraction(ninputs);

    test_circuit(ninputs, ninputs, &circuit);
}

#[test]
fn test_binary_multiplication() {
    let ninputs = 64;
    let circuit = circuits::binary_gadgets::TestBinaryMultiplication(ninputs);

    test_circuit(ninputs, ninputs, &circuit);
}
