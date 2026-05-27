//! Load a notary-produced `TlsWitness` from a file and drive the SP1 guest.
//!
//! The witness is produced by `notary_demo --witness-out <path>` in the
//! `notary` crate (separate workspace; that crate carries the swanky MPC
//! deps which conflict with sp1-sdk's `generic-array` pin, so the handoff
//! is via a bincode file rather than a direct Rust dep).

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use sp1_demo_common::{PublicClaim, TlsWitness};
use sp1_sdk::{
    blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin},
    include_elf, ProvingKey, SP1ProofWithPublicValues,
};

const ELF: Elf = include_elf!("sp1-demo-guest");

#[derive(Parser, Debug)]
#[command(about = "Drive SP1 with a notary-produced TlsWitness")]
struct Args {
    /// Path to the bincode-encoded `TlsWitness` (produced by `notary_demo`).
    #[arg(long)]
    witness_in: PathBuf,

    /// Generate a STARK proof in addition to executing.
    #[arg(long)]
    prove: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    eprintln!("loading witness from {}", args.witness_in.display());
    let bytes = fs::read(&args.witness_in)
        .with_context(|| format!("read {}", args.witness_in.display()))?;
    let witness: TlsWitness = bincode::deserialize(&bytes).context("decode TlsWitness")?;

    eprintln!(
        "witness loaded: host={} field={} threshold={} inbound={} outbound={} notary={}",
        witness.hostname,
        witness.json_field,
        witness.threshold,
        witness.raw_inbound.len(),
        witness.raw_outbound.len(),
        witness.notary.is_some(),
    );

    if let Some(att) = &witness.notary {
        eprintln!(
            "  notary pubkey={} records={} verify={}",
            hex_encode(&att.bundle.notary_pubkey),
            att.bundle.records.len(),
            att.bundle.verify()
        );
        if !att.bundle.verify() {
            anyhow::bail!("notary bundle signature did not verify");
        }
    }

    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);

    let prover = ProverClient::from_env();

    if args.prove {
        let pk = prover.setup(ELF)?;
        let proof: SP1ProofWithPublicValues = prover.prove(&pk, stdin).compressed().run()?;
        let proof_path = "proof.bin";
        proof.save(proof_path)?;
        prover.verify(&proof, pk.verifying_key(), None)?;
        let mut pv = proof.public_values.clone();
        let claim: PublicClaim = pv.read();
        println!("Proof verified.");
        println!("   host:      {}", claim.host);
        println!("   field:     {}", claim.field);
        println!("   threshold: {}", claim.threshold);
        println!("   value:     {}", claim.value);
    } else {
        let (mut pv, report) = prover.execute(ELF, stdin).run()?;
        let claim: PublicClaim = pv.read();
        println!("Execution succeeded (no proof generated).");
        println!("   host:      {}", claim.host);
        println!("   field:     {}", claim.field);
        println!("   threshold: {}", claim.threshold);
        println!("   value:     {}", claim.value);
        println!("   cycles:    {}", report.total_instruction_count());
    }

    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
