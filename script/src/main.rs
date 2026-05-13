use anyhow::Result;
use clap::Parser;
use sp1_sdk::{
    blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin},
    include_elf, ProvingKey, SP1ProofWithPublicValues,
};

const ELF: Elf = include_elf!("sp1-https-json-program");

#[derive(Parser, Debug)]
struct Args {
    /// HTTPS URL to GET
    #[arg(long)]
    url: String,

    /// RFC 6901 JSON Pointer to the field to check, e.g. "/price"
    #[arg(long)]
    field: String,

    /// Threshold: assert field > threshold
    #[arg(long)]
    threshold: f64,

    /// If set, generate a full STARK proof; otherwise just execute (faster for dev)
    #[arg(long)]
    prove: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // -----------------------------------------------------------------------
    // 1. Make the HTTPS GET on the host side.
    // -----------------------------------------------------------------------

    let response_text = reqwest::blocking::Client::builder()
        .use_rustls_tls()
        .build()?
        .get(&args.url)
        .send()?
        .error_for_status()?
        .text()?;

    println!("Response body: {}", response_text);

    // -----------------------------------------------------------------------
    // 2. Write inputs to the guest stdin.
    // -----------------------------------------------------------------------

    let mut stdin = SP1Stdin::new();
    stdin.write(&response_text);
    stdin.write(&args.field);
    stdin.write(&args.threshold);

    // -----------------------------------------------------------------------
    // 3. Execute or prove.
    // -----------------------------------------------------------------------

    let prover = ProverClient::from_env();

    if args.prove {
        let pk = prover.setup(ELF)?;
        let proof: SP1ProofWithPublicValues = prover.prove(&pk, stdin)
            .compressed()
            .run()?;
        let proof_path = "proof.bin";
        proof.save(proof_path)?;
        println!("Proof saved to {proof_path}");
        let proof = SP1ProofWithPublicValues::load(proof_path)?;
        prover.verify(&proof, pk.verifying_key(), None)?;

        let mut pv = proof.public_values.clone();
        let field: String = pv.read();
        let threshold: f64 = pv.read();
        let value: f64 = pv.read();

        println!("Proof verified.");
        println!("   field:     {}", field);
        println!("   threshold: {}", threshold);
        println!("   value:     {}", value);
    } else {
        let (mut pv, report) = prover.execute(ELF, stdin).run()?;

        let field: String = pv.read();
        let threshold: f64 = pv.read();
        let value: f64 = pv.read();

        println!("Execution succeeded (no proof generated).");
        println!("   field:     {}", field);
        println!("   threshold: {}", threshold);
        println!("   value:     {}", value);
        println!("   cycles:    {}", report.total_instruction_count());
    }

    Ok(())
}
