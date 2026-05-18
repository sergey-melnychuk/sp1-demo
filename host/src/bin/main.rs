use std::net::TcpStream;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;
use rustls::ClientConfig;
use sp1_sdk::{
    blocking::{Elf, ProveRequest, Prover, ProverClient, SP1Stdin},
    include_elf, ProvingKey, SP1ProofWithPublicValues,
};

use sp1_demo_host::{crypto::make_provider, stream::CapturingStream};
use sp1_demo_common::{PublicClaim, TlsWitness};

const ELF: Elf = include_elf!("sp1-demo-guest");

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

    let url = url::Url::parse(&args.url).context("invalid URL")?;
    let host = url.host_str().context("URL has no host")?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let path = if url.path().is_empty() { "/" } else { url.path() };
    let query_path = match url.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };

    fn keygen() -> ([u8; 32], [u8; 32]) {
        use x25519_dalek::{PublicKey, StaticSecret};
        let esk = StaticSecret::random_from_rng(rand::thread_rng());
        let epk = PublicKey::from(&esk);
        (esk.to_bytes(), *epk.as_bytes())
    }

    // -----------------------------------------------------------------------
    // Phase 1 — Key generation.
    // esk_client stays in memory; epk_client is injected into ClientHello.
    // -----------------------------------------------------------------------
    let (esk_client, epk_client) = keygen();
    eprintln!("phase 1: epk_client generated ({} bytes)", epk_client.len());

    // -----------------------------------------------------------------------
    // Phase 2 — TLS connection using the externally-generated key.
    //
    // TRUST NOTE: the host holds esk_client (phase 1) and, after the
    // handshake, raw_inbound containing epk_server. From these it can compute
    // shared_secret = X25519(esk_client, epk_server) and thus server_write_key.
    // A malicious host could forge application-data records. For self-proving
    // (user runs on their own machine) this is acceptable — the prover is the
    // user and has no incentive to forge their own data. Delegated proving
    // requires MPC-TLS or a TEE; see NEXT.md §6.5.
    // -----------------------------------------------------------------------
    let mut provider = make_provider(esk_client);
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];

    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();

    let server_name: rustls::pki_types::ServerName =
        host.clone().try_into().context("invalid server name")?;

    let tcp = TcpStream::connect(format!("{host}:{port}"))?;
    let mut stream = CapturingStream::new(tcp);

    let mut tls = rustls::ClientConnection::new(Arc::new(config), server_name)?;
    let mut joined = rustls::Stream::new(&mut tls, &mut stream);

    use std::io::Write;
    write!(
        joined,
        "GET {query_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: application/json\r\n\r\n"
    )?;

    use std::io::Read;
    let mut response_bytes = Vec::new();
    joined.read_to_end(&mut response_bytes)?;

    let response_str = String::from_utf8_lossy(&response_bytes);
    let body = response_str.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
    println!("Response: {body}");

    eprintln!(
        "phase 2: inbound={} bytes, outbound={} bytes",
        stream.inbound.len(),
        stream.outbound.len(),
    );

    // -----------------------------------------------------------------------
    // Phase 3 — Assemble witness and run SP1 guest.
    // The host provides only esk_client and raw wire bytes.
    // The guest derives all keys and parses all messages independently.
    // -----------------------------------------------------------------------
    let witness = TlsWitness {
        esk_client,
        raw_inbound: stream.inbound,
        raw_outbound: stream.outbound,
        hostname: host.clone(),
        json_field: args.field.clone(),
        threshold: args.threshold,
    };

    let mut stdin = SP1Stdin::new();
    stdin.write(&witness);

    let prover = ProverClient::from_env();

    if args.prove {
        let pk = prover.setup(ELF)?;
        let proof: SP1ProofWithPublicValues = prover.prove(&pk, stdin).compressed().run()?;
        let proof_path = "proof.bin";
        proof.save(proof_path)?;
        println!("Proof saved to {proof_path}");

        let proof = SP1ProofWithPublicValues::load(proof_path)?;
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
