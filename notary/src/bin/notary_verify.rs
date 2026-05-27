//! Standalone verifier for Ed25519-signed notary session bundles.
//!
//! Verifies the signature and optionally cross-checks witness-path binding fields
//! against raw TLS handshake bytes supplied on the command line.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use notary::ecdh::parse_server_hello_key_share;
use notary::handshake::handshake_transcript_hash;
use sp1_demo_common::{NotaryBundle, SessionBinding};

#[derive(Parser, Debug)]
#[command(about = "Verify a notary session bundle (Ed25519 + optional handshake binding)")]
struct Args {
    /// Path to bincode-serialized [`NotaryBundle`].
    #[arg(long)]
    bundle: PathBuf,

    /// Optional raw outbound handshake bytes (ClientHello + ClientFinished region).
    #[arg(long)]
    outbound: Option<PathBuf>,

    /// Optional raw inbound handshake bytes (ServerHello through ServerFinished region).
    #[arg(long)]
    inbound: Option<PathBuf>,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn print_binding(b: &SessionBinding) {
    println!("  server_epk:                 {}", hex(&b.server_epk));
    println!("  cert_chain_hash:            {}", hex(&b.cert_chain_hash));
    println!(
        "  handshake_transcript_hash:  {}",
        hex(&b.handshake_transcript_hash)
    );
    println!(
        "  key_schedule_context_hash:  {}",
        hex(&b.key_schedule_context_hash)
    );
    println!(
        "  circuit_aes_sha256:         {}",
        hex(&b.circuit_aes_sha256)
    );
    println!(
        "  circuit_sha256_compress:    {}",
        hex(&b.circuit_sha256_compress_sha256)
    );
    let mode_label = match b.garbling_mode {
        3 => "WRK17 HKDF+AES+GHASH",
        2 => "WRK17 HKDF+AES (GHASH semi-honest)",
        1 => "WRK17 HKDF only",
        _ => "legacy/semi-honest",
    };
    println!(
        "  garbling_mode:              {} ({})",
        b.garbling_mode, mode_label
    );
}

fn main() -> Result<()> {
    let args = Args::parse();
    let raw =
        fs::read(&args.bundle).with_context(|| format!("read bundle {}", args.bundle.display()))?;
    let bundle: NotaryBundle =
        bincode::deserialize(&raw).context("bincode deserialize NotaryBundle")?;

    println!("--- notary bundle ---");
    println!("  bundle_version: {}", bundle.bundle_version);
    println!("  notary_pubkey:  {}", hex(&bundle.notary_pubkey));
    println!("  timestamp_unix: {}", bundle.timestamp_unix);
    println!("  session_id:     {}", bundle.session_id);
    println!("  server_name:    {}", bundle.server_name);
    println!("  records:        {}", bundle.records.len());
    for r in &bundle.records {
        let op = match r.op {
            0x01 => "encrypt",
            0x02 => "decrypt",
            _ => "?",
        };
        println!(
            "    [{op}] seq={} aad_len={} commit={}",
            r.seq,
            r.aad.len(),
            hex(&r.commit_hash)
        );
    }

    if bundle.bundle_version >= NotaryBundle::BUNDLE_VERSION_BINDING {
        println!("--- session binding (signed) ---");
        print_binding(&bundle.binding);
    }

    let sig_ok = bundle.verify();
    println!("  signature verify: {}", if sig_ok { "OK" } else { "FAIL" });
    if !sig_ok {
        bail!("bundle signature verification failed");
    }

    if bundle.bundle_version >= NotaryBundle::BUNDLE_VERSION_BINDING
        && let (Some(out_path), Some(in_path)) = (&args.outbound, &args.inbound)
    {
        let outbound =
            fs::read(out_path).with_context(|| format!("read outbound {}", out_path.display()))?;
        let inbound =
            fs::read(in_path).with_context(|| format!("read inbound {}", in_path.display()))?;
        let ht = handshake_transcript_hash(&outbound, &inbound);
        if ht != bundle.binding.handshake_transcript_hash {
            bail!(
                "handshake_transcript_hash mismatch: bundle={} recomputed={}",
                hex(&bundle.binding.handshake_transcript_hash),
                hex(&ht)
            );
        }
        let epk = parse_server_hello_key_share(&inbound).context("parse ServerHello epk")?;
        if epk != bundle.binding.server_epk {
            bail!(
                "server_epk mismatch: bundle={} parsed={}",
                hex(&bundle.binding.server_epk),
                hex(&epk)
            );
        }
        println!("--- witness cross-check ---");
        println!("  handshake_transcript_hash: OK");
        println!("  server_epk:                OK");
    }

    Ok(())
}
