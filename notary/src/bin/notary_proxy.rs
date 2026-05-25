//! Notary proxy daemon.
//!
//! Listens on a TCP port. For each connection:
//!   1. Reads a 56-byte setup frame from the swanky channel:
//!        K_N_tx (16) || IV_tx (12) || K_N_rx (16) || IV_rx (12)
//!   2. Runs [`notary::tls::run_notary_worker_attested`] until the prover sends
//!      OP_FINISH (in which case the notary signs and returns the bundle) or
//!      the peer disconnects.
//!
//! A long-term Ed25519 signing key is loaded from disk (created on first run).
//! The corresponding public key is printed at startup so external verifiers
//! can be told what to trust.
//!
//! Minimal-demo: no auth, no rate limit, no audit log, no key rotation.

use std::fs;
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use ed25519_dalek::SigningKey;
use notary::tls::run_notary_worker_attested;
use rand::RngCore;
use swanky_channel::Channel;

#[derive(Parser, Debug)]
#[command(about = "2PC notary daemon — runs garbler-side AES-GCM for split-key TLS sessions, signs session bundles")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:9001")]
    listen: String,

    /// Path to the notary's Ed25519 signing key (32 raw bytes).
    /// If the file doesn't exist, a fresh key is generated and written.
    #[arg(long, default_value = "notary_signing.key")]
    key_path: PathBuf,
}

fn load_or_create_key(path: &PathBuf) -> Result<SigningKey> {
    if path.exists() {
        let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
        let arr: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .context("signing key file must be exactly 32 bytes")?;
        Ok(SigningKey::from_bytes(&arr))
    } else {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        fs::write(path, sk.to_bytes())
            .with_context(|| format!("write {}", path.display()))?;
        eprintln!("notary_proxy: generated new signing key at {}", path.display());
        Ok(sk)
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn handle(stream: TcpStream, signing_key: Arc<SigningKey>) -> swanky_error::Result<()> {
    let peer =
        stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "<?>".into());
    eprintln!("notary_proxy: connection from {peer}");
    Channel::with(stream, |ch| {
        let mut k_n_tx = [0u8; 16];
        let mut iv_tx = [0u8; 12];
        let mut k_n_rx = [0u8; 16];
        let mut iv_rx = [0u8; 12];
        ch.read_bytes(&mut k_n_tx)?;
        ch.read_bytes(&mut iv_tx)?;
        ch.read_bytes(&mut k_n_rx)?;
        ch.read_bytes(&mut iv_rx)?;
        eprintln!("notary_proxy: setup received from {peer}, running attested worker");
        match run_notary_worker_attested(ch, &signing_key, k_n_tx, iv_tx, k_n_rx, iv_rx)? {
            Some(bundle) => eprintln!(
                "notary_proxy: signed bundle for {peer} — session_id={:?} server={:?} records={}",
                bundle.session_id,
                bundle.server_name,
                bundle.records.len()
            ),
            None => eprintln!("notary_proxy: {peer} disconnected without OP_FINISH"),
        }
        Ok(())
    })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let signing_key = Arc::new(load_or_create_key(&args.key_path)?);
    eprintln!(
        "notary_proxy: pubkey = {}",
        hex_encode(signing_key.verifying_key().to_bytes().as_slice())
    );

    let listener =
        TcpListener::bind(&args.listen).with_context(|| format!("bind {}", args.listen))?;
    eprintln!("notary_proxy: listening on {}", args.listen);
    for stream in listener.incoming() {
        let stream = stream.context("accept")?;
        let sk = signing_key.clone();
        thread::spawn(move || {
            if let Err(e) = handle(stream, sk) {
                eprintln!("notary_proxy: connection error: {e:#}");
            }
        });
    }
    Ok(())
}
