//! Notary proxy daemon.
//!
//! Listens on a TCP port. For each connection:
//!   1. Reads a 56-byte setup frame from the swanky channel:
//!        K_N_tx (16) || IV_tx (12) || K_N_rx (16) || IV_rx (12)
//!   2. Runs [`notary::tls::run_notary_worker`] until the peer closes.
//!
//! No persistent state, no auth — minimal-demo notary. A production version
//! would add: authenticated session setup, rate limiting, audit log, key
//! rotation. Out of scope here.

use std::net::{TcpListener, TcpStream};
use std::thread;

use anyhow::{Context, Result};
use clap::Parser;
use notary::tls::run_notary_worker;
use swanky_channel::Channel;

#[derive(Parser, Debug)]
#[command(about = "2PC notary daemon — runs garbler-side AES-GCM for split-key TLS sessions")]
struct Args {
    /// Address to listen on.
    #[arg(long, default_value = "127.0.0.1:9001")]
    listen: String,
}

fn handle(stream: TcpStream) -> swanky_error::Result<()> {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "<?>".into());
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
        eprintln!("notary_proxy: setup received from {peer}, running worker");
        run_notary_worker(ch, k_n_tx, iv_tx, k_n_rx, iv_rx)?;
        eprintln!("notary_proxy: {peer} disconnected");
        Ok(())
    })
}

fn main() -> Result<()> {
    let args = Args::parse();
    let listener =
        TcpListener::bind(&args.listen).with_context(|| format!("bind {}", args.listen))?;
    eprintln!("notary_proxy: listening on {}", args.listen);
    for stream in listener.incoming() {
        let stream = stream.context("accept")?;
        thread::spawn(move || {
            if let Err(e) = handle(stream) {
                eprintln!("notary_proxy: connection error: {e:#}");
            }
        });
    }
    Ok(())
}
