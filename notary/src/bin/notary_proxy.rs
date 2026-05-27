//! Notary proxy daemon.
//!
//! Listens on a TCP port. For each connection the prover first sends a **setup mode** byte:
//!
//! - **`0` — legacy:** prover sends **`K_N_tx (16) || IV_tx (12) || K_N_rx (16) || IV_rx (12)`**
//!   (56 bytes). Same as the original demo (host chose random XOR masks).
//! - **`1` — notary-chosen XOR masks:** notary samples `K_N_tx || K_N_rx` (32 bytes) and its
//!   additive X25519 scalar share (32 bytes), sends both **before** TLS; after IVs the host runs
//!   OT-blinded ECDH by default (`SETUP_ECDH_OT`) or leaky/skip per host flags.
//! - **`2` — 2PC traffic keys:** notary sends scalar share only; host sends TLS transcript
//!   hashes (64 B) after handshake, then OT-blinded ECDH; both parties derive AES traffic keys
//!   via 2PC HKDF (`--2pc-traffic-keys` in `notary_demo`).
//!
//! Then runs [`notary::tls::run_notary_worker_attested`] until the prover sends
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
use notary::ecdh::{self, share_to_bytes, EcdhSetupOutcome};
use notary::tls::{
    notary_ecdh_after_setup_ivs, run_notary_worker_attested, run_notary_worker_attested_2pc,
    TwoPcTrafficSetup,
};
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


/// Setup mode byte from prover (`notary_demo`).
const SETUP_LEGACY_HOST_MASKS: u8 = 0;
const SETUP_NOTARY_CHOOSES_XOR_MASKS: u8 = 1;
const SETUP_2PC_TRAFFIC_KEYS: u8 = 2;

enum SetupKeys {
    PreSplit {
        k_n_tx: [u8; 16],
        iv_tx: [u8; 12],
        k_n_rx: [u8; 16],
        iv_rx: [u8; 12],
    },
    TwoPcPending {
        ikm_n: [u8; 32],
        after_sh: [u8; 32],
        after_sf: [u8; 32],
        ikm_full: [u8; 32],
    },
}

fn read_setup_frame(ch: &mut Channel, peer: &str) -> swanky_error::Result<SetupKeys> {
    let mut mode = [0u8; 1];
    ch.read_bytes(&mut mode)?;
    match mode[0] {
        SETUP_LEGACY_HOST_MASKS => {
            let mut frame = [0u8; 56];
            ch.read_bytes(&mut frame)?;
            let mut k_n_tx = [0u8; 16];
            let mut iv_tx = [0u8; 12];
            let mut k_n_rx = [0u8; 16];
            let mut iv_rx = [0u8; 12];
            k_n_tx.copy_from_slice(&frame[..16]);
            iv_tx.copy_from_slice(&frame[16..28]);
            k_n_rx.copy_from_slice(&frame[28..44]);
            iv_rx.copy_from_slice(&frame[44..56]);
            eprintln!(
                "notary_proxy: setup LEGACY host-chosen XOR masks received from {peer}"
            );
            Ok(SetupKeys::PreSplit {
                k_n_tx,
                iv_tx,
                k_n_rx,
                iv_rx,
            })
        }
        SETUP_NOTARY_CHOOSES_XOR_MASKS => {
            let mut k_n_tx = [0u8; 16];
            let mut k_n_rx = [0u8; 16];
            rand::thread_rng().fill_bytes(&mut k_n_tx);
            rand::thread_rng().fill_bytes(&mut k_n_rx);
            let ecdh_share = ecdh::generate_share(&mut rand::thread_rng());
            let mut kn = [0u8; 32];
            kn[..16].copy_from_slice(&k_n_tx);
            kn[16..].copy_from_slice(&k_n_rx);
            ch.write_bytes(&kn)?;
            ch.write_bytes(&share_to_bytes(&ecdh_share))?;
            ch.force_flush().map_err(|e| {
                swanky_error::swanky_error!(
                    swanky_error::ErrorKind::NetworkError,
                    "flush setup after notary-chosen masks: {e}"
                )
            })?;
            eprintln!(
                "notary_proxy: pushed XOR masks + scalar share ({peer}), waiting for IVs"
            );
            let mut iv_tx = [0u8; 12];
            let mut iv_rx = [0u8; 12];
            ch.read_bytes(&mut iv_tx)?;
            ch.read_bytes(&mut iv_rx)?;
            eprintln!("notary_proxy: IVs received from {peer}");
            match notary_ecdh_after_setup_ivs(ch, &ecdh_share, &mut rand::thread_rng())? {
                EcdhSetupOutcome::Skipped => {
                    eprintln!("notary_proxy: ECDH skipped by host ({peer})");
                }
                EcdhSetupOutcome::Leaky(outcome) => eprintln!(
                    "notary_proxy: leaky additive ECDH — IKM={}",
                    hex_encode(&outcome.ikm.0)
                ),
                EcdhSetupOutcome::Ot(outcome) => eprintln!(
                    "notary_proxy: OT-blinded ECDH — IKM={} (host holds XOR share only)",
                    hex_encode(&outcome.ikm.0)
                ),
            }
            Ok(SetupKeys::PreSplit {
                k_n_tx,
                iv_tx,
                k_n_rx,
                iv_rx,
            })
        }
        SETUP_2PC_TRAFFIC_KEYS => {
            let ecdh_share = ecdh::generate_share(&mut rand::thread_rng());
            ch.write_bytes(&share_to_bytes(&ecdh_share))?;
            ch.force_flush().map_err(|e| {
                swanky_error::swanky_error!(
                    swanky_error::ErrorKind::NetworkError,
                    "flush setup after 2PC scalar share: {e}"
                )
            })?;
            eprintln!("notary_proxy: pushed scalar share ({peer}), waiting for transcript");
            let mut transcript = [0u8; 64];
            ch.read_bytes(&mut transcript)?;
            let mut after_sh = [0u8; 32];
            let mut after_sf = [0u8; 32];
            after_sh.copy_from_slice(&transcript[..32]);
            after_sf.copy_from_slice(&transcript[32..]);
            eprintln!("notary_proxy: transcript hashes received from {peer}");
            let (ikm_n, ikm_full) = match notary_ecdh_after_setup_ivs(ch, &ecdh_share, &mut rand::thread_rng())? {
                EcdhSetupOutcome::Skipped => {
                    eprintln!("notary_proxy: ECDH skipped — cannot derive 2PC traffic keys");
                    swanky_error::bail!(
                        swanky_error::ErrorKind::OtherError,
                        "2PC traffic setup requires ECDH from {peer}"
                    );
                }
                EcdhSetupOutcome::Leaky(outcome) => {
                    eprintln!(
                        "notary_proxy: leaky ECDH IKM={}",
                        hex_encode(&outcome.ikm.0)
                    );
                    (outcome.notary_ikm_share, outcome.ikm.0)
                }
                EcdhSetupOutcome::Ot(outcome) => {
                    eprintln!(
                        "notary_proxy: OT ECDH IKM={} (host XOR share only)",
                        hex_encode(&outcome.ikm.0)
                    );
                    (outcome.notary_ikm_share, outcome.ikm.0)
                }
            };
            ch.force_flush().map_err(|e| {
                swanky_error::swanky_error!(
                    swanky_error::ErrorKind::NetworkError,
                    "flush after ECDH before HKDF: {e}"
                )
            })?;
            Ok(SetupKeys::TwoPcPending {
                ikm_n,
                after_sh,
                after_sf,
                ikm_full,
            })
        }
        other => swanky_error::bail!(
            swanky_error::ErrorKind::OtherError,
            "unknown setup mode 0x{:02x} from {peer}",
            other
        ),
    }
}

fn handle(stream: TcpStream, signing_key: Arc<SigningKey>) -> swanky_error::Result<()> {
    let peer =
        stream.peer_addr().map(|a| a.to_string()).unwrap_or_else(|_| "<?>".into());
    eprintln!("notary_proxy: connection from {peer}");
    Channel::with(stream, |ch| {
        match read_setup_frame(ch, &peer)? {
            SetupKeys::PreSplit {
                k_n_tx,
                iv_tx,
                k_n_rx,
                iv_rx,
            } => {
                eprintln!("notary_proxy: setup complete from {peer}, running attested worker");
                match run_notary_worker_attested(ch, &signing_key, k_n_tx, iv_tx, k_n_rx, iv_rx)? {
                    Some(bundle) => eprintln!(
                        "notary_proxy: signed bundle for {peer} — session_id={:?} server={:?} records={}",
                        bundle.session_id,
                        bundle.server_name,
                        bundle.records.len()
                    ),
                    None => eprintln!("notary_proxy: {peer} disconnected without OP_FINISH"),
                }
            }
            SetupKeys::TwoPcPending {
                ikm_n,
                after_sh,
                after_sf,
                ikm_full,
            } => {
                eprintln!("notary_proxy: 2PC setup complete ({peer}), waiting for OP_2PC_HKDF");
                match run_notary_worker_attested_2pc(
                    ch,
                    &signing_key,
                    TwoPcTrafficSetup {
                        ikm_n,
                        after_sh,
                        after_sf,
                        ikm_full,
                    },
                )? {
                    Some(bundle) => eprintln!(
                        "notary_proxy: signed bundle for {peer} — session_id={:?} server={:?} records={}",
                        bundle.session_id,
                        bundle.server_name,
                        bundle.records.len()
                    ),
                    None => eprintln!("notary_proxy: {peer} disconnected without OP_FINISH"),
                }
            }
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
