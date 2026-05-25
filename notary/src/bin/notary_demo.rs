//! End-to-end demo: HTTPS GET against a real server with the AEAD record
//! layer driven by split-key 2PC AES-GCM in coordination with `notary_proxy`.
//!
//! Flow:
//!   1. rustls TLS 1.3 handshake to `--url` (uses the standard ring AEAD —
//!      handshake records are not 2PC'd, that's a deferred TODO).
//!   2. `dangerous_extract_secrets()` pulls the application traffic keys out
//!      of the connection.
//!   3. We split each key (tx + rx) with the notary: pick random K_N, derive
//!      K_C = key XOR K_N, send K_N + IV to the notary, **zero the full key
//!      from our memory**.
//!   4. From this point on, host has only K_C; notary has K_N; neither has K.
//!   5. We take over the TcpStream manually: build the HTTP GET, encrypt it
//!      as a TLS 1.3 record via 2PC AES-GCM, write to the socket. Read
//!      response records, decrypt each via 2PC, assemble plaintext, print it.
//!
//! Trust caveats (all flagged in the codebase already):
//!   - Handshake is local-only — the host briefly held K (between step 1 and
//!     the split + zero in step 3). True "host never has K" requires ECDH 2PC.
//!   - This demo is semi-honest; authenticated garbling not wired in.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use notary::tls::{client_decrypt_record, client_encrypt_record, tls13_aad};
use rand::RngCore;
use rustls::crypto::cipher::AeadKey;
use rustls::{ClientConfig, ClientConnection};
use swanky_channel::Channel;
use zeroize::Zeroize;

#[derive(Parser, Debug)]
#[command(about = "Demo: TLS 1.3 GET driven by split-key 2PC AES-GCM (record layer)")]
struct Args {
    /// HTTPS URL to GET. Must use TLS 1.3 with TLS_AES_128_GCM_SHA256.
    #[arg(long)]
    url: String,

    /// Notary proxy address.
    #[arg(long, default_value = "127.0.0.1:9001")]
    notary: String,
}

fn xor_key(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

/// Read one TLS record from a stream: 5-byte header + payload.
/// Returns (content_type, legacy_version, payload).
fn read_tls_record(s: &mut TcpStream) -> Result<(u8, u16, Vec<u8>)> {
    let mut hdr = [0u8; 5];
    s.read_exact(&mut hdr).context("read record header")?;
    let ct = hdr[0];
    let ver = u16::from_be_bytes([hdr[1], hdr[2]]);
    let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
    if len > 16640 {
        bail!("oversized TLS record: {len}");
    }
    let mut payload = vec![0u8; len];
    s.read_exact(&mut payload).context("read record payload")?;
    Ok((ct, ver, payload))
}

fn write_tls_record(s: &mut TcpStream, ct: u8, ver: u16, payload: &[u8]) -> Result<()> {
    let mut hdr = [0u8; 5];
    hdr[0] = ct;
    hdr[1..3].copy_from_slice(&ver.to_be_bytes());
    hdr[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    s.write_all(&hdr).context("write record header")?;
    s.write_all(payload).context("write record payload")?;
    s.flush().context("flush")?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    let url = url::Url::parse(&args.url).context("invalid URL")?;
    if url.scheme() != "https" {
        bail!("URL must be https://");
    }
    let host = url.host_str().context("URL has no host")?.to_string();
    let port = url.port_or_known_default().unwrap_or(443);
    let path = url.path();
    let path = if path.is_empty() { "/" } else { path };
    let query_path = match url.query() {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    };

    // ── Phase 1: TLS 1.3 handshake (uses standard ring AEAD) ──────────────
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];

    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();
    config.enable_secret_extraction = true;

    let server_name: rustls::pki_types::ServerName =
        host.clone().try_into().context("invalid server name")?;

    eprintln!("phase 1: TCP+TLS handshake to {host}:{port}");
    let mut tcp = TcpStream::connect(format!("{host}:{port}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    let mut tls = ClientConnection::new(Arc::new(config), server_name)?;
    // Drive handshake to completion.
    while tls.is_handshaking() {
        if tls.wants_write() {
            tls.write_tls(&mut tcp).context("write handshake")?;
        }
        if tls.wants_read() {
            tls.read_tls(&mut tcp).context("read handshake")?;
            tls.process_new_packets().context("process handshake")?;
        }
    }
    // Flush any leftover records rustls has queued (e.g. our own Finished).
    while tls.wants_write() {
        tls.write_tls(&mut tcp).context("flush post-handshake")?;
    }
    // Drain any post-handshake records the server queued (e.g. NewSessionTicket).
    tcp.set_read_timeout(Some(Duration::from_millis(150)))?;
    let _ = tls.read_tls(&mut tcp);
    let _ = tls.process_new_packets();
    while tls.wants_write() {
        let _ = tls.write_tls(&mut tcp);
    }
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;

    // ── Phase 2: extract traffic secrets ──────────────────────────────────
    let secrets = tls.dangerous_extract_secrets().context("extract secrets")?;
    let (mut tx_seq, tx_secrets) = secrets.tx;
    let (mut rx_seq, rx_secrets) = secrets.rx;
    let (mut tx_key, mut tx_iv) = aes128_gcm_from_secrets(&tx_secrets)?;
    let (mut rx_key, mut rx_iv) = aes128_gcm_from_secrets(&rx_secrets)?;
    eprintln!(
        "phase 2: traffic secrets extracted (tx_seq={}, rx_seq={})",
        tx_seq, rx_seq
    );

    // ── Phase 3: split each direction with the notary ─────────────────────
    let mut k_n_tx = [0u8; 16];
    let mut k_n_rx = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut k_n_tx);
    rand::thread_rng().fill_bytes(&mut k_n_rx);
    let k_c_tx = xor_key(&tx_key, &k_n_tx);
    let k_c_rx = xor_key(&rx_key, &k_n_rx);
    // After this point the host must never need the full keys again.
    // Zero our copies and keep only the client shares.
    tx_key.zeroize();
    rx_key.zeroize();

    eprintln!("phase 3: connecting to notary at {}", args.notary);
    let mut notary_tcp = TcpStream::connect(&args.notary)
        .with_context(|| format!("connect to notary {}", args.notary))?;
    notary_tcp.set_nodelay(true)?;

    // Send setup frame to notary: K_N_tx || IV_tx || K_N_rx || IV_rx (56 bytes).
    notary_tcp.write_all(&k_n_tx)?;
    notary_tcp.write_all(&tx_iv)?;
    notary_tcp.write_all(&k_n_rx)?;
    notary_tcp.write_all(&rx_iv)?;
    notary_tcp.flush()?;

    // ── Phase 4: take over the record layer manually via 2PC ──────────────
    let http_request = format!(
        "GET {query_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
    );
    eprintln!(
        "phase 4: encrypting {} bytes of HTTP request via 2PC AES-GCM",
        http_request.len()
    );

    // TLS 1.3 inner = plaintext || inner_content_type (0x17 = application_data).
    let mut inner = http_request.into_bytes();
    inner.push(0x17);

    let total_len = inner.len() + 16; // tag

    // Build AAD per RFC 8446 §5.2 — `tls13_aad` already produces this.
    let aad = tls13_aad(total_len);

    // Open ONE swanky channel for the whole session — multiple Channel::with
    // calls would lose buffered bytes between operations.
    let full_plaintext: Vec<u8> = Channel::with(&mut notary_tcp, |ch| -> swanky_error::Result<_> {
        // Encrypt request via 2PC; send the resulting record to the server.
        let (ct, tag) = client_encrypt_record(ch, k_c_tx, tx_iv, &inner, &aad, tx_seq)?;
        tx_seq += 1;
        let mut record_payload = ct.clone();
        record_payload.extend_from_slice(&tag);
        if let Err(e) = write_tls_record(&mut tcp, 0x17, 0x0303, &record_payload) {
            swanky_error::bail!(
                swanky_error::ErrorKind::NetworkError,
                "write request: {e}"
            );
        }
        eprintln!("phase 4: request record sent");

        // ── Phase 5: read response records, decrypt each via 2PC ──────
        let mut full = Vec::new();
        eprintln!("phase 5: reading response records");
        loop {
            let (ct_kind, _ver, payload) = match read_tls_record(&mut tcp) {
                Ok(rec) => rec,
                Err(e) => {
                    eprintln!("record read ended: {e}");
                    break;
                }
            };
            if ct_kind != 0x17 {
                eprintln!(
                    "unexpected record content type 0x{:02x}, stopping",
                    ct_kind
                );
                break;
            }
            if payload.len() < 16 {
                swanky_error::bail!(swanky_error::ErrorKind::OtherError, "short record");
            }
            let aad = tls13_aad(payload.len());
            let tag_start = payload.len() - 16;
            let mut tag = [0u8; 16];
            tag.copy_from_slice(&payload[tag_start..]);
            let ct = payload[..tag_start].to_vec();

            let plain = client_decrypt_record(ch, k_c_rx, rx_iv, &ct, tag, &aad, rx_seq)?;
            rx_seq += 1;
            let mut buf = plain;
            while buf.last() == Some(&0u8) {
                buf.pop();
            }
            let Some(inner_ct) = buf.pop() else {
                swanky_error::bail!(
                    swanky_error::ErrorKind::OtherError,
                    "empty decrypted record"
                );
            };
            match inner_ct {
                0x17 => full.extend_from_slice(&buf),
                0x15 => {
                    eprintln!("server sent TLS alert: {buf:?}");
                    break;
                }
                _ => {
                    // post-handshake handshake messages (NewSessionTicket etc.) — skip
                }
            }
        }
        Ok(full)
    })
    .map_err(|e| anyhow::anyhow!("notary session: {e:#}"))?;
    drop(notary_tcp);

    let body = String::from_utf8_lossy(&full_plaintext);
    println!("--- response ({} bytes) ---", full_plaintext.len());
    println!("{body}");

    // Zero shares before exit (best-effort).
    let mut k_c_tx_z = k_c_tx;
    let mut k_c_rx_z = k_c_rx;
    k_c_tx_z.zeroize();
    k_c_rx_z.zeroize();
    tx_iv.zeroize();
    rx_iv.zeroize();

    Ok(())
}

/// Pull `(key, iv)` out of `ConnectionTrafficSecrets`, requiring AES-128-GCM.
fn aes128_gcm_from_secrets(
    s: &rustls::ConnectionTrafficSecrets,
) -> Result<([u8; 16], [u8; 12])> {
    use rustls::ConnectionTrafficSecrets;
    match s {
        ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
            let key_bytes: &[u8] = key.as_ref();
            let iv_bytes: &[u8] = iv.as_ref();
            let key_arr: [u8; 16] = key_bytes
                .try_into()
                .context("AES-128-GCM key must be 16 bytes")?;
            let iv_arr: [u8; 12] = iv_bytes
                .try_into()
                .context("AES-128-GCM iv must be 12 bytes")?;
            Ok((key_arr, iv_arr))
        }
        _ => bail!("expected AES-128-GCM secrets (TLS_AES_128_GCM_SHA256), got something else"),
    }
}

// Silence unused-warning for AeadKey/zeroize-related imports if the compiler complains.
#[allow(dead_code)]
fn _unused_imports(_: AeadKey) {}
