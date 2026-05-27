//! End-to-end demo: HTTPS GET against a real server with the AEAD record
//! layer driven by split-key 2PC AES-GCM in coordination with `notary_proxy`.
//!
//! Flow:
//!   1. rustls TLS 1.3 handshake to `--url` (uses the standard ring AEAD —
//!      handshake records are not 2PC'd, that's a deferred TODO).
//!   2. `dangerous_extract_secrets()` pulls the application traffic keys out
//!      of the connection.
//!   3. We split each AES traffic key: `K_C = K_full XOR K_N`, **zero the full key**
//!      from host memory. **Default:** `K_N` is chosen by the notary **before** TLS handshake
//!      (`--legacy-host-xor-masks` restores host-chosen masks after handshake).
//!      Default mode 1 runs OT-blinded ECDH after IVs (host gets XOR IKM share only).
//!      Full OT-MtA scalar mult + 2PC HKDF remain TODO.md #1.
//!   4. From this point on, host has only K_C; notary has K_N; neither has K.
//!   5. We take over the TcpStream manually: build the HTTP GET, encrypt it
//!      as a TLS 1.3 record via 2PC AES-GCM, write to the socket. Read
//!      response records, decrypt each via 2PC, assemble plaintext, print it.
//!
//! Trust caveats (all flagged in the codebase already):
//!   - Handshake is local-only — the host briefly held K (between step 1 and
//!     the split + zero in step 3). True "host never has K" requires ECDH 2PC
//!     (`notary::ecdh::OtX25519Blinded` — host XOR IKM share; rustls still brief full keys).
//!   - Mode 2 sends raw handshake bytes to the notary for independent transcript verify.
//!   - Record-layer 2PC uses authenticated garbling (WRK17).

use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::Parser;
use notary::ecdh::{
    EphemeralShare, combined_client_esk, generate_share, host_send_ecdh_leaky, host_send_ecdh_ot,
    host_skip_ecdh_leaky, parse_server_hello_key_share, reference_ikm, share_from_bytes,
};
use notary::garble::Wrk17ClientSession;
use notary::handshake::{HandshakeCapture, cert_chain_hash, write_handshake_capture};
use notary::hkdf::{client_tls13_client_traffic_from_ikm_shares, reference_tls13_client_traffic};
use notary::tls::{
    ChannelRw, client_decrypt_record, client_encrypt_record, client_finish_session, tls13_aad,
};
use notary::transcript::transcript_hashes_with_ikm;
use rand::RngCore;
use rustls::crypto::cipher::AeadKey;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{ClientConfig, ClientConnection, Error, NamedGroup};
use swanky_channel::Channel;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Setup framing (must stay in sync with `notary_proxy`).
const SETUP_LEGACY_HOST_MASKS: u8 = 0;
const SETUP_NOTARY_CHOOSES_XOR_MASKS: u8 = 1;
const SETUP_2PC_TRAFFIC_KEYS: u8 = 2;

#[derive(Parser, Debug)]
#[command(about = "Demo: TLS 1.3 GET driven by split-key 2PC AES-GCM (record layer)")]
struct Args {
    /// HTTPS URL to GET. Must use TLS 1.3 with TLS_AES_128_GCM_SHA256.
    #[arg(long)]
    url: String,

    /// Notary proxy address.
    #[arg(long, default_value = "127.0.0.1:9001")]
    notary: String,

    /// Optional: bincode-serialize the resulting `TlsWitness` to this path
    /// (raw inbound/outbound + signed bundle + K_C shares + claim params).
    /// Consumed by `sp1-demo-host`'s `notarized` binary to drive the SP1 guest.
    #[arg(long)]
    witness_out: Option<std::path::PathBuf>,

    /// JSON Pointer to the field to claim (e.g. `/userId`).
    /// Only used when `--witness-out` is set.
    #[arg(long, default_value = "/userId")]
    field: String,

    /// Threshold for the field-value claim (`field > threshold`).
    /// Only used when `--witness-out` is set.
    #[arg(long, default_value_t = 0.0)]
    threshold: f64,

    /// Original demo: host samples XOR masks **after** the handshake (single connection to notary).
    ///
    /// If **not** set (default), the **notary** sends `K_N_tx || K_N_rx` and its scalar share
    /// **before** TLS; the host injects `(s_host + s_notary)` into ClientHello via
    /// `ExternalKxGroup`, then runs OT-blinded ECDH after IVs (unless `--skip-ecdh-wire` /
    /// `--leaky-ecdh-wire`). rustls still briefly holds full AES keys after extract.
    #[arg(long)]
    legacy_host_xor_masks: bool,

    /// Mode 1 only: skip the post-IV ECDH round (`SETUP_ECDH_SKIP`).
    #[arg(long)]
    skip_ecdh_wire: bool,

    /// Mode 1 only: use leaky cleartext partial-point ECDH instead of OT-blinded (debug).
    #[arg(long, conflicts_with = "skip_ecdh_wire")]
    leaky_ecdh_wire: bool,

    /// Derive AES traffic keys via 2PC HKDF from OT IKM XOR shares + transcript hashes
    /// (setup mode 2). Skips `dangerous_extract_secrets()` for record-layer keys.
    #[arg(long, conflicts_with = "legacy_host_xor_masks")]
    two_pc_traffic_keys: bool,

    /// With `--2pc-traffic-keys`: compare 2PC-derived keys against rustls extract (debug).
    #[arg(long, requires = "two_pc_traffic_keys")]
    verify_rustls_keys: bool,
}

/// Wraps a `TcpStream` and records every raw byte in both directions during the TLS handshake.
struct CapturingStream {
    inner: TcpStream,
    inbound: Vec<u8>,
    outbound: Vec<u8>,
}

impl CapturingStream {
    fn new(stream: TcpStream) -> Self {
        Self {
            inner: stream,
            inbound: Vec::new(),
            outbound: Vec::new(),
        }
    }
}

impl Read for CapturingStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.inbound.extend_from_slice(&buf[..n]);
        Ok(n)
    }
}

impl Write for CapturingStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.outbound.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

fn xor_key(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    std::array::from_fn(|i| a[i] ^ b[i])
}

fn map_io<T>(r: std::io::Result<T>) -> swanky_error::Result<T> {
    r.map_err(|e| swanky_error::swanky_error!(swanky_error::ErrorKind::NetworkError, "{e}"))
}

fn map_rustls<T>(r: Result<T, rustls::Error>) -> swanky_error::Result<T> {
    r.map_err(|e| swanky_error::swanky_error!(swanky_error::ErrorKind::OtherError, "{e}"))
}

/// Inject a pre-agreed client X25519 ephemeral into rustls (mode 1).
struct ExternalKxGroup {
    esk_client: [u8; 32],
}

impl std::fmt::Debug for ExternalKxGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ExternalKxGroup(X25519)")
    }
}

impl SupportedKxGroup for ExternalKxGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = StaticSecret::from(self.esk_client);
        let public = PublicKey::from(&secret);
        Ok(Box::new(ExternalActiveKx { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct ExternalActiveKx {
    secret: StaticSecret,
    public: PublicKey,
}

impl ActiveKeyExchange for ExternalActiveKx {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let server_pub_bytes = <[u8; 32]>::try_from(peer_pub_key)
            .map_err(|_| Error::General("X25519: peer key must be 32 bytes".into()))?;
        let server_pub = PublicKey::from(server_pub_bytes);
        let shared = self.secret.diffie_hellman(&server_pub);
        Ok(SharedSecret::from(shared.as_bytes().as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

fn make_provider(esk_client: [u8; 32]) -> rustls::crypto::CryptoProvider {
    let kx: &'static dyn SupportedKxGroup = Box::leak(Box::new(ExternalKxGroup { esk_client }));
    rustls::crypto::CryptoProvider {
        kx_groups: vec![kx],
        ..rustls::crypto::ring::default_provider()
    }
}

/// Read one TLS record from a stream: 5-byte header + payload.
/// Returns (content_type, legacy_version, payload, raw_record_bytes).
fn read_tls_record(s: &mut TcpStream) -> Result<(u8, u16, Vec<u8>, Vec<u8>)> {
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
    let mut raw = Vec::with_capacity(5 + len);
    raw.extend_from_slice(&hdr);
    raw.extend_from_slice(&payload);
    Ok((ct, ver, payload, raw))
}

fn build_tls_record(ct: u8, ver: u16, payload: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(5 + payload.len());
    raw.push(ct);
    raw.extend_from_slice(&ver.to_be_bytes());
    raw.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    raw.extend_from_slice(payload);
    raw
}

fn write_tls_record(s: &mut TcpStream, ct: u8, ver: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let raw = build_tls_record(ct, ver, payload);
    s.write_all(&raw).context("write record")?;
    s.flush().context("flush")?;
    Ok(raw)
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.two_pc_traffic_keys {
        return run_two_pc_traffic_demo(args);
    }

    run_legacy_demo(args)
}

fn run_two_pc_traffic_demo(args: Args) -> Result<()> {
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

    eprintln!(
        "phase 0: connect notary (single Channel session) {}",
        args.notary
    );
    let notary_tcp = TcpStream::connect(&args.notary)
        .with_context(|| format!("connect to notary {}", args.notary))?;
    notary_tcp.set_nodelay(true)?;

    let session_result = Channel::with(notary_tcp, |ch| -> swanky_error::Result<_> {
        ch.write_bytes(&[SETUP_2PC_TRAFFIC_KEYS]).map_err(|e| {
            swanky_error::swanky_error!(swanky_error::ErrorKind::NetworkError, "{e}")
        })?;
        let mut notary_scalar = [0u8; 32];
        ch.read_bytes(&mut notary_scalar)?;
        let notary_share = share_from_bytes(&notary_scalar);
        let host_share = generate_share(&mut rand::thread_rng());
        let esk = combined_client_esk(&host_share, &notary_share);
        eprintln!("phase 0a: scalar share received — ClientHello uses split ephemeral");

        let mut provider = make_provider(esk);
        provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
        let mut config = map_rustls(
            ClientConfig::builder_with_provider(Arc::new(provider))
                .with_protocol_versions(&[&rustls::version::TLS13]),
        )?
        .with_root_certificates(rustls::RootCertStore {
            roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
        })
        .with_no_client_auth();
        config.enable_secret_extraction = true;

        let server_name: rustls::pki_types::ServerName = host.clone().try_into().map_err(|_| {
            swanky_error::swanky_error!(swanky_error::ErrorKind::OtherError, "invalid server name")
        })?;

        eprintln!("phase 1: TCP+TLS handshake to {host}:{port}");
        let tcp = map_io(TcpStream::connect(format!("{host}:{port}")))?;
        map_io(tcp.set_read_timeout(Some(Duration::from_secs(15))))?;
        let mut capturing = CapturingStream::new(tcp);
        let mut tls = map_rustls(ClientConnection::new(Arc::new(config), server_name))?;
        while tls.is_handshaking() {
            if tls.wants_write() {
                map_io(tls.write_tls(&mut capturing))?;
            }
            if tls.wants_read() {
                map_io(tls.read_tls(&mut capturing))?;
                map_rustls(tls.process_new_packets())?;
            }
        }
        while tls.wants_write() {
            map_io(tls.write_tls(&mut capturing))?;
        }
        map_io(
            capturing
                .inner
                .set_read_timeout(Some(Duration::from_millis(150))),
        )?;
        let _ = tls.read_tls(&mut capturing);
        let _ = tls.process_new_packets();
        while tls.wants_write() {
            let _ = tls.write_tls(&mut capturing);
        }
        map_io(
            capturing
                .inner
                .set_read_timeout(Some(Duration::from_secs(15))),
        )?;

        let server_epk = parse_server_hello_key_share(&capturing.inbound).ok_or_else(|| {
            swanky_error::swanky_error!(swanky_error::ErrorKind::OtherError, "no server epk")
        })?;
        let cert_hash = tls
            .peer_certificates()
            .map(|certs| {
                let der: Vec<&[u8]> = certs.iter().map(|c| c.as_ref()).collect();
                cert_chain_hash(&der)
            })
            .unwrap_or([0u8; 32]);
        let ikm_oracle = reference_ikm(&host_share, &notary_share, &server_epk);
        let (after_sh, after_sf) =
            transcript_hashes_with_ikm(&capturing.outbound, &capturing.inbound, &ikm_oracle.0)
                .ok_or_else(|| {
                    swanky_error::swanky_error!(
                        swanky_error::ErrorKind::OtherError,
                        "transcript hashes"
                    )
                })?;
        let (_, tx_iv, _, rx_iv) =
            reference_tls13_client_traffic(&ikm_oracle.0, &after_sh, &after_sf);

        eprintln!("phase 2: 2PC traffic key path (no rustls extract for record keys)");
        if args.verify_rustls_keys {
            let secrets = map_rustls(tls.dangerous_extract_secrets())?;
            let (_, rust_tx) = secrets.tx;
            let (_, rust_rx) = secrets.rx;
            let (ref_tx, ref_iv_tx, ref_rx, ref_iv_rx) =
                reference_tls13_client_traffic(&ikm_oracle.0, &after_sh, &after_sf);
            use rustls::ConnectionTrafficSecrets;
            match &rust_tx {
                ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                    assert_eq!(key.as_ref(), ref_tx.as_slice());
                    assert_eq!(iv.as_ref(), ref_iv_tx.as_slice());
                }
                _ => swanky_error::bail!(
                    swanky_error::ErrorKind::OtherError,
                    "expected AES-128-GCM tx secrets"
                ),
            }
            match &rust_rx {
                ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                    assert_eq!(key.as_ref(), ref_rx.as_slice());
                    assert_eq!(iv.as_ref(), ref_iv_rx.as_slice());
                }
                _ => swanky_error::bail!(
                    swanky_error::ErrorKind::OtherError,
                    "expected AES-128-GCM rx secrets"
                ),
            }
            eprintln!("phase 2: rustls extract matches reference key schedule");
        }

        eprintln!("phase 3: handshake capture + OT ECDH on notary channel");
        write_handshake_capture(
            ch,
            &HandshakeCapture {
                server_epk,
                cert_chain_hash: cert_hash,
                outbound: capturing.outbound.clone(),
                inbound: capturing.inbound.clone(),
            },
        )?;
        let mut io = ChannelRw(ch);
        let outcome = host_send_ecdh_ot(&mut io, &host_share, &server_epk).map_err(|e| {
            swanky_error::swanky_error!(swanky_error::ErrorKind::NetworkError, "{e}")
        })?;
        ch.force_flush().map_err(|e| {
            swanky_error::swanky_error!(
                swanky_error::ErrorKind::NetworkError,
                "post-ECDH flush: {e}"
            )
        })?;
        eprintln!(
            "phase 3b: host XOR IKM share={} (2PC HKDF next)",
            hex_encode(&outcome.host_ikm_share)
        );

        let mut raw_outbound = capturing.outbound;
        let mut raw_inbound = capturing.inbound;
        let mut tcp = capturing.inner;

        eprintln!("phase 4a: 2PC HKDF traffic key schedule (OP_2PC_HKDF)");
        let mut wrk17 = Wrk17ClientSession::init(ch)?;
        let traffic = client_tls13_client_traffic_from_ikm_shares(
            ch,
            outcome.host_ikm_share,
            after_sh,
            after_sf,
            &mut wrk17,
        )?;
        let k_c_tx = traffic.k_c_tx;
        let k_c_rx = traffic.k_c_rx;
        let mut rx_seq = 0u64;

        let http_request = format!(
            "GET {query_path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
        );
        eprintln!(
            "phase 4: encrypting {} bytes of HTTP request via 2PC AES-GCM",
            http_request.len()
        );
        let mut inner = http_request.into_bytes();
        inner.push(0x17);
        let aad = tls13_aad(inner.len() + 16);

        let (ct, tag) = client_encrypt_record(ch, &mut wrk17, k_c_tx, tx_iv, &inner, &aad, 0)?;
        let mut record_payload = ct.clone();
        record_payload.extend_from_slice(&tag);
        let req_raw = write_tls_record(&mut tcp, 0x17, 0x0303, &record_payload).map_err(|e| {
            swanky_error::swanky_error!(swanky_error::ErrorKind::NetworkError, "{e}")
        })?;
        raw_outbound.extend_from_slice(&req_raw);

        let mut full = Vec::new();
        eprintln!("phase 5: reading response records");
        loop {
            let (ct_kind, _ver, payload, raw) = match read_tls_record(&mut tcp) {
                Ok(rec) => rec,
                Err(e) => {
                    eprintln!("record read ended: {e}");
                    break;
                }
            };
            raw_inbound.extend_from_slice(&raw);
            if ct_kind != 0x17 {
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
            let plain =
                client_decrypt_record(ch, &mut wrk17, k_c_rx, rx_iv, &ct, tag, &aad, rx_seq)?;
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
            if inner_ct == 0x17 {
                full.extend_from_slice(&buf);
            }
        }

        let session_id = format!(
            "demo-{}-{}",
            host,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        let bundle = client_finish_session(ch, &session_id, &host)?;
        Ok((
            full,
            bundle,
            raw_inbound,
            raw_outbound,
            k_c_tx,
            k_c_rx,
            tx_iv,
            rx_iv,
        ))
    })
    .map_err(|e| anyhow::anyhow!("notary session: {e:#}"))?;

    let (full_plaintext, bundle, raw_inbound, raw_outbound, k_c_tx, k_c_rx, tx_iv, rx_iv) =
        session_result;

    print_demo_output(
        &full_plaintext,
        &bundle,
        &host,
        &args,
        raw_inbound,
        raw_outbound,
        k_c_tx,
        k_c_rx,
        tx_iv,
        rx_iv,
    )
}

fn run_legacy_demo(args: Args) -> Result<()> {
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

    // ── Phase 0 / 1: notary setup + TLS 1.3 handshake ─────────────────────
    let mut k_n_tx = [0u8; 16];
    let mut k_n_rx = [0u8; 16];
    let mut notary_pre_tls: Option<TcpStream> = None;
    let mut host_ecdh_share: Option<EphemeralShare> = None;
    let mut notary_ecdh_share: Option<EphemeralShare> = None;

    let mut provider = if args.legacy_host_xor_masks {
        rustls::crypto::ring::default_provider()
    } else {
        make_provider([0u8; 32]) // replaced after notary scalar share arrives
    };
    provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];

    if !args.legacy_host_xor_masks {
        eprintln!(
            "phase 0a: connect notary for XOR masks + scalar share {}",
            args.notary
        );
        let mut nm = TcpStream::connect(&args.notary)
            .with_context(|| format!("connect to notary {}", args.notary))?;
        nm.set_nodelay(true)?;
        nm.write_all(&[SETUP_NOTARY_CHOOSES_XOR_MASKS])
            .context("write setup mode")?;
        nm.flush().context("flush setup mode")?;
        let mut kn = [0u8; 32];
        nm.read_exact(&mut kn)
            .context("read notary XOR mask frame")?;
        let mut notary_scalar = [0u8; 32];
        nm.read_exact(&mut notary_scalar)
            .context("read notary scalar share")?;
        k_n_tx.copy_from_slice(&kn[..16]);
        k_n_rx.copy_from_slice(&kn[16..32]);
        let notary_share = share_from_bytes(&notary_scalar);
        let host_share = generate_share(&mut rand::thread_rng());
        host_ecdh_share = Some(host_share);
        notary_ecdh_share = Some(notary_share);
        let esk = combined_client_esk(&host_share, &notary_share);
        provider = make_provider(esk);
        provider.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256];
        eprintln!(
            "phase 0a: notary XOR masks + scalar share received — ClientHello uses split ephemeral"
        );
        notary_pre_tls = Some(nm);
    }

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
    let tcp = TcpStream::connect(format!("{host}:{port}"))?;
    tcp.set_read_timeout(Some(Duration::from_secs(15)))?;
    let mut capturing = CapturingStream::new(tcp);
    let mut tls = ClientConnection::new(Arc::new(config), server_name)?;
    // Drive handshake to completion.
    while tls.is_handshaking() {
        if tls.wants_write() {
            tls.write_tls(&mut capturing).context("write handshake")?;
        }
        if tls.wants_read() {
            tls.read_tls(&mut capturing).context("read handshake")?;
            tls.process_new_packets().context("process handshake")?;
        }
    }
    // Flush any leftover records rustls has queued (e.g. our own Finished).
    while tls.wants_write() {
        tls.write_tls(&mut capturing)
            .context("flush post-handshake")?;
    }
    // Drain any post-handshake records the server queued (e.g. NewSessionTicket).
    capturing
        .inner
        .set_read_timeout(Some(Duration::from_millis(150)))?;
    let _ = tls.read_tls(&mut capturing);
    let _ = tls.process_new_packets();
    while tls.wants_write() {
        let _ = tls.write_tls(&mut capturing);
    }
    capturing
        .inner
        .set_read_timeout(Some(Duration::from_secs(15)))?;
    let server_epk = parse_server_hello_key_share(&capturing.inbound);
    let mut raw_outbound = capturing.outbound;
    let mut raw_inbound = capturing.inbound;
    let mut tcp = capturing.inner;

    let mut notary_tcp: TcpStream;

    // ── Phase 2: extract traffic secrets ──────────────────────────────────
    let secrets = tls.dangerous_extract_secrets().context("extract secrets")?;
    let (mut tx_seq, tx_secrets) = secrets.tx;
    let (mut rx_seq, rx_secrets) = secrets.rx;
    let (mut tx_key, tx_iv) = aes128_gcm_from_secrets(&tx_secrets)?;
    let (mut rx_key, rx_iv) = aes128_gcm_from_secrets(&rx_secrets)?;
    eprintln!(
        "phase 2: traffic secrets extracted (tx_seq={}, rx_seq={})",
        tx_seq, rx_seq
    );

    let k_c_tx = xor_key(&tx_key, &k_n_tx);
    let k_c_rx = xor_key(&rx_key, &k_n_rx);
    tx_key.zeroize();
    rx_key.zeroize();

    eprintln!("phase 3: finalizing setup with notary at {}", args.notary);
    notary_tcp = if let Some(mut nm) = notary_pre_tls {
        nm.write_all(&tx_iv).context("write IV_tx")?;
        nm.write_all(&rx_iv).context("write IV_rx")?;
        nm.flush().context("flush IVs")?;
        if args.skip_ecdh_wire {
            eprintln!("phase 3b: skipping ECDH wire (--skip-ecdh-wire)");
            host_skip_ecdh_leaky(&mut nm).context("write SETUP_ECDH_SKIP")?;
            nm.flush().context("flush ECDH skip")?;
        } else if let Some(epk) = server_epk {
            let host_share = host_ecdh_share
                .as_ref()
                .context("mode 1 requires host ECDH share from phase 0a")?;
            if args.leaky_ecdh_wire {
                eprintln!("phase 3b: leaky additive ECDH (debug — cleartext partials)");
                let notary_share = notary_ecdh_share
                    .as_ref()
                    .context("mode 1 requires notary ECDH share from phase 0a")?;
                let outcome = host_send_ecdh_leaky(&mut nm, host_share, notary_share, &epk)
                    .context("leaky ECDH wire")?;
                nm.flush().context("flush leaky ECDH")?;
                eprintln!(
                    "phase 3b: host-side IKM={} (both parties learn full IKM)",
                    hex_encode(&outcome.ikm.0)
                );
            } else {
                eprintln!("phase 3b: OT-blinded ECDH (server epk from ServerHello)");
                let outcome =
                    host_send_ecdh_ot(&mut nm, host_share, &epk).context("OT ECDH wire")?;
                nm.flush().context("flush OT ECDH")?;
                eprintln!(
                    "phase 3b: host XOR IKM share={} (full IKM not sent to host)",
                    hex_encode(&outcome.host_ikm_share)
                );
            }
        } else {
            eprintln!("phase 3b: no ServerHello key_share in capture — skipping ECDH");
            host_skip_ecdh_leaky(&mut nm).context("write SETUP_ECDH_SKIP")?;
            nm.flush().context("flush ECDH skip")?;
        }
        nm
    } else {
        rand::thread_rng().fill_bytes(&mut k_n_tx);
        rand::thread_rng().fill_bytes(&mut k_n_rx);

        let mut nm = TcpStream::connect(&args.notary)
            .with_context(|| format!("connect to notary {}", args.notary))?;
        nm.set_nodelay(true)?;
        nm.write_all(&[SETUP_LEGACY_HOST_MASKS])
            .context("write legacy setup mode")?;

        let mut setup = [0u8; 56];
        setup[..16].copy_from_slice(&k_n_tx);
        setup[16..28].copy_from_slice(&tx_iv);
        setup[28..44].copy_from_slice(&k_n_rx);
        setup[44..56].copy_from_slice(&rx_iv);
        nm.write_all(&setup).context("write legacy setup frame")?;
        nm.flush().context("flush legacy setup")?;
        nm
    };

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
    let session_result = Channel::with(&mut notary_tcp, |ch| -> swanky_error::Result<_> {
        // Encrypt request via 2PC; send the resulting record to the server.
        let mut wrk17 = Wrk17ClientSession::init(ch)?;
        let (ct, tag) = client_encrypt_record(ch, &mut wrk17, k_c_tx, tx_iv, &inner, &aad, tx_seq)?;
        tx_seq += 1;
        let mut record_payload = ct.clone();
        record_payload.extend_from_slice(&tag);
        let req_raw = match write_tls_record(&mut tcp, 0x17, 0x0303, &record_payload) {
            Ok(raw) => raw,
            Err(e) => {
                swanky_error::bail!(swanky_error::ErrorKind::NetworkError, "write request: {e}");
            }
        };
        raw_outbound.extend_from_slice(&req_raw);
        eprintln!(
            "phase 4: request record sent ({} bytes on wire)",
            req_raw.len()
        );

        // ── Phase 5: read response records, decrypt each via 2PC ──────
        let mut full = Vec::new();
        eprintln!("phase 5: reading response records");
        loop {
            let (ct_kind, _ver, payload, raw) = match read_tls_record(&mut tcp) {
                Ok(rec) => rec,
                Err(e) => {
                    eprintln!("record read ended: {e}");
                    break;
                }
            };
            raw_inbound.extend_from_slice(&raw);
            if ct_kind != 0x17 {
                eprintln!("unexpected record content type 0x{:02x}, stopping", ct_kind);
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

            let plain =
                client_decrypt_record(ch, &mut wrk17, k_c_rx, rx_iv, &ct, tag, &aad, rx_seq)?;
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

        // Ask the notary to sign the session bundle.
        let session_id = format!(
            "demo-{}-{}",
            host,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        eprintln!("phase 6: requesting signed bundle from notary");
        let bundle = client_finish_session(ch, &session_id, &host)?;
        Ok((
            full,
            bundle,
            raw_inbound,
            raw_outbound,
            k_c_tx,
            k_c_rx,
            tx_iv,
            rx_iv,
        ))
    })
    .map_err(|e| anyhow::anyhow!("notary session: {e:#}"))?;
    let (full_plaintext, bundle, raw_inbound, raw_outbound, k_c_tx, k_c_rx, tx_iv, rx_iv) =
        session_result;
    drop(notary_tcp);

    print_demo_output(
        &full_plaintext,
        &bundle,
        &host,
        &args,
        raw_inbound,
        raw_outbound,
        k_c_tx,
        k_c_rx,
        tx_iv,
        rx_iv,
    )
}

#[allow(clippy::too_many_arguments)]
fn print_demo_output(
    full_plaintext: &[u8],
    bundle: &notary::NotaryBundle,
    host: &str,
    args: &Args,
    raw_inbound: Vec<u8>,
    raw_outbound: Vec<u8>,
    k_c_tx: [u8; 16],
    k_c_rx: [u8; 16],
    mut tx_iv: [u8; 12],
    mut rx_iv: [u8; 12],
) -> Result<()> {
    let body = String::from_utf8_lossy(full_plaintext);
    println!("--- response ({} bytes) ---", full_plaintext.len());
    println!("{body}");

    println!("--- notary bundle ---");
    println!("  notary_pubkey:  {}", hex_encode(&bundle.notary_pubkey));
    println!("  timestamp_unix: {}", bundle.timestamp_unix);
    println!("  session_id:     {}", bundle.session_id);
    println!("  server_name:    {}", bundle.server_name);
    println!("  records:        {}", bundle.records.len());
    for r in &bundle.records {
        let op_label = match r.op {
            0x01 => "encrypt",
            0x02 => "decrypt",
            _ => "?",
        };
        println!(
            "    [{}] seq={} aad_len={} commit={}",
            op_label,
            r.seq,
            r.aad.len(),
            hex_encode(&r.commit_hash)
        );
    }
    println!("  signature:      {}", hex_encode(&bundle.signature));
    println!(
        "  verify():       {}",
        if bundle.verify() { "ok" } else { "FAIL" }
    );
    if bundle.bundle_version >= sp1_demo_common::NotaryBundle::BUNDLE_VERSION_BINDING {
        let b = &bundle.binding;
        println!("--- session binding ---");
        println!(
            "  server_epk:                 {}",
            hex_encode(&b.server_epk)
        );
        println!(
            "  cert_chain_hash:            {}",
            hex_encode(&b.cert_chain_hash)
        );
        println!(
            "  handshake_transcript_hash:  {}",
            hex_encode(&b.handshake_transcript_hash)
        );
        println!(
            "  key_schedule_context_hash:  {}",
            hex_encode(&b.key_schedule_context_hash)
        );
        println!("  garbling_mode:              {}", b.garbling_mode);
    }

    if let Some(out) = args.witness_out.as_ref() {
        use sp1_demo_common::{NotaryAttestation, TlsWitness};
        let witness = TlsWitness {
            esk_client: [0u8; 32],
            raw_inbound,
            raw_outbound,
            hostname: host.to_string(),
            json_field: args.field.clone(),
            threshold: args.threshold,
            notary: Some(NotaryAttestation {
                bundle: bundle.clone(),
                k_c_tx,
                k_c_rx,
            }),
        };
        let bytes = bincode::serialize(&witness).context("serialize TlsWitness")?;
        std::fs::write(out, &bytes).with_context(|| format!("write witness {}", out.display()))?;
        eprintln!(
            "wrote SP1 witness ({} bytes) to {}",
            bytes.len(),
            out.display()
        );
    }

    let mut k_c_tx_z = k_c_tx;
    let mut k_c_rx_z = k_c_rx;
    k_c_tx_z.zeroize();
    k_c_rx_z.zeroize();
    tx_iv.zeroize();
    rx_iv.zeroize();
    Ok(())
}

/// Pull `(key, iv)` out of `ConnectionTrafficSecrets`, requiring AES-128-GCM.
fn aes128_gcm_from_secrets(s: &rustls::ConnectionTrafficSecrets) -> Result<([u8; 16], [u8; 12])> {
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

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// Silence unused-warning for AeadKey/zeroize-related imports if the compiler complains.
#[allow(dead_code)]
fn _unused_imports(_: AeadKey) {}
