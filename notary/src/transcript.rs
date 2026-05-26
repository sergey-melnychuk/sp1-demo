//! TLS 1.3 handshake transcript hashes for 2PC key schedule (RFC 8446 §4.4).
//!
//! `transcript_after_client_finished` needs server handshake traffic keys to
//! decrypt post-ServerHello records. Callers may derive those keys via 2PC
//! (preferred) or a local reference oracle in tests.

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use sha2::{Digest, Sha256};

use crate::hkdf::{reference_empty_hash, reference_hkdf_expand_label, reference_hkdf_extract};

struct RawRecord {
    content_type: u8,
    legacy_version: u16,
    payload: Vec<u8>,
}

fn parse_records(bytes: &[u8]) -> Option<Vec<RawRecord>> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos + 5 <= bytes.len() {
        let ct = bytes[pos];
        let version = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]);
        let length = u16::from_be_bytes([bytes[pos + 3], bytes[pos + 4]]) as usize;
        pos += 5;
        if pos + length > bytes.len() {
            return None;
        }
        records.push(RawRecord {
            content_type: ct,
            legacy_version: version,
            payload: bytes[pos..pos + length].to_vec(),
        });
        pos += length;
    }
    Some(records)
}

fn xor_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    nonce
}

fn decrypt_hs_record(
    key: &[u8; 16],
    iv: &[u8; 12],
    seq: u64,
    record: &RawRecord,
) -> Option<(Vec<u8>, u8)> {
    if record.content_type != 0x17 {
        return None;
    }
    let nonce = xor_nonce(iv, seq);
    let aad = crate::tls::tls13_aad(record.payload.len());
    let mut buf = record.payload.clone();
    if buf.len() < 16 {
        return None;
    }
    Aes128Gcm::new(key.into())
        .decrypt_in_place(Nonce::from_slice(&nonce), &aad, &mut buf)
        .ok()?;
    let inner_ct = *buf.last()?;
    buf.pop();
    Some((buf, inner_ct))
}

fn hs_header(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut h = vec![msg_type];
    let len = body.len();
    h.push(((len >> 16) & 0xff) as u8);
    h.push(((len >> 8) & 0xff) as u8);
    h.push((len & 0xff) as u8);
    h
}

fn parse_handshake_messages(payload: &[u8]) -> Option<Vec<(u8, Vec<u8>)>> {
    let mut out = Vec::new();
    let mut p = 0;
    while p + 4 <= payload.len() {
        let ty = payload[p];
        let len = ((payload[p + 1] as usize) << 16)
            | ((payload[p + 2] as usize) << 8)
            | (payload[p + 3] as usize);
        p += 4;
        if p + len > payload.len() {
            return None;
        }
        out.push((ty, payload[p..p + len].to_vec()));
        p += len;
    }
    Some(out)
}

/// `SHA256(ClientHello || ServerHello)` from cleartext handshake records.
pub fn transcript_after_server_hello(raw_outbound: &[u8], raw_inbound: &[u8]) -> Option<[u8; 32]> {
    let out = parse_records(raw_outbound)?;
    let inp = parse_records(raw_inbound)?;
    let ch = out.iter().find(|r| r.content_type == 22)?;
    let sh = inp.iter().find(|r| r.content_type == 22)?;
    let mut h = Sha256::new();
    h.update(&ch.payload);
    h.update(&sh.payload);
    Some(h.finalize().into())
}

/// Reference server handshake traffic keys (for transcript parsing in tests / host helper).
pub fn reference_server_hs_keys(
    ikm: &[u8; 32],
    transcript_after_sh: &[u8; 32],
) -> ([u8; 16], [u8; 12]) {
    let empty = reference_empty_hash();
    let early = reference_hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let derived1 = reference_hkdf_expand_label(&early, "derived", &empty, 32);
    let hs = reference_hkdf_extract(&derived1, ikm);
    let server_hs = reference_hkdf_expand_label(&hs, "s hs traffic", transcript_after_sh, 32);
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    key.copy_from_slice(&reference_hkdf_expand_label(&server_hs, "key", &[], 16)[..16]);
    iv.copy_from_slice(&reference_hkdf_expand_label(&server_hs, "iv", &[], 12)[..12]);
    (key, iv)
}

/// Reference client handshake traffic keys (decrypt outbound ClientFinished).
pub fn reference_client_hs_keys(
    ikm: &[u8; 32],
    transcript_after_sh: &[u8; 32],
) -> ([u8; 16], [u8; 12]) {
    let empty = reference_empty_hash();
    let early = reference_hkdf_extract(&[0u8; 32], &[0u8; 32]);
    let derived1 = reference_hkdf_expand_label(&early, "derived", &empty, 32);
    let hs = reference_hkdf_extract(&derived1, ikm);
    let client_hs = reference_hkdf_expand_label(&hs, "c hs traffic", transcript_after_sh, 32);
    let mut key = [0u8; 16];
    let mut iv = [0u8; 12];
    key.copy_from_slice(&reference_hkdf_expand_label(&client_hs, "key", &[], 16)[..16]);
    iv.copy_from_slice(&reference_hkdf_expand_label(&client_hs, "iv", &[], 12)[..12]);
    (key, iv)
}

fn append_hs_messages(messages: &mut Vec<Vec<u8>>, plain: &[u8], inner_ct: u8) -> Option<bool> {
    if inner_ct != 22 {
        return Some(false);
    }
    let mut saw_finished = false;
    for (ty, body) in parse_handshake_messages(plain)? {
        let raw: Vec<u8> = hs_header(ty, &body).into_iter().chain(body).collect();
        if ty == 20 {
            saw_finished = true;
        }
        messages.push(raw);
    }
    Some(saw_finished)
}

/// Transcript hash through ServerFinished (RFC 8446 §7.1 — context for `c ap traffic`).
pub fn transcript_after_server_finished(
    raw_outbound: &[u8],
    raw_inbound: &[u8],
    ikm: &[u8; 32],
) -> Option<[u8; 32]> {
    let after_sh = transcript_after_server_hello(raw_outbound, raw_inbound)?;
    let (server_hs_key, server_hs_iv) = reference_server_hs_keys(ikm, &after_sh);

    let out = parse_records(raw_outbound)?;
    let inp = parse_records(raw_inbound)?;
    let ch = out.iter().find(|r| r.content_type == 22)?;
    let sh = inp.iter().find(|r| r.content_type == 22)?;

    let mut messages: Vec<Vec<u8>> = Vec::new();
    messages.push(ch.payload.clone());
    messages.push(sh.payload.clone());

    let mut server_hs_seq = 0u64;
    let mut saw_server_finished = false;

    for r in &inp {
        if r.content_type != 0x17 || saw_server_finished {
            continue;
        }
        let (plain, inner_ct) =
            decrypt_hs_record(&server_hs_key, &server_hs_iv, server_hs_seq, r)?;
        server_hs_seq += 1;
        if append_hs_messages(&mut messages, &plain, inner_ct)? {
            saw_server_finished = true;
        }
    }

    if !saw_server_finished || messages.len() < 6 {
        return None;
    }
    let mut h = Sha256::new();
    for m in &messages {
        h.update(m);
    }
    Some(h.finalize().into())
}

/// Transcript hash through ClientFinished (resumption / verify-data context).
pub fn transcript_after_client_finished(
    raw_outbound: &[u8],
    raw_inbound: &[u8],
    ikm: &[u8; 32],
) -> Option<[u8; 32]> {
    let after_sh = transcript_after_server_hello(raw_outbound, raw_inbound)?;
    let (server_hs_key, server_hs_iv) = reference_server_hs_keys(ikm, &after_sh);
    let (client_hs_key, client_hs_iv) = reference_client_hs_keys(ikm, &after_sh);

    let out = parse_records(raw_outbound)?;
    let inp = parse_records(raw_inbound)?;
    let ch = out.iter().find(|r| r.content_type == 22)?;
    let sh = inp.iter().find(|r| r.content_type == 22)?;

    let mut messages: Vec<Vec<u8>> = Vec::new();
    messages.push(ch.payload.clone());
    messages.push(sh.payload.clone());

    let mut server_hs_seq = 0u64;
    let mut client_hs_seq = 0u64;
    let mut saw_server_finished = false;
    let mut saw_client_finished = false;

    for r in &inp {
        if r.content_type != 0x17 || saw_server_finished {
            continue;
        }
        let (plain, inner_ct) =
            decrypt_hs_record(&server_hs_key, &server_hs_iv, server_hs_seq, r)?;
        server_hs_seq += 1;
        if append_hs_messages(&mut messages, &plain, inner_ct)? {
            saw_server_finished = true;
        }
    }

    for r in &out {
        if r.content_type != 0x17 || saw_client_finished {
            continue;
        }
        let (plain, inner_ct) =
            decrypt_hs_record(&client_hs_key, &client_hs_iv, client_hs_seq, r)?;
        client_hs_seq += 1;
        if append_hs_messages(&mut messages, &plain, inner_ct)? {
            saw_client_finished = true;
            break;
        }
    }

    if !saw_client_finished || messages.len() < 7 {
        return None;
    }
    let mut h = Sha256::new();
    for m in &messages {
        h.update(m);
    }
    Some(h.finalize().into())
}

/// `(after_server_hello, after_server_finished)` for TLS 1.3 app traffic key schedule.
pub fn transcript_hashes_with_ikm(
    raw_outbound: &[u8],
    raw_inbound: &[u8],
    ikm: &[u8; 32],
) -> Option<([u8; 32], [u8; 32])> {
    let after_sh = transcript_after_server_hello(raw_outbound, raw_inbound)?;
    let after_sf = transcript_after_server_finished(raw_outbound, raw_inbound, ikm)?;
    Some((after_sh, after_sf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ecdh::{combined_client_esk, generate_share, reference_ikm};
    use crate::hkdf::{
        reference_empty_hash, reference_hkdf_expand_label, reference_hkdf_extract,
        reference_tls13_client_traffic,
    };
    use rand::rngs::OsRng;
    use rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256;
    use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
    use rustls::crypto::ring::default_provider;
    use rustls::{ClientConfig, ClientConnection, Error, KeyLog, NamedGroup, RootCertStore};
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};
    use x25519_dalek::{PublicKey, StaticSecret};

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

    struct Cap {
        inner: std::net::TcpStream,
        inbound: Vec<u8>,
        outbound: Vec<u8>,
    }

    #[derive(Default, Debug)]
    struct LogSecrets {
        server_hs: Option<[u8; 32]>,
    }

    #[derive(Clone, Debug)]
    struct Log(Arc<Mutex<LogSecrets>>);

    impl KeyLog for Log {
        fn log(&self, label: &str, _: &[u8], secret: &[u8]) {
            if label == "SERVER_HANDSHAKE_TRAFFIC_SECRET" {
                let mut g = self.0.lock().unwrap();
                let mut s = [0u8; 32];
                s.copy_from_slice(secret);
                g.server_hs = Some(s);
            }
        }
    }

    impl Read for Cap {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.inbound.extend_from_slice(&buf[..n]);
            Ok(n)
        }
    }

    impl Write for Cap {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let n = self.inner.write(buf)?;
            self.outbound.extend_from_slice(&buf[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }

    #[test]
    #[ignore = "network integration test"]
    fn transcript_hashes_match_rustls_extract() {
        let host = "jsonplaceholder.typicode.com";
        let tcp = std::net::TcpStream::connect(format!("{host}:443")).expect("connect");
        tcp.set_read_timeout(Some(std::time::Duration::from_secs(15)))
            .ok();
        let mut cap = Cap {
            inner: tcp,
            inbound: Vec::new(),
            outbound: Vec::new(),
        };

        let host_share = generate_share(&mut OsRng);
        let notary_share = generate_share(&mut OsRng);
        let esk = combined_client_esk(&host_share, &notary_share);
        let kx: &'static dyn SupportedKxGroup = Box::leak(Box::new(ExternalKxGroup { esk_client: esk }));
        let mut provider = default_provider();
        provider.kx_groups = vec![kx];
        provider.cipher_suites = vec![TLS13_AES_128_GCM_SHA256];
        let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_root_certificates(RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            })
            .with_no_client_auth();
        config.enable_secret_extraction = true;
        let key_log = Arc::new(Mutex::new(LogSecrets::default()));
        config.key_log = Arc::new(Log(key_log.clone()));

        let sn: rustls::pki_types::ServerName = host.try_into().unwrap();
        let mut tls = ClientConnection::new(Arc::new(config), sn).unwrap();
        while tls.is_handshaking() {
            if tls.wants_write() {
                tls.write_tls(&mut cap).unwrap();
            }
            if tls.wants_read() {
                tls.read_tls(&mut cap).unwrap();
                tls.process_new_packets().unwrap();
            }
        }
        while tls.wants_write() {
            tls.write_tls(&mut cap).unwrap();
        }

        let out_recs = parse_records(&cap.outbound).expect("out recs");
        let in_recs = parse_records(&cap.inbound).expect("in recs");
        let out_len: usize = out_recs.iter().map(|r| 5 + r.payload.len()).sum();
        let in_len: usize = in_recs.iter().map(|r| 5 + r.payload.len()).sum();
        assert_eq!(out_len, cap.outbound.len(), "out parse consumed");
        assert_eq!(in_len, cap.inbound.len(), "in parse consumed");

        let server_epk = crate::ecdh::parse_server_hello_key_share(&cap.inbound).expect("epk");
        let ikm = reference_ikm(&host_share, &notary_share, &server_epk);
        let esk = combined_client_esk(&host_share, &notary_share);
        let ss = StaticSecret::from(esk).diffie_hellman(&PublicKey::from(server_epk));
        assert_eq!(ss.as_bytes(), ikm.0.as_slice(), "ikm vs x25519");

        let (after_sh, after_sf) =
            transcript_hashes_with_ikm(&cap.outbound, &cap.inbound, &ikm.0).expect("hashes");

        let empty = reference_empty_hash();
        let early = reference_hkdf_extract(&[0u8; 32], &[0u8; 32]);
        let derived1 = reference_hkdf_expand_label(&early, "derived", &empty, 32);
        let hs = reference_hkdf_extract(&derived1, &ikm.0);
        let expect_server_hs =
            reference_hkdf_expand_label(&hs, "s hs traffic", &after_sh, 32);
        assert_eq!(
            key_log.lock().unwrap().server_hs.as_ref(),
            Some(&expect_server_hs),
            "server hs secret vs keylog"
        );

        let secrets = tls.dangerous_extract_secrets().unwrap();
        let (_, rust_tx) = secrets.tx;
        let (_, rust_rx) = secrets.rx;
        let (tx_key, tx_iv, rx_key, rx_iv) =
            reference_tls13_client_traffic(&ikm.0, &after_sh, &after_sf);

        use rustls::ConnectionTrafficSecrets;
        match &rust_tx {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                assert_eq!(key.as_ref(), tx_key.as_slice());
                assert_eq!(iv.as_ref(), tx_iv.as_slice());
            }
            _ => panic!("expected aes128"),
        }
        match &rust_rx {
            ConnectionTrafficSecrets::Aes128Gcm { key, iv } => {
                assert_eq!(key.as_ref(), rx_key.as_slice());
                assert_eq!(iv.as_ref(), rx_iv.as_slice());
            }
            _ => panic!("expected aes128"),
        }
    }
}
