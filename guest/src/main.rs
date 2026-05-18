#![no_main]
sp1_zkvm::entrypoint!(main);

use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes128Gcm,
};
use der::Decode;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use p256::ecdsa::{signature::Verifier as EcVerifier, DerSignature, VerifyingKey};
use p384::ecdsa::{
    signature::Verifier as P384Verifier, DerSignature as P384DerSignature,
    VerifyingKey as P384VerifyingKey,
};
use rsa::{pkcs1v15, pkcs8::DecodePublicKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use sp1_demo_common::{PublicClaim, TlsWitness};
use x25519_dalek::{PublicKey, StaticSecret};
use x509_cert::Certificate;

pub fn main() {
    let witness: TlsWitness = sp1_zkvm::io::read();

    // -----------------------------------------------------------------------
    // 1. Parse ClientHello key_share → epk_client_wire.  RFC 8446 §4.1.2, §4.2.8
    //    Assert epk_client_wire == esk_client × G.
    //    The server's CertificateVerify (step 9) signs the transcript that
    //    includes ClientHello, which includes epk_client.  This assertion
    //    ties the proof to the specific ephemeral key used in the handshake.
    // -----------------------------------------------------------------------
    let epk_client_wire = parse_client_hello_key_share(&witness.raw_outbound)
        .expect("epk_client not found in ClientHello key_share");

    let derived_epk = PublicKey::from(&StaticSecret::from(witness.esk_client));
    assert_eq!(
        derived_epk.as_bytes(),
        &epk_client_wire,
        "epk_client in ClientHello does not match esk_client"
    );

    // -----------------------------------------------------------------------
    // 2. Parse ServerHello key_share → epk_server.  RFC 8446 §4.1.3, §4.2.8
    //    ServerHello key_share contains a single KeyShareEntry (unlike
    //    ClientHello which sends a list).  NamedGroup 0x001d = X25519.
    // -----------------------------------------------------------------------
    let epk_server_bytes = parse_server_hello_key_share(&witness.raw_inbound)
        .expect("epk_server not found in ServerHello key_share");

    // -----------------------------------------------------------------------
    // 3. X25519 ECDH + HKDF key schedule.  RFC 8446 §7.1
    //
    //    shared_secret = X25519(esk_client, epk_server)
    //
    //    early_secret  = HKDF-Extract(0×00·32, 0×00·32)
    //    derived1      = HKDF-Expand-Label(early_secret, "derived", SHA256(""), 32)
    //    hs_secret     = HKDF-Extract(derived1, shared_secret)
    //    server_hs_secret = HKDF-Expand-Label(hs_secret, "s hs traffic", transcript_after_sh, 32)
    //    derived2      = HKDF-Expand-Label(hs_secret, "derived", SHA256(""), 32)
    //    master_secret = HKDF-Extract(derived2, 0×00·32)
    //
    //    transcript_after_sh = SHA256(ClientHello || ServerHello)
    // -----------------------------------------------------------------------
    let client_secret = StaticSecret::from(witness.esk_client);
    let server_pub = PublicKey::from(epk_server_bytes);
    let ecdh = client_secret.diffie_hellman(&server_pub);

    // Build transcript hash after ServerHello for HS key derivation.
    // Need to find the raw ClientHello and ServerHello message bytes.
    let ch_sh_transcript = {
        // outbound first record payload = ClientHello message (type 22 record, payload is the HS messages)
        let out_records = parse_records(&witness.raw_outbound);
        let in_records = parse_records(&witness.raw_inbound);

        let ch_payload = out_records
            .iter()
            .find(|r| r.content_type == 22)
            .expect("ClientHello record not found")
            .payload
            .clone();

        let sh_payload = in_records
            .iter()
            .find(|r| r.content_type == 22)
            .expect("ServerHello record not found")
            .payload
            .clone();

        let mut h = Sha256::new();
        h.update(&ch_payload);
        h.update(&sh_payload);
        h.finalize()
    };
    let transcript_after_sh: [u8; 32] = ch_sh_transcript.into();

    let (early_secret, _) = Hkdf::<Sha256>::extract(Some(&[0u8; 32]), &[0u8; 32]);
    let derived1 = expand_label(&early_secret, "derived", &empty_hash(), 32);
    let (hs_secret, _) = Hkdf::<Sha256>::extract(Some(&derived1), ecdh.as_bytes());

    let server_hs_secret = expand_label(&hs_secret, "s hs traffic", &transcript_after_sh, 32);

    let derived2 = expand_label(&hs_secret, "derived", &empty_hash(), 32);
    let (master_secret, _) = Hkdf::<Sha256>::extract(Some(&derived2), &[0u8; 32]);

    // -----------------------------------------------------------------------
    // 4. Decrypt encrypted handshake records.  RFC 8446 §5.2, §4.4
    //
    //    Encrypted records have outer content_type=23 (application_data).
    //    After AES-128-GCM decryption the last byte is the inner content
    //    type (22 = handshake).  RFC 8446 §5.2
    //
    //    hs_key = HKDF-Expand-Label(server_hs_secret, "key", "", 16)
    //    hs_iv  = HKDF-Expand-Label(server_hs_secret, "iv",  "", 12)
    //    nonce  = hs_iv XOR seq  (seq resets to 0 for each key)
    //
    //    Expected handshake messages in order:
    //      8  EncryptedExtensions   RFC 8446 §4.3.1
    //     11  Certificate           RFC 8446 §4.4.2
    //     15  CertificateVerify     RFC 8446 §4.4.3
    //     20  Finished              RFC 8446 §4.4.4
    // -----------------------------------------------------------------------
    let hs_key_vec = expand_label(&server_hs_secret, "key", &[], 16);
    let hs_iv_vec = expand_label(&server_hs_secret, "iv", &[], 12);
    let mut hs_key = [0u8; 16];
    let mut hs_iv = [0u8; 12];
    hs_key.copy_from_slice(&hs_key_vec);
    hs_iv.copy_from_slice(&hs_iv_vec);

    let out_records = parse_records(&witness.raw_outbound);
    let in_records = parse_records(&witness.raw_inbound);

    // Handshake transcript messages in order: [CH, SH, EE, Cert, CertVerify, Finished]
    let mut handshake_messages: Vec<Vec<u8>> = Vec::new();

    let ch_payload = out_records
        .iter()
        .find(|r| r.content_type == 22)
        .expect("ClientHello not found")
        .payload
        .clone();
    handshake_messages.push(ch_payload);

    let sh_payload = in_records
        .iter()
        .find(|r| r.content_type == 22)
        .expect("ServerHello not found")
        .payload
        .clone();
    handshake_messages.push(sh_payload);

    const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
    const HS_CERTIFICATE: u8 = 11;
    const HS_CERTIFICATE_VERIFY: u8 = 15;
    const HS_FINISHED: u8 = 20;

    let mut hs_seq: u64 = 0;
    let mut cert_chain_der: Option<Vec<Vec<u8>>> = None;
    let mut cert_verify_msg: Option<Vec<u8>> = None;
    let mut server_finished_body: Option<Vec<u8>> = None;
    let mut handshake_done = false;
    let mut encrypted_app_records: Vec<Vec<u8>> = Vec::new();

    for r in &in_records {
        if r.content_type != 23 {
            continue;
        }
        if handshake_done {
            encrypted_app_records.push(record_to_bytes(r));
            continue;
        }

        let (plaintext, inner_ct) =
            decrypt_record(&hs_key, &hs_iv, hs_seq, r).expect("HS record decrypt failed");
        hs_seq += 1;

        if inner_ct == 23 {
            // Application data snuck in before Finished — treat as app record.
            handshake_done = true;
            encrypted_app_records.push(record_to_bytes(r));
            continue;
        }

        let msgs = parse_handshake_messages(&plaintext).expect("parse HS messages failed");
        for msg in &msgs {
            let raw: Vec<u8> = hs_header(msg).iter().chain(&msg.body).copied().collect();
            match msg.msg_type {
                HS_ENCRYPTED_EXTENSIONS => {
                    handshake_messages.push(raw);
                }
                HS_CERTIFICATE => {
                    cert_chain_der =
                        Some(parse_cert_message(&msg.body).expect("parse Certificate failed"));
                    handshake_messages.push(raw);
                }
                HS_CERTIFICATE_VERIFY => {
                    cert_verify_msg = Some(msg.body.clone());
                    handshake_messages.push(raw);
                }
                HS_FINISHED => {
                    server_finished_body = Some(msg.body.clone());
                    handshake_messages.push(raw);
                    handshake_done = true;
                }
                _ => {
                    handshake_messages.push(raw);
                }
            }
        }
    }

    assert!(
        handshake_messages.len() >= 6,
        "need at least 6 handshake messages, got {}",
        handshake_messages.len()
    );

    let cert_chain_der = cert_chain_der.expect("Certificate message not found");
    let cert_verify_msg = cert_verify_msg.expect("CertificateVerify not found");
    let server_finished_body = server_finished_body.expect("ServerFinished not found");

    // -----------------------------------------------------------------------
    // 5. Transcript hashes.  RFC 8446 §4.4 (transcript hash definition)
    //
    //    transcript_before_cv       = SHA256(CH || SH || EE || Cert)
    //    transcript_before_finished = SHA256(CH || SH || EE || Cert || CV)
    //    transcript_after_finished  = SHA256(CH || SH || EE || Cert || CV || Fin)
    //
    //    Each hash covers the 4-byte handshake header (type + 3-byte length)
    //    plus the message body, exactly as transmitted on the wire.
    // -----------------------------------------------------------------------
    let transcript_before_cv: [u8; 32] = {
        let mut h = Sha256::new();
        for msg in &handshake_messages[..4] {
            h.update(msg);
        }
        h.finalize().into()
    };

    let transcript_before_finished: [u8; 32] = {
        let mut h = Sha256::new();
        for msg in &handshake_messages[..5] {
            h.update(msg);
        }
        h.finalize().into()
    };

    let transcript_after_finished: [u8; 32] = {
        let mut h = Sha256::new();
        for msg in &handshake_messages[..6] {
            h.update(msg);
        }
        h.finalize().into()
    };

    // -----------------------------------------------------------------------
    // 6. Verify Server Finished HMAC.  RFC 8446 §4.4.4
    //
    //    finished_key  = HKDF-Expand-Label(server_hs_secret, "finished", "", 32)
    //    verify_data   = HMAC-SHA256(finished_key, transcript_before_finished)
    //
    //    Proves the server completed the handshake: only a party that derived
    //    server_hs_secret (i.e. performed X25519 with the real server) can
    //    produce a valid verify_data.
    // -----------------------------------------------------------------------
    let finished_key = expand_label(&server_hs_secret, "finished", &[], 32);
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&finished_key).unwrap();
    mac.update(&transcript_before_finished);
    let expected_verify_data = mac.finalize().into_bytes();
    assert_eq!(
        expected_verify_data.as_ref() as &[u8],
        server_finished_body.as_slice(),
        "Server Finished HMAC verification failed"
    );

    // -----------------------------------------------------------------------
    // 7. Certificate chain verification.  RFC 8446 §4.4.2, RFC 5280 §6
    //
    //    Walk chain[0] (leaf) → chain[n-1], verify each cert's signature
    //    against the next cert's SPKI (or a trust anchor from webpki-roots).
    //    Trust anchor matching: subject bytes or last-cert issuer bytes
    //    compared against Mozilla root store (webpki-roots crate).
    //    Supported signature algorithms: ECDSA-P256-SHA256, ECDSA-P384-SHA384,
    //    RSA-PKCS1-SHA256, RSA-PKCS1-SHA384.  RFC 5280 §4.1.1.2
    // -----------------------------------------------------------------------
    let chain: Vec<Certificate> = cert_chain_der
        .iter()
        .map(|der| Certificate::from_der(der).expect("invalid DER cert"))
        .collect();

    assert!(!chain.is_empty(), "empty cert chain");

    let (anchor_boundary, anchor_spki) = find_trust_anchor(&chain, &cert_chain_der);

    for i in 0..anchor_boundary {
        let issuer_spki = if i + 1 < anchor_boundary {
            chain[i + 1].tbs_certificate.subject_public_key_info.clone()
        } else {
            anchor_spki.clone()
        };
        verify_cert_signature(&chain[i], &issuer_spki);
    }

    // -----------------------------------------------------------------------
    // 8. Hostname verification via leaf cert SAN.  RFC 9525, RFC 5280 §4.2.1.6
    //
    //    Check SubjectAltName extension (OID 2.5.29.17) for a dNSName entry
    //    matching the requested hostname.  Wildcard: *.example.com matches
    //    foo.example.com but not foo.bar.example.com (single label only).
    //    RFC 9525 §6.3 prohibits multi-level wildcard matching.
    // -----------------------------------------------------------------------
    verify_hostname(&chain[0], &witness.hostname);

    // -----------------------------------------------------------------------
    // 9. CertificateVerify.  RFC 8446 §4.4.3, §4.2.3
    //
    //    signed_content = 0x20×64 || "TLS 1.3, server CertificateVerify" || 0x00
    //                     || transcript_before_cv
    //
    //    The 64-byte padding and context string prevent cross-protocol attacks.
    //    Supported signature schemes (RFC 8446 §4.2.3):
    //      0x0403  ecdsa_secp256r1_sha256  (P-256)
    //      0x0503  ecdsa_secp384r1_sha384  (P-384)
    //      0x0804  rsa_pss_rsae_sha256
    //      0x0805  rsa_pss_rsae_sha384
    //      0x0401  rsa_pkcs1_sha256
    //
    //    This is the key security step: proves the real server (holder of the
    //    cert private key) signed a transcript that includes epk_client.
    // -----------------------------------------------------------------------
    let cv_msg = &cert_verify_msg;
    assert!(cv_msg.len() >= 4, "CertificateVerify too short");
    let scheme = u16::from_be_bytes([cv_msg[0], cv_msg[1]]);
    let sig_len = u16::from_be_bytes([cv_msg[2], cv_msg[3]]) as usize;
    assert!(cv_msg.len() >= 4 + sig_len, "CertificateVerify truncated");
    let sig_bytes = &cv_msg[4..4 + sig_len];

    let mut signed_content = vec![0x20u8; 64];
    signed_content.extend_from_slice(b"TLS 1.3, server CertificateVerify");
    signed_content.push(0x00);
    signed_content.extend_from_slice(&transcript_before_cv);

    let leaf_spki = &chain[0].tbs_certificate.subject_public_key_info;
    let leaf_pk = leaf_spki.subject_public_key.raw_bytes();

    match scheme {
        0x0403 => {
            let vk = VerifyingKey::from_sec1_bytes(leaf_pk).expect("leaf cert not P-256");
            let sig = DerSignature::try_from(sig_bytes).expect("invalid ECDSA-P256 sig DER");
            vk.verify(&signed_content, &sig)
                .expect("CertificateVerify ECDSA-P256 sig invalid");
        }
        0x0503 => {
            let vk = P384VerifyingKey::from_sec1_bytes(leaf_pk).expect("leaf cert not P-384");
            let sig = P384DerSignature::try_from(sig_bytes).expect("invalid ECDSA-P384 sig DER");
            P384Verifier::verify(&vk, &signed_content, &sig)
                .expect("CertificateVerify ECDSA-P384 sig invalid");
        }
        0x0804 => {
            use der::Encode;
            use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVk};
            let spki_der = leaf_spki.to_der().expect("encode leaf SPKI");
            let pk = RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA leaf key");
            let vk = PssVk::<Sha256>::new(pk);
            let sig = PssSignature::try_from(sig_bytes).expect("invalid RSA-PSS sig");
            rsa::signature::Verifier::verify(&vk, &signed_content, &sig)
                .expect("CertificateVerify RSA-PSS-SHA256 sig invalid");
        }
        0x0805 => {
            use der::Encode;
            use rsa::pss::{Signature as PssSignature, VerifyingKey as PssVk};
            use sha2::Sha384;
            let spki_der = leaf_spki.to_der().expect("encode leaf SPKI");
            let pk = RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA leaf key");
            let vk = PssVk::<Sha384>::new(pk);
            let sig = PssSignature::try_from(sig_bytes).expect("invalid RSA-PSS sig");
            rsa::signature::Verifier::verify(&vk, &signed_content, &sig)
                .expect("CertificateVerify RSA-PSS-SHA384 sig invalid");
        }
        0x0401 => {
            use der::Encode;
            let spki_der = leaf_spki.to_der().expect("encode leaf SPKI");
            let pk = RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA leaf key");
            let vk = pkcs1v15::VerifyingKey::<Sha256>::new(pk);
            let sig = pkcs1v15::Signature::try_from(sig_bytes).expect("invalid RSA-PKCS1 sig");
            rsa::signature::Verifier::verify(&vk, &signed_content, &sig)
                .expect("CertificateVerify RSA-PKCS1-SHA256 sig invalid");
        }
        other => panic!("unsupported CertificateVerify scheme: 0x{:04x}", other),
    }

    // -----------------------------------------------------------------------
    // 10. App traffic key derivation + application record decryption.
    //     RFC 8446 §7.3 (traffic key calculation), §5.2, §5.3
    //
    //     server_app_secret = HKDF-Expand-Label(master_secret, "s ap traffic",
    //                                           transcript_after_finished, 32)
    //     app_key = HKDF-Expand-Label(server_app_secret, "key", "", 16)
    //     app_iv  = HKDF-Expand-Label(server_app_secret, "iv",  "", 12)
    //     nonce   = app_iv XOR seq_be  (RFC 8446 §5.3)
    //     aad     = 5-byte TLS record header  (RFC 8446 §5.2)
    // -----------------------------------------------------------------------
    let server_app_secret = expand_label(
        &master_secret,
        "s ap traffic",
        &transcript_after_finished,
        32,
    );

    let app_key_vec = expand_label(&server_app_secret, "key", &[], 16);
    let app_iv_vec = expand_label(&server_app_secret, "iv", &[], 12);
    let mut app_key = [0u8; 16];
    let mut app_iv = [0u8; 12];
    app_key.copy_from_slice(&app_key_vec);
    app_iv.copy_from_slice(&app_iv_vec);

    // Sequence-number continuity: the AES-128-GCM nonce is `app_iv XOR seq`,
    // so if the host omits any record in the middle the subsequent decryptions
    // will use the wrong nonce and GCM auth will fail.  Records at the tail
    // can still be withheld without triggering this check; protection against
    // tail omission requires verifying HTTP response completeness (Content-
    // Length or terminal chunked boundary) — tracked in NEXT.md.
    let mut plaintext = Vec::new();
    for (seq, record_bytes) in encrypted_app_records.iter().enumerate() {
        assert!(record_bytes.len() >= 5);
        let ct = record_bytes[0];
        let version = u16::from_be_bytes([record_bytes[1], record_bytes[2]]);
        let payload = &record_bytes[5..];

        let nonce = xor_nonce(&app_iv, seq as u64);
        let aad = {
            let mut h = [0u8; 5];
            h[0] = ct;
            h[1..3].copy_from_slice(&version.to_be_bytes());
            h[3..5].copy_from_slice(&(payload.len() as u16).to_be_bytes());
            h
        };

        let tag_start = payload.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&payload[tag_start..]);
        let mut buf = payload[..tag_start].to_vec();

        <Aes128Gcm as KeyInit>::new(&app_key.into())
            .decrypt_in_place_detached(nonce.as_ref().into(), &aad, &mut buf, &tag.into())
            .expect("AES-GCM app record auth failed");

        let inner_ct = *buf.last().expect("empty decrypted record");
        buf.pop();
        if inner_ct == 23 {
            plaintext.extend_from_slice(&buf);
        }
    }

    // -----------------------------------------------------------------------
    // 11. HTTP/1.1 response parsing + JSON assertion.
    //     RFC 9112 §6.1 (chunked transfer encoding), RFC 6901 (JSON Pointer)
    // -----------------------------------------------------------------------
    let response = String::from_utf8(plaintext).expect("response is not UTF-8");
    let raw_body = response.split("\r\n\r\n").nth(1).unwrap_or("");
    let body = unchunk(raw_body);

    let json: serde_json::Value = serde_json::from_str(&body).expect("body is not valid JSON");

    let field_value = json
        .pointer(&witness.json_field)
        .unwrap_or_else(|| panic!("field '{}' not found", witness.json_field))
        .as_f64()
        .unwrap_or_else(|| panic!("field '{}' is not a number", witness.json_field));

    assert!(
        field_value > witness.threshold,
        "{} = {} is not > {}",
        witness.json_field,
        field_value,
        witness.threshold
    );

    // -----------------------------------------------------------------------
    // 12. Commit public values.
    // -----------------------------------------------------------------------
    sp1_zkvm::io::commit(&PublicClaim {
        host: witness.hostname,
        field: witness.json_field,
        threshold: witness.threshold,
        value: field_value,
    });
}

// ---------------------------------------------------------------------------
// TLS record layer
// ---------------------------------------------------------------------------

struct RawRecord {
    content_type: u8,
    legacy_version: u16,
    payload: Vec<u8>,
}

// TLS record header: content_type(1) + legacy_version(2) + length(2).  RFC 8446 §5.1
fn parse_records(bytes: &[u8]) -> Vec<RawRecord> {
    let mut records = Vec::new();
    let mut pos = 0;
    while pos + 5 <= bytes.len() {
        let ct = bytes[pos];
        let version = u16::from_be_bytes([bytes[pos + 1], bytes[pos + 2]]);
        let length = u16::from_be_bytes([bytes[pos + 3], bytes[pos + 4]]) as usize;
        pos += 5;
        assert!(pos + length <= bytes.len(), "truncated TLS record");
        records.push(RawRecord {
            content_type: ct,
            legacy_version: version,
            payload: bytes[pos..pos + length].to_vec(),
        });
        pos += length;
    }
    records
}

fn record_to_bytes(r: &RawRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + r.payload.len());
    out.push(r.content_type);
    out.extend_from_slice(&r.legacy_version.to_be_bytes());
    out.extend_from_slice(&(r.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&r.payload);
    out
}

// Decrypt one TLS 1.3 record; strip inner content type byte.  RFC 8446 §5.2
fn decrypt_record(
    key: &[u8; 16],
    iv: &[u8; 12],
    seq: u64,
    record: &RawRecord,
) -> Result<(Vec<u8>, u8), &'static str> {
    let nonce = xor_nonce(iv, seq);
    let aad = {
        let mut h = [0u8; 5];
        h[0] = record.content_type;
        h[1..3].copy_from_slice(&record.legacy_version.to_be_bytes());
        h[3..5].copy_from_slice(&(record.payload.len() as u16).to_be_bytes());
        h
    };

    let mut buf = record.payload.clone();
    if buf.len() < 16 {
        return Err("record too short for GCM tag");
    }
    let tag_start = buf.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&buf[tag_start..]);
    buf.truncate(tag_start);

    <Aes128Gcm as KeyInit>::new(key.into())
        .decrypt_in_place_detached(nonce.as_ref().into(), &aad, &mut buf, &tag.into())
        .map_err(|_| "AES-GCM authentication failed")?;

    let inner_ct = *buf.last().ok_or("empty decrypted record")?;
    buf.pop();
    Ok((buf, inner_ct))
}

// ---------------------------------------------------------------------------
// Handshake message parsing
// ---------------------------------------------------------------------------

struct HandshakeMsg {
    msg_type: u8,
    body: Vec<u8>,
}

// Handshake message: msg_type(1) + length(3) + body.  RFC 8446 §4
fn parse_handshake_messages(data: &[u8]) -> Result<Vec<HandshakeMsg>, &'static str> {
    let mut msgs = Vec::new();
    let mut pos = 0;
    while pos < data.len() {
        if data.len() - pos < 4 {
            return Err("truncated handshake header");
        }
        let msg_type = data[pos];
        let length = u32::from_be_bytes([0, data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        if data.len() - pos < length {
            return Err("truncated handshake body");
        }
        msgs.push(HandshakeMsg {
            msg_type,
            body: data[pos..pos + length].to_vec(),
        });
        pos += length;
    }
    Ok(msgs)
}

fn hs_header(msg: &HandshakeMsg) -> [u8; 4] {
    let len = msg.body.len() as u32;
    [msg.msg_type, (len >> 16) as u8, (len >> 8) as u8, len as u8]
}

/// Certificate message body layout.  RFC 8446 §4.4.2
/// certificate_request_context(1+N) + certificate_list(3-byte len, then entries)
/// Each entry: cert_data(3-byte len + DER) + extensions(2-byte len + data)
fn parse_cert_message(body: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    let mut pos = 0;
    if pos >= body.len() {
        return Err("empty Certificate message");
    }
    let ctx_len = body[pos] as usize;
    pos += 1 + ctx_len;
    if body.len() - pos < 3 {
        return Err("truncated certificate_list length");
    }
    let list_len = u32::from_be_bytes([0, body[pos], body[pos + 1], body[pos + 2]]) as usize;
    pos += 3;
    let list_end = pos + list_len;
    let mut certs = Vec::new();
    while pos < list_end {
        if list_end - pos < 3 {
            return Err("truncated cert_data length");
        }
        let cert_len = u32::from_be_bytes([0, body[pos], body[pos + 1], body[pos + 2]]) as usize;
        pos += 3;
        if list_end - pos < cert_len {
            return Err("truncated cert_data");
        }
        certs.push(body[pos..pos + cert_len].to_vec());
        pos += cert_len;
        if list_end - pos < 2 {
            return Err("truncated cert extensions length");
        }
        let ext_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
        pos += 2 + ext_len;
    }
    Ok(certs)
}

// ---------------------------------------------------------------------------
// TLS extension key_share parsers
// ---------------------------------------------------------------------------

/// Extract the X25519 public key from the key_share extension of a
/// ClientHello record payload (the raw handshake bytes, not the record header).
///
/// ClientHello layout (simplified):
///   2  legacy_version
///   32 client_random
///   1  session_id_len + session_id
///   2  cipher_suites_len + cipher_suites
///   1  compression_methods_len + compression_methods
///   2  extensions_len
///   extensions...
///
/// key_share extension (type 0x0033) in ClientHello contains a list of
/// KeyShareEntry: { 2-byte NamedGroup, 2-byte key_len, key_bytes }.
fn parse_client_hello_key_share(outbound: &[u8]) -> Option<[u8; 32]> {
    // Find the ClientHello record (content_type = 22, plaintext handshake).
    let records = parse_records(outbound);
    let ch_payload = records
        .iter()
        .find(|r| r.content_type == 22)?
        .payload
        .clone();

    // ch_payload = one or more handshake messages; first should be ClientHello (type 1).
    let msgs = parse_handshake_messages(&ch_payload).ok()?;
    let ch = msgs.iter().find(|m| m.msg_type == 1)?; // ClientHello
    let body = &ch.body;

    let mut pos = 0;
    // legacy_version (2)
    pos += 2;
    // client_random (32)
    pos += 32;
    // session_id
    if pos >= body.len() {
        return None;
    }
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    // cipher_suites
    if pos + 2 > body.len() {
        return None;
    }
    let cs_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2 + cs_len;
    // compression_methods
    if pos >= body.len() {
        return None;
    }
    let cm_len = body[pos] as usize;
    pos += 1 + cm_len;
    // extensions_len
    if pos + 2 > body.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;

    parse_key_share_client(&body[pos..ext_end.min(body.len())])
}

/// Parse extension list (ClientHello format) looking for key_share (0x0033),
/// then find the X25519 (0x001d) entry.
fn parse_key_share_client(exts: &[u8]) -> Option<[u8; 32]> {
    let mut pos = 0;
    while pos + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[pos], exts[pos + 1]]);
        let ext_len = u16::from_be_bytes([exts[pos + 2], exts[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > exts.len() {
            break;
        }
        let ext_data = &exts[pos..pos + ext_len];
        if ext_type == 0x0033 {
            // client_shares list: 2-byte list_len, then entries
            if ext_data.len() < 2 {
                return None;
            }
            let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
            let mut epos = 2;
            let list_end = 2 + list_len;
            while epos + 4 <= list_end.min(ext_data.len()) {
                let group = u16::from_be_bytes([ext_data[epos], ext_data[epos + 1]]);
                let klen = u16::from_be_bytes([ext_data[epos + 2], ext_data[epos + 3]]) as usize;
                epos += 4;
                if epos + klen > ext_data.len() {
                    break;
                }
                if group == 0x001d && klen == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&ext_data[epos..epos + 32]);
                    return Some(key);
                }
                epos += klen;
            }
        }
        pos += ext_len;
    }
    None
}

/// Extract the X25519 public key from the key_share extension of a
/// ServerHello record payload.
///
/// ServerHello key_share (type 0x0033) contains a single KeyShareEntry:
///   { 2-byte NamedGroup, 2-byte key_len, key_bytes }
fn parse_server_hello_key_share(inbound: &[u8]) -> Option<[u8; 32]> {
    let records = parse_records(inbound);
    let sh_payload = records
        .iter()
        .find(|r| r.content_type == 22)?
        .payload
        .clone();

    let msgs = parse_handshake_messages(&sh_payload).ok()?;
    let sh = msgs.iter().find(|m| m.msg_type == 2)?; // ServerHello
    let body = &sh.body;

    let mut pos = 0;
    // legacy_version (2)
    pos += 2;
    // server_random (32)
    pos += 32;
    // session_id
    if pos >= body.len() {
        return None;
    }
    let sid_len = body[pos] as usize;
    pos += 1 + sid_len;
    // cipher_suite (2)
    pos += 2;
    // compression_method (1)
    pos += 1;
    // extensions_len
    if pos + 2 > body.len() {
        return None;
    }
    let ext_total = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;

    parse_key_share_server(&body[pos..ext_end.min(body.len())])
}

/// Parse extension list (ServerHello format) for key_share (0x0033),
/// which contains a single entry: { NamedGroup(2), key_len(2), key }.
fn parse_key_share_server(exts: &[u8]) -> Option<[u8; 32]> {
    let mut pos = 0;
    while pos + 4 <= exts.len() {
        let ext_type = u16::from_be_bytes([exts[pos], exts[pos + 1]]);
        let ext_len = u16::from_be_bytes([exts[pos + 2], exts[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > exts.len() {
            break;
        }
        let ext_data = &exts[pos..pos + ext_len];
        if ext_type == 0x0033 {
            // Single entry: 2-byte group + 2-byte key_len + key
            if ext_data.len() < 4 {
                return None;
            }
            let group = u16::from_be_bytes([ext_data[0], ext_data[1]]);
            let klen = u16::from_be_bytes([ext_data[2], ext_data[3]]) as usize;
            if group == 0x001d && klen == 32 && ext_data.len() >= 4 + 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&ext_data[4..36]);
                return Some(key);
            }
        }
        pos += ext_len;
    }
    None
}

// ---------------------------------------------------------------------------
// Certificate helpers
// ---------------------------------------------------------------------------

const OID_ECDSA_SHA256: &str = "1.2.840.10045.4.3.2";
const OID_ECDSA_SHA384: &str = "1.2.840.10045.4.3.3";
const OID_RSA_SHA256: &str = "1.2.840.113549.1.1.11";
const OID_RSA_SHA384: &str = "1.2.840.113549.1.1.12";

fn verify_cert_signature(
    cert: &Certificate,
    issuer_spki: &x509_cert::spki::SubjectPublicKeyInfoOwned,
) {
    use der::Encode;
    let tbs_der = cert.tbs_certificate.to_der().expect("encode TBS");
    let sig_bytes = cert.signature.raw_bytes();
    let oid = cert.signature_algorithm.oid.to_string();

    match oid.as_str() {
        OID_ECDSA_SHA256 => {
            let pk = issuer_spki.subject_public_key.raw_bytes();
            let vk = VerifyingKey::from_sec1_bytes(pk).expect("issuer not P-256");
            let sig = DerSignature::try_from(sig_bytes).expect("invalid ECDSA-P256 sig");
            EcVerifier::verify(&vk, &tbs_der, &sig).expect("cert ECDSA-P256 sig invalid");
        }
        OID_ECDSA_SHA384 => {
            let pk = issuer_spki.subject_public_key.raw_bytes();
            let vk = P384VerifyingKey::from_sec1_bytes(pk).expect("issuer not P-384");
            let sig = P384DerSignature::try_from(sig_bytes).expect("invalid ECDSA-P384 sig");
            P384Verifier::verify(&vk, &tbs_der, &sig).expect("cert ECDSA-P384 sig invalid");
        }
        OID_RSA_SHA256 => {
            use der::Encode;
            let spki_der = issuer_spki.to_der().expect("encode SPKI");
            let pk = RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA key");
            let vk = pkcs1v15::VerifyingKey::<Sha256>::new(pk);
            let sig = pkcs1v15::Signature::try_from(sig_bytes).expect("invalid RSA sig");
            rsa::signature::Verifier::verify(&vk, &tbs_der, &sig)
                .expect("cert RSA-SHA256 sig invalid");
        }
        OID_RSA_SHA384 => {
            use der::Encode;
            use sha2::Sha384;
            let spki_der = issuer_spki.to_der().expect("encode SPKI");
            let pk = RsaPublicKey::from_public_key_der(&spki_der).expect("parse RSA key");
            let vk = pkcs1v15::VerifyingKey::<Sha384>::new(pk);
            let sig = pkcs1v15::Signature::try_from(sig_bytes).expect("invalid RSA sig");
            rsa::signature::Verifier::verify(&vk, &tbs_der, &sig)
                .expect("cert RSA-SHA384 sig invalid");
        }
        other => panic!("unsupported sig alg: {}", other),
    }
}

fn find_trust_anchor(
    chain: &[Certificate],
    chain_ders: &[Vec<u8>],
) -> (usize, x509_cert::spki::SubjectPublicKeyInfoOwned) {
    for i in 0..chain.len() {
        if let Some(subj_content) = raw_name_content(chain_ders, i, NameField::Subject) {
            if let Some(anchor) = webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .find(|a| a.subject.as_ref() == subj_content)
            {
                let spki = parse_anchor_spki(anchor.subject_public_key_info.as_ref());
                return (i, spki);
            }
        }
    }

    let last = chain.len() - 1;
    if let Some(iss_content) = raw_name_content(chain_ders, last, NameField::Issuer) {
        if let Some(anchor) = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .find(|a| a.subject.as_ref() == iss_content)
        {
            let spki = parse_anchor_spki(anchor.subject_public_key_info.as_ref());
            return (chain.len(), spki);
        }
    }

    panic!("root CA not found in trust store");
}

fn parse_anchor_spki(content: &[u8]) -> x509_cert::spki::SubjectPublicKeyInfoOwned {
    let len = content.len();
    let mut full = Vec::with_capacity(4 + len);
    full.push(0x30);
    if len < 0x80 {
        full.push(len as u8);
    } else if len < 0x100 {
        full.push(0x81);
        full.push(len as u8);
    } else {
        full.push(0x82);
        full.push((len >> 8) as u8);
        full.push(len as u8);
    }
    full.extend_from_slice(content);
    x509_cert::spki::SubjectPublicKeyInfoOwned::from_der(&full).expect("parse trust anchor SPKI")
}

enum NameField {
    Subject,
    Issuer,
}

fn raw_name_content(chain_ders: &[Vec<u8>], idx: usize, field: NameField) -> Option<&[u8]> {
    let cert_der = &chain_ders[idx];
    let cert_content = der_unwrap_sequence(cert_der)?;
    let (tbs_tlv, _) = der_next_tlv(cert_content)?;
    let tbs_content = der_unwrap_sequence(tbs_tlv)?;

    let mut pos = tbs_content;
    if pos.first() == Some(&0xa0) {
        let (_, rest) = der_next_tlv(pos)?;
        pos = rest;
    }
    let (_, rest) = der_next_tlv(pos)?;
    pos = rest;
    let (_, rest) = der_next_tlv(pos)?;
    pos = rest;
    let (issuer_tlv, rest) = der_next_tlv(pos)?;

    let name_tlv = match field {
        NameField::Issuer => issuer_tlv,
        NameField::Subject => {
            let (_, rest2) = der_next_tlv(rest)?;
            let (subject_tlv, _) = der_next_tlv(rest2)?;
            subject_tlv
        }
    };

    der_unwrap_sequence(name_tlv)
}

fn verify_hostname(cert: &Certificate, host: &str) {
    use x509_cert::ext::pkix::{name::GeneralName, SubjectAltName};

    const ID_CE_SUBJECT_ALT_NAME: der::asn1::ObjectIdentifier =
        der::asn1::ObjectIdentifier::new_unwrap("2.5.29.17");

    let exts = cert
        .tbs_certificate
        .extensions
        .as_ref()
        .expect("leaf cert has no extensions");

    let san_ext = exts
        .iter()
        .find(|e| e.extn_id == ID_CE_SUBJECT_ALT_NAME)
        .expect("leaf cert has no SAN extension");

    let san: SubjectAltName =
        SubjectAltName::from_der(san_ext.extn_value.as_bytes()).expect("parse SAN");

    let matched = san.0.iter().any(|name| {
        if let GeneralName::DnsName(dns) = name {
            hostname_matches(dns.as_str(), host)
        } else {
            false
        }
    });

    assert!(matched, "hostname '{}' not in cert SAN", host);
}

fn der_unwrap_sequence(der: &[u8]) -> Option<&[u8]> {
    if der.first() != Some(&0x30) {
        return None;
    }
    der_next_tlv(der)
        .map(|(_, rest)| &der[..der.len() - rest.len()])
        .map(|seq| {
            let tag_len = if seq[1] & 0x80 == 0 {
                2
            } else {
                2 + (seq[1] & 0x7f) as usize
            };
            &seq[tag_len..]
        })
}

fn der_next_tlv(der: &[u8]) -> Option<(&[u8], &[u8])> {
    if der.len() < 2 {
        return None;
    }
    let (len, header_len) = if der[1] & 0x80 == 0 {
        (der[1] as usize, 2)
    } else {
        let n = (der[1] & 0x7f) as usize;
        if der.len() < 2 + n {
            return None;
        }
        let mut l = 0usize;
        for &b in &der[2..2 + n] {
            l = (l << 8) | b as usize;
        }
        (l, 2 + n)
    };
    let total = header_len + len;
    if der.len() < total {
        return None;
    }
    Some((&der[..total], &der[total..]))
}

fn hostname_matches(pattern: &str, host: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        host.ends_with(suffix)
            && host.len() > suffix.len() + 1
            && !host[..host.len() - suffix.len() - 1].contains('.')
    } else {
        pattern.eq_ignore_ascii_case(host)
    }
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

fn unchunk(body: &str) -> String {
    let mut out = String::new();
    let mut s = body;
    while let Some(p) = s.find("\r\n") {
        let size_hex = s[..p].split(';').next().unwrap_or("").trim();
        let chunk_len = match usize::from_str_radix(size_hex, 16) {
            Ok(n) => n,
            Err(_) => break,
        };
        s = &s[p + 2..];
        if chunk_len == 0 {
            break;
        }
        if s.len() < chunk_len {
            break;
        }
        out.push_str(&s[..chunk_len]);
        s = &s[chunk_len..];
        if s.starts_with("\r\n") {
            s = &s[2..];
        }
    }
    if out.is_empty() {
        body.to_string()
    } else {
        out
    }
}

// ---------------------------------------------------------------------------
// HKDF / crypto helpers
// ---------------------------------------------------------------------------

// HKDF-Expand-Label.  RFC 8446 §7.1
// HkdfLabel = length(2) + "tls13 "+label(1+N) + context(1+M)
fn expand_label(prk: &[u8], label: &str, context: &[u8], len: usize) -> Vec<u8> {
    let full_label = format!("tls13 {label}");
    let mut info = Vec::new();
    info.extend_from_slice(&(len as u16).to_be_bytes());
    info.push(full_label.len() as u8);
    info.extend_from_slice(full_label.as_bytes());
    info.push(context.len() as u8);
    info.extend_from_slice(context);
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("valid PRK");
    let mut out = vec![0u8; len];
    hk.expand(&info, &mut out).expect("HKDF-Expand-Label");
    out
}

fn empty_hash() -> [u8; 32] {
    Sha256::digest([]).into()
}

// Per-record nonce: iv XOR seq_be.  RFC 8446 §5.3
// Sequence number is big-endian in the low 8 bytes; top 4 bytes of iv unchanged.
fn xor_nonce(iv: &[u8; 12], seq: u64) -> [u8; 12] {
    let mut nonce = *iv;
    for (i, b) in seq.to_be_bytes().iter().enumerate() {
        nonce[4 + i] ^= b;
    }
    nonce
}
