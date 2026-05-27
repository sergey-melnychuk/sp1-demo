//! Mode-2 handshake byte capture on the notary channel (witness path).

use sha2::{Digest, Sha256};
use sp1_demo_common::SessionBinding;
use swanky_channel::Channel;
use swanky_error::Result as SwankyResult;

use crate::ecdh::parse_server_hello_key_share;
use crate::garble::production_session_binding;
use crate::transcript::{cert_chain_ders_from_handshake, transcript_hashes_with_ikm};

/// Raw TLS handshake bytes the host observed, plus binding metadata.
#[derive(Debug, Clone)]
pub struct HandshakeCapture {
    pub server_epk: [u8; 32],
    pub cert_chain_hash: [u8; 32],
    pub outbound: Vec<u8>,
    pub inbound: Vec<u8>,
}

/// SHA-256 over length-prefixed outbound || inbound handshake captures.
pub fn handshake_transcript_hash(outbound: &[u8], inbound: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(&(outbound.len() as u64).to_be_bytes());
    h.update(outbound);
    h.update(&(inbound.len() as u64).to_be_bytes());
    h.update(inbound);
    h.finalize().into()
}

/// SHA-256(`after_server_hello || after_server_finished`) — TLS 1.3 key-schedule context.
pub fn key_schedule_context_hash(after_sh: &[u8; 32], after_sf: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(after_sh);
    h.update(after_sf);
    h.finalize().into()
}

/// Canonical hash of the peer certificate chain (DER certs, length-prefixed).
pub fn cert_chain_hash(certs: &[impl AsRef<[u8]>]) -> [u8; 32] {
    let mut h = Sha256::new();
    for cert in certs {
        let der = cert.as_ref();
        h.update(&(der.len() as u32).to_be_bytes());
        h.update(der);
    }
    h.finalize().into()
}

const MAX_HANDSHAKE_BYTES: u32 = 256 * 1024;

pub fn write_handshake_capture(
    ch: &mut Channel,
    cap: &HandshakeCapture,
) -> SwankyResult<()> {
    if cap.outbound.len() as u32 > MAX_HANDSHAKE_BYTES
        || cap.inbound.len() as u32 > MAX_HANDSHAKE_BYTES
    {
        swanky_error::bail!(
            swanky_error::ErrorKind::OtherError,
            "handshake capture exceeds {MAX_HANDSHAKE_BYTES} bytes per direction"
        );
    }
    ch.write_bytes(&cap.server_epk)?;
    ch.write_bytes(&cap.cert_chain_hash)?;
    ch.write_bytes(&(cap.outbound.len() as u32).to_be_bytes())?;
    ch.write_bytes(&cap.outbound)?;
    ch.write_bytes(&(cap.inbound.len() as u32).to_be_bytes())?;
    ch.write_bytes(&cap.inbound)?;
    ch.force_flush().map_err(|e| {
        swanky_error::swanky_error!(swanky_error::ErrorKind::NetworkError, "flush handshake: {e}")
    })?;
    Ok(())
}

pub fn read_handshake_capture(ch: &mut Channel) -> SwankyResult<HandshakeCapture> {
    let mut server_epk = [0u8; 32];
    ch.read_bytes(&mut server_epk)?;
    let mut cert_chain_hash = [0u8; 32];
    ch.read_bytes(&mut cert_chain_hash)?;
    let mut out_len_buf = [0u8; 4];
    ch.read_bytes(&mut out_len_buf)?;
    let out_len = u32::from_be_bytes(out_len_buf);
    if out_len > MAX_HANDSHAKE_BYTES {
        swanky_error::bail!(
            swanky_error::ErrorKind::OtherError,
            "outbound handshake length {out_len} exceeds limit"
        );
    }
    let mut outbound = vec![0u8; out_len as usize];
    ch.read_bytes(&mut outbound)?;
    let mut in_len_buf = [0u8; 4];
    ch.read_bytes(&mut in_len_buf)?;
    let in_len = u32::from_be_bytes(in_len_buf);
    if in_len > MAX_HANDSHAKE_BYTES {
        swanky_error::bail!(
            swanky_error::ErrorKind::OtherError,
            "inbound handshake length {in_len} exceeds limit"
        );
    }
    let mut inbound = vec![0u8; in_len as usize];
    ch.read_bytes(&mut inbound)?;
    Ok(HandshakeCapture {
        server_epk,
        cert_chain_hash,
        outbound,
        inbound,
    })
}

/// Notary-side verification after ECDH: recompute transcript + cert binding.
pub struct VerifiedHandshake {
    pub after_sh: [u8; 32],
    pub after_sf: [u8; 32],
    pub binding: SessionBinding,
}

pub fn verify_handshake_capture(
    cap: &HandshakeCapture,
    ikm: &[u8; 32],
) -> SwankyResult<VerifiedHandshake> {
    let epk = parse_server_hello_key_share(&cap.inbound).ok_or_else(|| {
        swanky_error::swanky_error!(
            swanky_error::ErrorKind::OtherError,
            "ServerHello key_share missing from inbound capture"
        )
    })?;
    if epk != cap.server_epk {
        swanky_error::bail!(
            swanky_error::ErrorKind::OtherError,
            "server_epk mismatch (host claimed vs parsed ServerHello)"
        );
    }

    let cert_ders = cert_chain_ders_from_handshake(&cap.outbound, &cap.inbound, ikm).ok_or_else(
        || {
            swanky_error::swanky_error!(
                swanky_error::ErrorKind::OtherError,
                "could not parse Certificate chain from handshake capture"
            )
        },
    )?;
    let cert_hash = cert_chain_hash(&cert_ders);
    if cert_hash != cap.cert_chain_hash {
        swanky_error::bail!(
            swanky_error::ErrorKind::OtherError,
            "cert_chain_hash mismatch (host claimed vs notary-parsed chain)"
        );
    }

    let (after_sh, after_sf) =
        transcript_hashes_with_ikm(&cap.outbound, &cap.inbound, ikm).ok_or_else(|| {
            swanky_error::swanky_error!(
                swanky_error::ErrorKind::OtherError,
                "transcript hash recomputation failed on notary"
            )
        })?;

    let mut binding = production_session_binding();
    binding.server_epk = cap.server_epk;
    binding.cert_chain_hash = cert_hash;
    binding.handshake_transcript_hash =
        handshake_transcript_hash(&cap.outbound, &cap.inbound);
    binding.key_schedule_context_hash = key_schedule_context_hash(&after_sh, &after_sf);

    Ok(VerifiedHandshake {
        after_sh,
        after_sf,
        binding,
    })
}
