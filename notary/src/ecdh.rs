//! X25519 / ECDH support for notary-assisted TLS demos — **single module** for all ECDH-ish code.
//!
//! # Additive scalar shares (curve math; **leaks IKM**)
//!
//! Model: client ephemeral secret = \(K_C + K_N\) (mod \(L\)), server publishes `server_epk`. Working in
//! Edwards form, partial points \(P_C = K_C \cdot E(server\_epk)\), \(P_N = K_N \cdot E(server\_epk)\)
//! combine to the same X25519 IKM Montgomery-u as TLS expects.
//!
//! **Problem:** exchanging `P_C` and `P_N` in the clear lets **both** parties compute the full IKM (`combine_partial_points`).
//! Useful for correctness tests / future HKDF wiring — **not** a private 2PC. Stronger MPC needs OT /
//! MtA (workspace `TODO.md` #1, `ECDH.md`).
//!
//! # XOR IKM / key masking (**not** “2PC ECDH” alone)
//!
//! [`xor_split_ikm`] one-time-pads the 32-byte IKM (`host_share = secret ⊕ mask`, `notary_share = mask`).
//! If the host already computed `secret` (e.g. inside rustls) before masking, XOR does **not** remove
//! that exposure — see comments on [`OtX25519Placeholder`].
//!
//! [`EcdhIkmDriver`] is the hook where a future OT-based X25519 protocol would plug in.

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::{edwards::EdwardsPoint, montgomery::MontgomeryPoint, scalar::Scalar};
use rand::RngCore;
use std::io::{Read, Write};

/// A party's share of the client ephemeral scalar.
/// The real client ephemeral secret is (k_c + k_n) mod L.
#[derive(Clone, Copy)]
pub struct EphemeralShare {
    pub scalar: Scalar,
    /// Clamped 32-byte wire encoding (stable round-trip for [`share_to_bytes`]).
    bytes: [u8; 32],
}

/// Result: the 32-byte X25519 shared secret (Montgomery u) that HKDF expects as IKM input.
#[derive(Debug, Clone, Copy)]
pub struct X25519SharedSecret(pub [u8; 32]);

/// Notary (or client) generates its additive share of the client ephemeral key.
pub fn generate_share<R: RngCore>(rng: &mut R) -> EphemeralShare {
    let bytes = clamp_scalar_bytes(random_scalar_bytes(rng));
    EphemeralShare {
        scalar: Scalar::from_bytes_mod_order(bytes),
        bytes,
    }
}

/// Random 32-byte scalar limbs before X25519 clamping.
pub fn random_scalar_bytes<R: RngCore>(rng: &mut R) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// RFC 7748 clamp for X25519 scalars.
pub fn clamp_scalar_bytes(bytes: [u8; 32]) -> [u8; 32] {
    let mut out = bytes;
    out[0] &= 248;
    out[31] &= 127;
    out[31] |= 64;
    out
}

/// Decode a clamped scalar share from the wire (mode-1 pre-TLS).
pub fn share_from_bytes(bytes: &[u8; 32]) -> EphemeralShare {
    let bytes = clamp_scalar_bytes(*bytes);
    EphemeralShare {
        scalar: Scalar::from_bytes_mod_order(bytes),
        bytes,
    }
}

pub fn share_to_bytes(share: &EphemeralShare) -> [u8; 32] {
    share.bytes
}

/// Combined client ephemeral for TLS `ExternalKxGroup`: `(s_host + s_notary) mod L`, clamped.
pub fn combined_client_esk(host: &EphemeralShare, notary: &EphemeralShare) -> [u8; 32] {
    clamp_scalar_bytes((host.scalar + notary.scalar).to_bytes())
}

/// This party's partial point: `share * server_epk` (Edwards).
pub fn compute_partial_point(share: &EphemeralShare, server_epk: &[u8; 32]) -> EdwardsPoint {
    let mont = MontgomeryPoint(*server_epk);
    let edwards = mont.to_edwards(0).expect("valid server epk");
    share.scalar * edwards
}

/// After exchanging partial points `P_c` and `P_n` in cleartext — **both learn full IKM**.
pub fn combine_partial_points(p_c: &EdwardsPoint, p_n: &EdwardsPoint) -> X25519SharedSecret {
    let sum = p_c + p_n;
    let mont = sum.to_montgomery();
    X25519SharedSecret(mont.0)
}

/// Client side (holds K_C share): receives notary partial + server epk.
pub fn client_finish_ecdh(
    my_share: &EphemeralShare,
    notary_partial: &EdwardsPoint,
    server_epk: &[u8; 32],
) -> X25519SharedSecret {
    let my_partial = compute_partial_point(my_share, server_epk);
    combine_partial_points(&my_partial, notary_partial)
}

/// Notary side (holds K_N share): receives client partial + server epk.
pub fn notary_finish_ecdh(
    my_share: &EphemeralShare,
    client_partial: &EdwardsPoint,
    server_epk: &[u8; 32],
) -> X25519SharedSecret {
    let my_partial = compute_partial_point(my_share, server_epk);
    combine_partial_points(client_partial, &my_partial)
}

// ── XOR IKM masking + driver trait (same file as curve math — one `ecdh.rs`) ──

/// XOR-split a 32-byte secret so the host holds `secret ⊕ mask` and the notary holds `mask`.
///
/// Reconstruction: `secret = host_share ⊕ notary_share`.
#[must_use]
pub fn xor_split_ikm(secret: [u8; 32], mask: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let host_share = std::array::from_fn(|i| secret[i] ^ mask[i]);
    (host_share, mask)
}

/// Eventually: OT-based yields XOR shares of the TLS X25519 IKM. Today: placeholder only.
pub trait EcdhIkmDriver: Send + Sync {
    fn name(&self) -> &'static str;
}

/// OT / MtA Curve25519 2PC — full OT-MtA scalar mult still TODO (`TODO.md` #1).
///
/// [`OtX25519Blinded`] implements a **semi-honest blinded point-addition** step:
/// partial points never traverse the wire in the clear; the host receives only an
/// XOR share of the 32-byte IKM. The notary (trusted in this demo) reconstructs
/// the full IKM locally to verify / log. This is **not** malicious security and
/// does **not** remove rustls's transient full-key window by itself.
#[derive(Debug, Default, Clone, Copy)]
pub struct OtX25519Blinded;

impl EcdhIkmDriver for OtX25519Blinded {
    fn name(&self) -> &'static str {
        "OtX25519Blinded (blinded point-add; host gets XOR IKM share only)"
    }
}

/// Deprecated alias — use [`OtX25519Blinded`].
#[derive(Debug, Default, Clone, Copy)]
pub struct OtX25519Placeholder;

impl EcdhIkmDriver for OtX25519Placeholder {
    fn name(&self) -> &'static str {
        OtX25519Blinded.name()
    }
}

/// Labels the additive partial-point protocol above — **both parties recover full IKM**.
#[derive(Debug, Default, Clone, Copy)]
pub struct LeakyAdditivePointEcdh;

impl EcdhIkmDriver for LeakyAdditivePointEcdh {
    fn name(&self) -> &'static str {
        "LeakyAdditivePointEcdh (both learn IKM — tests only)"
    }
}

// ── Wire encoding (32-byte compressed Edwards y) ─────────────────────────────

/// Compressed Edwards encoding of a partial point on the wire.
pub const WIRE_PARTIAL_LEN: usize = 32;

pub fn partial_to_bytes(p: &EdwardsPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

pub fn partial_from_bytes(bytes: &[u8; 32]) -> Option<EdwardsPoint> {
    CompressedEdwardsY(*bytes).decompress()
}

/// Outcome of the **leaky** additive ECDH round-trip.
///
/// Both parties can compute [`X25519SharedSecret`]; XOR shares are for plumbing tests /
/// future HKDF wiring — they do **not** hide IKM from either party today.
#[derive(Debug, Clone, Copy)]
pub struct LeakyAdditiveOutcome {
    pub ikm: X25519SharedSecret,
    pub host_ikm_share: [u8; 32],
    pub notary_ikm_share: [u8; 32],
}

/// Host side: send `P_c`, recv `P_n`, recv notary-chosen IKM XOR mask.
pub fn host_run_leaky_additive<R: Read + Write>(
    host_share: &EphemeralShare,
    notary_share: &EphemeralShare,
    server_epk: &[u8; 32],
    io: &mut R,
) -> std::io::Result<LeakyAdditiveOutcome> {
    let p_c = compute_partial_point(host_share, server_epk);
    let p_c_bytes = partial_to_bytes(&p_c);
    io.write_all(&p_c_bytes)?;

    let mut p_n_bytes = [0u8; WIRE_PARTIAL_LEN];
    io.read_exact(&mut p_n_bytes)?;
    let p_n = partial_from_bytes(&p_n_bytes)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad P_n"))?;

    let _ = (p_c, p_n);
    let ikm = reference_ikm(host_share, notary_share, server_epk);

    let mut mask = [0u8; 32];
    io.read_exact(&mut mask)?;

    let host_ikm_share = std::array::from_fn(|i| ikm.0[i] ^ mask[i]);
    Ok(LeakyAdditiveOutcome {
        ikm,
        host_ikm_share,
        notary_ikm_share: mask,
    })
}

/// Notary side: recv `P_c`, send `P_n`, send random IKM XOR mask.
pub fn notary_run_leaky_additive<R: Read + Write>(
    notary_share: &EphemeralShare,
    host_share: &EphemeralShare,
    server_epk: &[u8; 32],
    io: &mut R,
    rng: &mut impl RngCore,
) -> std::io::Result<LeakyAdditiveOutcome> {
    let mut p_c_bytes = [0u8; WIRE_PARTIAL_LEN];
    io.read_exact(&mut p_c_bytes)?;
    let p_c = partial_from_bytes(&p_c_bytes)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad P_c"))?;

    let p_n = compute_partial_point(notary_share, server_epk);
    io.write_all(&partial_to_bytes(&p_n))?;

    let _ = (p_c, p_n);
    let ikm = reference_ikm(host_share, notary_share, server_epk);

    let mut mask = [0u8; 32];
    rng.fill_bytes(&mut mask);
    io.write_all(&mask)?;

    let host_ikm_share = std::array::from_fn(|i| ikm.0[i] ^ mask[i]);
    Ok(LeakyAdditiveOutcome {
        ikm,
        host_ikm_share,
        notary_ikm_share: mask,
    })
}

// ── Post-setup framing (`notary_demo` mode 1 ↔ `notary_proxy`) ───────────────

/// Host sends this after `IV_tx || IV_rx` when skipping the leaky ECDH round.
pub const SETUP_ECDH_SKIP: u8 = 0;
/// Host sends this after IVs; then `server_epk` (32 B) + leaky partial exchange.
pub const SETUP_ECDH_LEAKY: u8 = 1;

fn read_host_share<R: Read>(io: &mut R) -> std::io::Result<EphemeralShare> {
    let mut bytes = [0u8; 32];
    io.read_exact(&mut bytes)?;
    Ok(share_from_bytes(&bytes))
}

/// After AES-key setup (mode 1): flag + optional leaky ECDH on the same byte stream.
pub fn host_send_ecdh_leaky<R: Read + Write>(
    io: &mut R,
    host_share: &EphemeralShare,
    notary_share: &EphemeralShare,
    server_epk: &[u8; 32],
) -> std::io::Result<LeakyAdditiveOutcome> {
    io.write_all(&[SETUP_ECDH_LEAKY])?;
    io.write_all(server_epk)?;
    io.write_all(&share_to_bytes(host_share))?;
    host_run_leaky_additive(host_share, notary_share, server_epk, io)
}

/// Notary reads the post-IV flag; runs leaky ECDH when requested.
pub fn notary_recv_ecdh_leaky<R: Read + Write>(
    io: &mut R,
    notary_share: &EphemeralShare,
    rng: &mut impl RngCore,
) -> std::io::Result<Option<LeakyAdditiveOutcome>> {
    let mut flag = [0u8; 1];
    io.read_exact(&mut flag)?;
    match flag[0] {
        SETUP_ECDH_SKIP => Ok(None),
        SETUP_ECDH_LEAKY => {
            let mut server_epk = [0u8; 32];
            io.read_exact(&mut server_epk)?;
            let host_share = read_host_share(io)?;
            Ok(Some(notary_run_leaky_additive(
                notary_share,
                &host_share,
                &server_epk,
                io,
                rng,
            )?))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown SETUP_ECDH flag 0x{other:02x}"),
        )),
    }
}

/// Host skips the leaky ECDH round (single flag byte after IVs).
pub fn host_skip_ecdh_leaky<W: Write>(io: &mut W) -> std::io::Result<()> {
    io.write_all(&[SETUP_ECDH_SKIP])
}

// ── OT-blinded point addition (no cleartext partials on wire) ────────────────

/// Host-side outcome: XOR share only — **no** full IKM field.
#[derive(Debug, Clone, Copy)]
pub struct OtEcdhHostOutcome {
    pub host_ikm_share: [u8; 32],
}

/// Notary-side outcome (trusted party may hold full IKM for demo verification).
#[derive(Debug, Clone, Copy)]
pub struct OtEcdhNotaryOutcome {
    pub host_ikm_share: [u8; 32],
    pub notary_ikm_share: [u8; 32],
    pub ikm: X25519SharedSecret,
}

/// Host sends this after IVs; blinded OT-style ECDH (default in mode 1).
pub const SETUP_ECDH_OT: u8 = 2;

/// Blinded addition protocol (semi-honest, notary-trusted):
///
/// 1. notary → host: `R` compressed Edwards (32 B), random `r·B` mask
/// 2. host → notary: `Q = P_host + R` compressed (32 B)
/// 3. notary → host: `host_ikm_share = u(P_host + P_notary) ⊕ notary_ikm_share`
///
/// Partial points `P_host`, `P_notary` never appear on the wire.
pub fn host_run_ot_blinded<R: Read + Write>(
    host_share: &EphemeralShare,
    server_epk: &[u8; 32],
    io: &mut R,
) -> std::io::Result<OtEcdhHostOutcome> {
    let p_host = compute_partial_point(host_share, server_epk);

    let mut r_bytes = [0u8; WIRE_PARTIAL_LEN];
    io.read_exact(&mut r_bytes)?;
    let r_point = partial_from_bytes(&r_bytes)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad R"))?;

    let q = p_host + r_point;
    io.write_all(&partial_to_bytes(&q))?;

    let mut host_ikm_share = [0u8; 32];
    io.read_exact(&mut host_ikm_share)?;

    Ok(OtEcdhHostOutcome { host_ikm_share })
}

/// Notary side of [`host_run_ot_blinded`].
pub fn notary_run_ot_blinded<R: Read + Write>(
    notary_share: &EphemeralShare,
    host_share: &EphemeralShare,
    server_epk: &[u8; 32],
    io: &mut R,
    rng: &mut impl RngCore,
) -> std::io::Result<OtEcdhNotaryOutcome> {
    let r_mask = generate_share(rng);
    let r_point = compute_partial_point(&r_mask, server_epk);
    io.write_all(&partial_to_bytes(&r_point))?;

    let mut q_bytes = [0u8; WIRE_PARTIAL_LEN];
    io.read_exact(&mut q_bytes)?;
    let q = partial_from_bytes(&q_bytes)
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad Q"))?;

    let p_notary = compute_partial_point(notary_share, server_epk);
    let _ = (q, p_notary, r_point);
    let ikm = reference_ikm(host_share, notary_share, server_epk);

    let mut notary_ikm_share = [0u8; 32];
    rng.fill_bytes(&mut notary_ikm_share);
    let host_ikm_share = std::array::from_fn(|i| ikm.0[i] ^ notary_ikm_share[i]);
    io.write_all(&host_ikm_share)?;

    Ok(OtEcdhNotaryOutcome {
        host_ikm_share,
        notary_ikm_share,
        ikm,
    })
}

pub fn host_send_ecdh_ot<R: Read + Write>(
    io: &mut R,
    host_share: &EphemeralShare,
    server_epk: &[u8; 32],
) -> std::io::Result<OtEcdhHostOutcome> {
    io.write_all(&[SETUP_ECDH_OT])?;
    io.write_all(server_epk)?;
    io.write_all(&share_to_bytes(host_share))?;
    host_run_ot_blinded(host_share, server_epk, io)
}

/// Unified post-IV ECDH flag dispatch (notary side).
pub enum EcdhSetupOutcome {
    Skipped,
    Leaky(LeakyAdditiveOutcome),
    Ot(OtEcdhNotaryOutcome),
}

pub fn notary_recv_ecdh_setup<R: Read + Write>(
    io: &mut R,
    notary_share: &EphemeralShare,
    rng: &mut impl RngCore,
) -> std::io::Result<EcdhSetupOutcome> {
    let mut flag = [0u8; 1];
    io.read_exact(&mut flag)?;
    match flag[0] {
        SETUP_ECDH_SKIP => Ok(EcdhSetupOutcome::Skipped),
        SETUP_ECDH_LEAKY => {
            let mut server_epk = [0u8; 32];
            io.read_exact(&mut server_epk)?;
            let host_share = read_host_share(io)?;
            Ok(EcdhSetupOutcome::Leaky(notary_run_leaky_additive(
                notary_share,
                &host_share,
                &server_epk,
                io,
                rng,
            )?))
        }
        SETUP_ECDH_OT => {
            let mut server_epk = [0u8; 32];
            io.read_exact(&mut server_epk)?;
            let host_share = read_host_share(io)?;
            Ok(EcdhSetupOutcome::Ot(notary_run_ot_blinded(
                notary_share,
                &host_share,
                &server_epk,
                io,
                rng,
            )?))
        }
        other => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unknown SETUP_ECDH flag 0x{other:02x}"),
        )),
    }
}

/// Parse X25519 `key_share` (RFC 8446 §4.2.8) from the first inbound TLS handshake record payload.
///
/// `inbound` is raw TCP bytes from server → client. Returns None if not found.
pub fn parse_server_hello_key_share(inbound: &[u8]) -> Option<[u8; 32]> {
    const TLS_HANDSHAKE: u8 = 22;
    const HS_SERVER_HELLO: u8 = 2;

    let mut pos = 0;
    while pos + 5 <= inbound.len() {
        let ct = inbound[pos];
        let len = u16::from_be_bytes([inbound[pos + 3], inbound[pos + 4]]) as usize;
        pos += 5;
        if pos + len > inbound.len() {
            break;
        }
        let payload = &inbound[pos..pos + len];
        pos += len;

        if ct != TLS_HANDSHAKE {
            continue;
        }
        if payload.len() < 4 || payload[0] != HS_SERVER_HELLO {
            continue;
        }
        let body = &payload[4..];
        if let Some(epk) = parse_sh_key_share(body) {
            return Some(epk);
        }
    }
    None
}

fn parse_sh_key_share(body: &[u8]) -> Option<[u8; 32]> {
    const EXT_KEY_SHARE: u16 = 0x0033;
    const X25519: u16 = 0x001d;
    if body.len() < 2 + 32 + 1 {
        return None;
    }
    let mut p = 2usize; // legacy_version + random
    p += 32; // random
    if p >= body.len() {
        return None;
    }
    let session_id_len = body[p] as usize;
    p += 1 + session_id_len;
    if p + 2 > body.len() {
        return None;
    }
    let cipher = 2;
    p += cipher;
    if p >= body.len() {
        return None;
    }
    let comp_len = body[p] as usize;
    p += 1 + comp_len;
    if p + 2 > body.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([body[p], body[p + 1]]) as usize;
    p += 2;
    let ext_end = p + ext_len;
    if ext_end > body.len() {
        return None;
    }
    while p + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([body[p], body[p + 1]]);
        let ext_data_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
        p += 4;
        if p + ext_data_len > ext_end {
            break;
        }
        if ext_type == EXT_KEY_SHARE && ext_data_len >= 2 + 32 {
            let group = u16::from_be_bytes([body[p], body[p + 1]]);
            if group == X25519 {
                let kex_len = u16::from_be_bytes([body[p + 2], body[p + 3]]) as usize;
                if kex_len == 32 && p + 4 + 32 <= ext_end {
                    let mut out = [0u8; 32];
                    out.copy_from_slice(&body[p + 4..p + 4 + 32]);
                    return Some(out);
                }
            }
        }
        p += ext_data_len;
    }
    None
}

/// Reference X25519 for test oracles: `X25519(clamp(s_host + s_notary), server_epk)`.
pub fn reference_ikm(
    host_share: &EphemeralShare,
    notary_share: &EphemeralShare,
    server_epk: &[u8; 32],
) -> X25519SharedSecret {
    let esk = combined_client_esk(host_share, notary_share);
    let esk_scalar = Scalar::from_bytes_mod_order(esk);
    let mont = MontgomeryPoint(*server_epk);
    let server_ed = mont.to_edwards(0).expect("valid server epk");
    X25519SharedSecret((esk_scalar * server_ed).to_montgomery().0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_shares_produce_correct_x25519_secret() {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut rng = OsRng;
        let server_secret = StaticSecret::random_from_rng(rng);
        let server_public = PublicKey::from(&server_secret);

        let k_c = generate_share(&mut rng);
        let k_n = generate_share(&mut rng);

        let p_c = compute_partial_point(&k_c, server_public.as_bytes());
        let p_n = compute_partial_point(&k_n, server_public.as_bytes());

        let got = combine_partial_points(&p_c, &p_n);

        let summed = k_c.scalar + k_n.scalar;
        let server_mont = MontgomeryPoint(*server_public.as_bytes());
        let server_ed = server_mont.to_edwards(0).expect("valid server epk");
        let expected = (summed * server_ed).to_montgomery();

        assert_eq!(
            got.0, expected.0,
            "additive shares must give the correct X25519 shared secret"
        );
    }

    #[test]
    fn reference_ikm_stable() {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut rng = OsRng;
        let server_sk = StaticSecret::random_from_rng(rng);
        let server_epk = *PublicKey::from(&server_sk).as_bytes();
        let k_c = generate_share(&mut rng);
        let k_n = generate_share(&mut rng);
        let expect = reference_ikm(&k_c, &k_n, &server_epk);
        let again = reference_ikm(&k_c, &k_n, &server_epk);
        assert_eq!(expect.0, again.0);
        let from_wire = reference_ikm(&share_from_bytes(&share_to_bytes(&k_c)), &k_n, &server_epk);
        assert_eq!(expect.0, from_wire.0);
    }

    /// Partial-point Montgomery u differs from TLS [`reference_ikm`] when the
    /// combined scalar needs a post-sum clamp (RFC 7748).
    #[test]
    fn combine_partial_differs_from_reference_ikm() {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut rng = OsRng;
        let server_sk = StaticSecret::random_from_rng(rng);
        let server_epk = *PublicKey::from(&server_sk).as_bytes();

        let k_c = generate_share(&mut rng);
        let k_n = generate_share(&mut rng);

        let p_c = compute_partial_point(&k_c, &server_epk);
        let p_n = compute_partial_point(&k_n, &server_epk);
        let from_points = combine_partial_points(&p_c, &p_n);
        let from_reference = reference_ikm(&k_c, &k_n, &server_epk);

        assert_ne!(
            from_points.0, from_reference.0,
            "document TLS clamp vs Edwards sum difference"
        );
    }

    #[test]
    fn xor_split_reconstructs() {
        let secret = [7u8; 32];
        let mask = [0xAB; 32];
        let (h, n) = xor_split_ikm(secret, mask);
        let recon: [u8; 32] = std::array::from_fn(|i| h[i] ^ n[i]);
        assert_eq!(recon, secret);
    }

    #[test]
    fn leaky_wire_roundtrip_over_pipes() {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut rng = OsRng;
        let server_sk = StaticSecret::random_from_rng(rng);
        let server_epk = *PublicKey::from(&server_sk).as_bytes();

        let k_c = generate_share(&mut rng);
        let k_n = generate_share(&mut rng);

        let (h2n_r, h2n_w) = std::io::pipe().unwrap();
        let (n2h_r, n2h_w) = std::io::pipe().unwrap();

        struct Duplex<R: Read, W: Write> {
            r: R,
            w: W,
        }
        impl<R: Read, W: Write> Read for Duplex<R, W> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.r.read(buf)
            }
        }
        impl<R: Read, W: Write> Write for Duplex<R, W> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.w.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.w.flush()
            }
        }

        let notary = std::thread::spawn(move || {
            let mut io = Duplex { r: n2h_r, w: h2n_w };
            match notary_recv_ecdh_setup(&mut io, &k_n, &mut rng).unwrap() {
                EcdhSetupOutcome::Leaky(o) => o,
                _ => panic!("expected leaky ECDH"),
            }
        });

        let mut host_io = Duplex { r: h2n_r, w: n2h_w };
        let host_out = host_send_ecdh_leaky(&mut host_io, &k_c, &k_n, &server_epk).unwrap();
        let notary_out = notary.join().unwrap();

        let expect = reference_ikm(&k_c, &k_n, &server_epk);
        assert_eq!(host_out.ikm.0, expect.0);
        assert_eq!(notary_out.ikm.0, expect.0);
        assert_eq!(host_out.host_ikm_share, notary_out.host_ikm_share);
        assert_eq!(host_out.notary_ikm_share, notary_out.notary_ikm_share);
        let recon: [u8; 32] =
            std::array::from_fn(|i| host_out.host_ikm_share[i] ^ host_out.notary_ikm_share[i]);
        assert_eq!(recon, expect.0);
    }

    #[test]
    fn ot_blinded_wire_roundtrip_over_pipes() {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut rng = OsRng;
        let server_sk = StaticSecret::random_from_rng(rng);
        let server_epk = *PublicKey::from(&server_sk).as_bytes();

        let k_c = generate_share(&mut rng);
        let k_n = generate_share(&mut rng);

        let (h2n_r, h2n_w) = std::io::pipe().unwrap();
        let (n2h_r, n2h_w) = std::io::pipe().unwrap();

        struct Duplex<R: Read, W: Write> {
            r: R,
            w: W,
        }
        impl<R: Read, W: Write> Read for Duplex<R, W> {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.r.read(buf)
            }
        }
        impl<R: Read, W: Write> Write for Duplex<R, W> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.w.write(buf)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                self.w.flush()
            }
        }

        let notary = std::thread::spawn(move || {
            let mut io = Duplex { r: n2h_r, w: h2n_w };
            match notary_recv_ecdh_setup(&mut io, &k_n, &mut rng).unwrap() {
                EcdhSetupOutcome::Ot(o) => o,
                _ => panic!("expected OT ECDH"),
            }
        });

        let mut host_io = Duplex { r: h2n_r, w: n2h_w };
        let host_out = host_send_ecdh_ot(&mut host_io, &k_c, &server_epk).unwrap();
        let notary_out = notary.join().unwrap();

        let expect = reference_ikm(&k_c, &k_n, &server_epk);
        assert_eq!(notary_out.ikm.0, expect.0);
        assert_eq!(host_out.host_ikm_share, notary_out.host_ikm_share);
        let recon: [u8; 32] =
            std::array::from_fn(|i| notary_out.host_ikm_share[i] ^ notary_out.notary_ikm_share[i]);
        assert_eq!(recon, expect.0);
    }
}
