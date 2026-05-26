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
}

/// Result: the 32-byte X25519 shared secret (Montgomery u) that HKDF expects as IKM input.
#[derive(Debug, Clone, Copy)]
pub struct X25519SharedSecret(pub [u8; 32]);

/// Notary (or client) generates its additive share of the client ephemeral key.
pub fn generate_share<R: RngCore>(rng: &mut R) -> EphemeralShare {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    // Clamp like X25519
    bytes[0] &= 248;
    bytes[31] &= 127;
    bytes[31] |= 64;
    EphemeralShare {
        scalar: Scalar::from_bytes_mod_order(bytes),
    }
}

/// This party's partial point: `share * server_epk` (Edwards).
pub fn compute_partial_point(share: &EphemeralShare, server_epk: &[u8; 32]) -> EdwardsPoint {
    let mont = MontgomeryPoint(*server_epk);
    let edwards = mont.to_edwards(0).expect("valid server epk");
    &share.scalar * edwards
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

/// OT / MtA Curve25519 2PC — unimplemented (`TODO.md` #1).
#[derive(Debug, Default, Clone, Copy)]
pub struct OtX25519Placeholder;

impl EcdhIkmDriver for OtX25519Placeholder {
    fn name(&self) -> &'static str {
        "OtX25519Placeholder (unimplemented — see TODO.md #1)"
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

    let ikm = combine_partial_points(&p_c, &p_n);

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

    let ikm = combine_partial_points(&p_c, &p_n);

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

/// Reference X25519 for test oracles: `X25519(host_share + notary_share, server_epk)`.
pub fn reference_ikm(
    host_share: &EphemeralShare,
    notary_share: &EphemeralShare,
    server_epk: &[u8; 32],
) -> X25519SharedSecret {
    let summed = host_share.scalar + notary_share.scalar;
    let mont = MontgomeryPoint(*server_epk);
    let server_ed = mont.to_edwards(0).expect("valid server epk");
    X25519SharedSecret((&summed * server_ed).to_montgomery().0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn additive_shares_produce_correct_x25519_secret() {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut rng = OsRng;
        let server_secret = StaticSecret::random_from_rng(&mut rng);
        let server_public = PublicKey::from(&server_secret);

        let k_c = generate_share(&mut rng);
        let k_n = generate_share(&mut rng);

        let p_c = compute_partial_point(&k_c, server_public.as_bytes());
        let p_n = compute_partial_point(&k_n, server_public.as_bytes());

        let got = combine_partial_points(&p_c, &p_n);

        let summed = k_c.scalar + k_n.scalar;
        let server_mont = MontgomeryPoint(*server_public.as_bytes());
        let server_ed = server_mont.to_edwards(0).expect("valid server epk");
        let expected = (&summed * server_ed).to_montgomery();

        assert_eq!(
            got.0, expected.0,
            "additive shares must give the correct X25519 shared secret"
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
        let server_sk = StaticSecret::random_from_rng(&mut rng);
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
            let mut io = Duplex {
                r: n2h_r,
                w: h2n_w,
            };
            notary_run_leaky_additive(&k_n, &server_epk, &mut io, &mut rng)
        });

        let mut host_io = Duplex {
            r: h2n_r,
            w: n2h_w,
        };
        let host_out = host_run_leaky_additive(&k_c, &server_epk, &mut host_io).unwrap();
        let notary_out = notary.join().unwrap().unwrap();

        let expect = reference_ikm(&k_c, &k_n, &server_epk);
        assert_eq!(host_out.ikm.0, expect.0);
        assert_eq!(notary_out.ikm.0, expect.0);
        assert_eq!(host_out.host_ikm_share, notary_out.host_ikm_share);
        assert_eq!(host_out.notary_ikm_share, notary_out.notary_ikm_share);
        let recon: [u8; 32] =
            std::array::from_fn(|i| host_out.host_ikm_share[i] ^ host_out.notary_ikm_share[i]);
        assert_eq!(recon, expect.0);
    }
}
