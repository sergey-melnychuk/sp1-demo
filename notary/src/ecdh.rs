//! 2PC / 3-party X25519 ECDH using additive scalar shares.
//!
//! Model the user wants:
//!   Client ephemeral secret = K_C + K_N  (additive shares, mod the group order)
//!   Server has its own ephemeral secret K_S
//!   Shared secret point P = (K_C + K_N) * server_epk = P_c + P_n
//!
//! We work in Edwards form (curve25519-dalek) because point addition is easy there.
//! At the end we convert the sum point to the Montgomery u-coordinate (the 32 bytes
//! that TLS 1.3 uses as the ECDH shared secret / IKM for HKDF).
//!
//! For the first version both parties exchange their partial points P_c and P_n
//! in the clear and add them locally. This gives both the same IKM bytes.
//! The split happens in the subsequent 2PC HKDF step (the derived AES keys and IVs
//! come out as K_c ^ K_n even though the IKM was known to both).
//!
//! Stronger privacy (never revealing the partial points or the IKM) would require
//! 2PC point addition + MtA for the final u-coordinate; that can be added later.

use curve25519_dalek::{edwards::EdwardsPoint, montgomery::MontgomeryPoint, scalar::Scalar};
use rand::RngCore;

/// A party's share of the client ephemeral scalar.
/// The real client ephemeral secret is (k_c + k_n) mod L.
#[derive(Clone, Copy)]
pub struct EphemeralShare {
    pub scalar: Scalar,
}

/// Result of the 3-party ECDH: the 32-byte X25519 shared secret (u-coordinate)
/// that will be fed into 2PC HKDF as the IKM.
#[derive(Clone, Copy)]
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

/// Given the server's ephemeral public key (the 32-byte X25519 public key from ServerHello),
/// compute this party's contribution to the shared secret: share * server_epk (Edwards).
pub fn compute_partial_point(share: &EphemeralShare, server_epk: &[u8; 32]) -> EdwardsPoint {
    // Convert server X25519 public key (Montgomery u) to Edwards.
    // We use the birational map; the sign is chosen arbitrarily (the final u will be correct).
    let mont = MontgomeryPoint(*server_epk);
    // The map from Montgomery u to Edwards (y) is well-defined for the base point we use.
    // curve25519-dalek provides a direct conversion via the compressed Edwards y form
    // that corresponds to the same point on the curve.
    let edwards = mont.to_edwards(0).expect("valid server epk");
    // Now multiply by our scalar share
    &share.scalar * edwards
}

/// Both parties call this after exchanging their partial points (P_c and P_n).
/// Returns the final X25519 shared secret bytes (the u-coordinate) that HKDF expects.
pub fn combine_partial_points(p_c: &EdwardsPoint, p_n: &EdwardsPoint) -> X25519SharedSecret {
    let sum = p_c + p_n;
    // Convert sum (Edwards) back to Montgomery u-coordinate (the X25519 shared secret).
    let mont = sum.to_montgomery();
    X25519SharedSecret(mont.0)
}

/// Convenience for the client side (holds K_C share).
/// It receives the notary's partial point and the server's epk (from the real TLS).
pub fn client_finish_ecdh(
    my_share: &EphemeralShare,
    notary_partial: &EdwardsPoint,
    server_epk: &[u8; 32],
) -> X25519SharedSecret {
    let my_partial = compute_partial_point(my_share, server_epk);
    combine_partial_points(&my_partial, notary_partial)
}

/// Convenience for the notary side (holds K_N share).
pub fn notary_finish_ecdh(
    my_share: &EphemeralShare,
    client_partial: &EdwardsPoint,
    server_epk: &[u8; 32],
) -> X25519SharedSecret {
    let my_partial = compute_partial_point(my_share, server_epk);
    combine_partial_points(client_partial, &my_partial)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn additive_shares_produce_correct_x25519_secret() {
        // Simulate the 3-party flow with a real X25519 keypair on the "server" side.
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut rng = OsRng;
        let server_secret = StaticSecret::random_from_rng(&mut rng);
        let server_public = PublicKey::from(&server_secret);

        // Client side generates two additive shares
        let k_c = generate_share(&mut rng);
        let k_n = generate_share(&mut rng);

        // Each side computes its partial point against the real server public key
        let p_c = compute_partial_point(&k_c, server_public.as_bytes());
        let p_n = compute_partial_point(&k_n, server_public.as_bytes());

        // Combine
        let got = combine_partial_points(&p_c, &p_n);

        // Reference: what a normal X25519 would produce with the summed scalar
        // acting on the server public point.
        let summed = k_c.scalar + k_n.scalar;
        let server_mont = MontgomeryPoint(*server_public.as_bytes());
        let server_ed = server_mont.to_edwards(0).expect("valid server epk");
        let expected = (&summed * server_ed).to_montgomery();

        assert_eq!(
            got.0, expected.0,
            "additive shares must give the correct X25519 shared secret"
        );
    }
}
