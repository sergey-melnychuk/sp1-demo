//! Generates a Bristol Old Format file for the SHA-256 *compression function*.
//!
//! `swanky`'s bundled `sha-256.txt` uses the standard IV baked into the circuit,
//! so it can hash exactly one 512-bit block and **cannot be chained**. HMAC
//! needs to chain (first block produces the chaining value used as the IV of
//! subsequent blocks), so we need a compression circuit that takes the IV
//! as an input.
//!
//! This binary emits `sha-256-compress.txt`:
//!   * 768 input bits  = 256-bit IV  || 512-bit message block
//!   * 256 output bits = next chaining value `H' = compress(IV, M)`
//!
//! Bit convention (matches the AES Bristol circuit we already use):
//!   * Input/output bytes are encoded MSB-first within each byte.
//!   * A 32-bit word `w` lives in 32 consecutive wires `[a..a+32]` where
//!     `a+0` is the MSB of `w` (bit 31) and `a+31` is the LSB (bit 0).
//!
//! Validation lives at the end of this file (use `--validate` to run the
//! generated circuit through the `Dummy` evaluator and check against the
//! `sha2` crate's `compress256`).
//!
//! Run:
//!   cargo run --bin gen_sha256_compress > circuits/sha-256-compress.txt
//!   cargo run --bin gen_sha256_compress -- --validate

use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};

// ── Bristol Old Format builder ────────────────────────────────────────────────

#[derive(Clone, Copy)]
enum GateKind {
    Inv,
    Xor,
    And,
}

struct Gate {
    kind: GateKind,
    in1: usize,
    in2: usize, // unused for Inv
    out: usize,
}

struct Builder {
    next_wire: usize,
    gates: Vec<Gate>,
    /// A wire that always evaluates to 0. Constructed as XOR(input[0], input[0])
    /// after we know we have at least one input wire.
    zero: usize,
    /// A wire that always evaluates to 1: INV(zero).
    one: usize,
}

impl Builder {
    fn new(n_input_bits: usize) -> Self {
        // Reserve input wires 0..n_input_bits.
        let mut b = Builder {
            next_wire: n_input_bits,
            gates: Vec::new(),
            zero: usize::MAX,
            one: usize::MAX,
        };
        // Build a constant-zero and constant-one wire from input bit 0.
        // zero = XOR(input[0], input[0])
        let z = b.alloc_wire();
        b.gates.push(Gate { kind: GateKind::Xor, in1: 0, in2: 0, out: z });
        b.zero = z;
        // one = INV(zero)
        let o = b.alloc_wire();
        b.gates.push(Gate { kind: GateKind::Inv, in1: z, in2: 0, out: o });
        b.one = o;
        b
    }

    fn alloc_wire(&mut self) -> usize {
        let w = self.next_wire;
        self.next_wire += 1;
        w
    }

    fn xor(&mut self, a: usize, b: usize) -> usize {
        let out = self.alloc_wire();
        self.gates.push(Gate { kind: GateKind::Xor, in1: a, in2: b, out });
        out
    }

    fn and(&mut self, a: usize, b: usize) -> usize {
        let out = self.alloc_wire();
        self.gates.push(Gate { kind: GateKind::And, in1: a, in2: b, out });
        out
    }

    fn inv(&mut self, a: usize) -> usize {
        let out = self.alloc_wire();
        self.gates.push(Gate { kind: GateKind::Inv, in1: a, in2: 0, out });
        out
    }

    fn constant_u32(&mut self, value: u32) -> [usize; 32] {
        // MSB-first: result[0] = bit 31, result[31] = bit 0
        let mut out = [0usize; 32];
        for i in 0..32 {
            let bit = (value >> (31 - i)) & 1;
            out[i] = if bit == 1 { self.one } else { self.zero };
        }
        out
    }

    /// Write the circuit out as Bristol Old Format, with the supplied output
    /// wires renamed to be the LAST `output_wires.len()` wires (via passthrough
    /// XOR-with-zero gates). The Bristol parser expects outputs at the end.
    fn write<W: Write>(self, mut w: W, n1: usize, n2: usize, output_wires: &[usize]) {
        // Add passthrough gates so output_wires become the final wires.
        let mut gates = self.gates;
        let mut next_wire = self.next_wire;
        let mut final_outputs = Vec::with_capacity(output_wires.len());
        for &ow in output_wires {
            let new = next_wire;
            next_wire += 1;
            gates.push(Gate { kind: GateKind::Xor, in1: ow, in2: self.zero, out: new });
            final_outputs.push(new);
        }

        // Header: ngates nwires \n n1 n2 n3 \n \n
        writeln!(w, "{} {}", gates.len(), next_wire).unwrap();
        writeln!(w, "{} {}   {}", n1, n2, final_outputs.len()).unwrap();
        writeln!(w).unwrap();

        for g in &gates {
            match g.kind {
                GateKind::Inv => writeln!(w, "1 1 {} {} INV", g.in1, g.out).unwrap(),
                GateKind::Xor => writeln!(w, "2 1 {} {} {} XOR", g.in1, g.in2, g.out).unwrap(),
                GateKind::And => writeln!(w, "2 1 {} {} {} AND", g.in1, g.in2, g.out).unwrap(),
            }
        }
    }
}

// ── u32 helpers (32-bit wires, MSB-first) ─────────────────────────────────────

type U32 = [usize; 32];

fn input_word(start_wire: usize) -> U32 {
    let mut out = [0usize; 32];
    for i in 0..32 {
        out[i] = start_wire + i;
    }
    out
}

fn xor_u32(b: &mut Builder, a: &U32, c: &U32) -> U32 {
    let mut out = [0usize; 32];
    for i in 0..32 {
        out[i] = b.xor(a[i], c[i]);
    }
    out
}

fn and_u32(b: &mut Builder, a: &U32, c: &U32) -> U32 {
    let mut out = [0usize; 32];
    for i in 0..32 {
        out[i] = b.and(a[i], c[i]);
    }
    out
}

fn not_u32(b: &mut Builder, a: &U32) -> U32 {
    let mut out = [0usize; 32];
    for i in 0..32 {
        out[i] = b.inv(a[i]);
    }
    out
}

/// Cyclic right rotation: in MSB-first indexing, result[k] = a[(k - n) mod 32].
fn rotr_u32(a: &U32, n: u32) -> U32 {
    let n = (n % 32) as usize;
    let mut out = [0usize; 32];
    for k in 0..32 {
        out[k] = a[(k + 32 - n) % 32];
    }
    out
}

/// Logical right shift: result[k] = a[k - n] if k >= n, else zero.
fn shr_u32(b: &mut Builder, a: &U32, n: u32) -> U32 {
    let n = n as usize;
    let mut out = [0usize; 32];
    for k in 0..32 {
        out[k] = if k >= n { a[k - n] } else { b.zero };
    }
    out
}

/// 32-bit addition (mod 2^32) via a ripple-carry adder.
/// Indexed MSB-first; the LSB is at index 31. Carry propagates 31 → 0.
fn add_u32(b: &mut Builder, x: &U32, y: &U32) -> U32 {
    let mut sum = [0usize; 32];
    // Half adder for the LSB (index 31)
    sum[31] = b.xor(x[31], y[31]);
    let mut carry = b.and(x[31], y[31]);
    // Full adders for bits 30 down to 0
    for i in (0..31).rev() {
        let t1 = b.xor(x[i], y[i]);
        sum[i] = b.xor(t1, carry);
        let t2 = b.and(x[i], y[i]);
        let t3 = b.and(t1, carry);
        carry = b.xor(t2, t3);
    }
    sum
}

// ── SHA-256 round helpers ─────────────────────────────────────────────────────

fn ch(b: &mut Builder, x: &U32, y: &U32, z: &U32) -> U32 {
    // (x AND y) XOR ((NOT x) AND z)
    let xy = and_u32(b, x, y);
    let nx = not_u32(b, x);
    let nxz = and_u32(b, &nx, z);
    xor_u32(b, &xy, &nxz)
}

fn maj(b: &mut Builder, x: &U32, y: &U32, z: &U32) -> U32 {
    // (x AND y) XOR (x AND z) XOR (y AND z)
    let xy = and_u32(b, x, y);
    let xz = and_u32(b, x, z);
    let yz = and_u32(b, y, z);
    let a = xor_u32(b, &xy, &xz);
    xor_u32(b, &a, &yz)
}

fn big_sigma0(b: &mut Builder, x: &U32) -> U32 {
    let a = rotr_u32(x, 2);
    let c = rotr_u32(x, 13);
    let d = rotr_u32(x, 22);
    let e = xor_u32(b, &a, &c);
    xor_u32(b, &e, &d)
}

fn big_sigma1(b: &mut Builder, x: &U32) -> U32 {
    let a = rotr_u32(x, 6);
    let c = rotr_u32(x, 11);
    let d = rotr_u32(x, 25);
    let e = xor_u32(b, &a, &c);
    xor_u32(b, &e, &d)
}

fn small_sigma0(b: &mut Builder, x: &U32) -> U32 {
    let a = rotr_u32(x, 7);
    let c = rotr_u32(x, 18);
    let d = shr_u32(b, x, 3);
    let e = xor_u32(b, &a, &c);
    xor_u32(b, &e, &d)
}

fn small_sigma1(b: &mut Builder, x: &U32) -> U32 {
    let a = rotr_u32(x, 17);
    let c = rotr_u32(x, 19);
    let d = shr_u32(b, x, 10);
    let e = xor_u32(b, &a, &c);
    xor_u32(b, &e, &d)
}

// SHA-256 round constants (FIPS 180-4 §4.2.2)
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// ── SHA-256 compression circuit construction ──────────────────────────────────

fn build_compression() -> (Builder, Vec<usize>) {
    // 256 bits of IV + 512 bits of message block
    let mut b = Builder::new(768);

    // Parse the 256-bit IV into 8 u32 words (MSB-first within each word).
    let mut h: [U32; 8] = [[0; 32]; 8];
    for i in 0..8 {
        h[i] = input_word(i * 32);
    }
    // Parse the 512-bit message into 16 u32 words.
    let mut w: [U32; 64] = [[0; 32]; 64];
    for i in 0..16 {
        w[i] = input_word(256 + i * 32);
    }

    // Message schedule W[16..64]
    for i in 16..64 {
        // W[i] = sigma1(W[i-2]) + W[i-7] + sigma0(W[i-15]) + W[i-16]
        let s1 = small_sigma1(&mut b, &w[i - 2]);
        let s0 = small_sigma0(&mut b, &w[i - 15]);
        let t = add_u32(&mut b, &s1, &w[i - 7]);
        let u = add_u32(&mut b, &s0, &w[i - 16]);
        w[i] = add_u32(&mut b, &t, &u);
    }

    // Working variables a..h initialized to H[0..7]
    let (mut a, mut b_v, mut c, mut d, mut e, mut f, mut g, mut hh) =
        (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

    for i in 0..64 {
        let k_i = b.constant_u32(K[i]);
        // T1 = h + Sigma1(e) + Ch(e,f,g) + K[i] + W[i]
        let s1 = big_sigma1(&mut b, &e);
        let chv = ch(&mut b, &e, &f, &g);
        let t = add_u32(&mut b, &hh, &s1);
        let t = add_u32(&mut b, &t, &chv);
        let t = add_u32(&mut b, &t, &k_i);
        let t1 = add_u32(&mut b, &t, &w[i]);
        // T2 = Sigma0(a) + Maj(a,b,c)
        let s0 = big_sigma0(&mut b, &a);
        let mj = maj(&mut b, &a, &b_v, &c);
        let t2 = add_u32(&mut b, &s0, &mj);
        // Update
        hh = g;
        g = f;
        f = e;
        e = add_u32(&mut b, &d, &t1);
        d = c;
        c = b_v;
        b_v = a;
        a = add_u32(&mut b, &t1, &t2);
    }

    // Final H' = (a + H[0], b + H[1], ..., h + H[7])
    let r = [
        add_u32(&mut b, &a, &h[0]),
        add_u32(&mut b, &b_v, &h[1]),
        add_u32(&mut b, &c, &h[2]),
        add_u32(&mut b, &d, &h[3]),
        add_u32(&mut b, &e, &h[4]),
        add_u32(&mut b, &f, &h[5]),
        add_u32(&mut b, &g, &h[6]),
        add_u32(&mut b, &hh, &h[7]),
    ];

    // Concatenate the 8 output words into 256 output wires, MSB-first.
    let mut out_bits = Vec::with_capacity(256);
    for word in &r {
        for &wire in word.iter() {
            out_bits.push(wire);
        }
    }
    (b, out_bits)
}

// ── Validation ────────────────────────────────────────────────────────────────

fn validate(circ_bytes: &[u8]) -> Result<(), String> {
    use fancy_garbling::circuit::BinaryCircuit;
    use fancy_garbling::dummy::Dummy;
    use sha2::compress256;

    let circ = BinaryCircuit::parse(std::io::Cursor::new(circ_bytes))
        .map_err(|e| format!("parse generated circuit: {e:?}"))?;

    // Test vector: empty SHA-256 compress (one block of all-zero input with std IV).
    // Standard SHA-256 IV (FIPS 180-4)
    let iv: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Try a deterministic input: IV = std IV, M = "abc" + standard SHA-256 padding
    // "abc" + 0x80 + zeros + length(24 bits) = 64 bytes
    let mut m = [0u8; 64];
    m[0] = b'a';
    m[1] = b'b';
    m[2] = b'c';
    m[3] = 0x80;
    // Length = 24 bits = 0x00...18, big-endian, in the last 8 bytes
    m[63] = 0x18;

    // Reference using sha2's compress256
    let mut state = iv;
    let block = sha2::digest::generic_array::GenericArray::clone_from_slice(&m);
    compress256(&mut state, &[block]);
    let expected_hex: String = state.iter().map(|w| format!("{:08x}", w)).collect();
    // Known: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    assert_eq!(
        expected_hex,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "sanity: sha2::compress256 for SHA-256(\"abc\") should match the known digest"
    );

    // Build the 768-bit input the circuit expects: IV (256 bits) || M (512 bits), MSB-first.
    let mut iv_bytes = [0u8; 32];
    for (i, w) in iv.iter().enumerate() {
        iv_bytes[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
    }
    let mut input_bytes = [0u8; 96];
    input_bytes[..32].copy_from_slice(&iv_bytes);
    input_bytes[32..].copy_from_slice(&m);

    let bits: Vec<u16> = input_bytes
        .iter()
        .flat_map(|&b| (0..8u8).rev().map(move |i| ((b >> i) & 1) as u16))
        .collect();
    assert_eq!(bits.len(), 768);

    let out = Dummy::eval(&circ, &bits).map_err(|e| format!("Dummy::eval: {e:?}"))?;

    // Decode 256 output bits (MSB-first per byte) to 32 bytes
    let mut out_bytes = [0u8; 32];
    for (i, chunk) in out.chunks(8).enumerate().take(32) {
        for (j, &bit) in chunk.iter().enumerate() {
            out_bytes[i] |= (bit as u8) << (7 - j);
        }
    }
    let got_hex: String = out_bytes.iter().map(|b| format!("{:02x}", b)).collect();

    if got_hex != expected_hex {
        return Err(format!(
            "circuit output mismatch:\n  got:      {}\n  expected: {}",
            got_hex, expected_hex
        ));
    }
    eprintln!("validate: OK — SHA-256(\"abc\") = {}", got_hex);
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    let validate_only = args.iter().any(|a| a == "--validate");

    eprintln!("building SHA-256 compression circuit...");
    let (b, output_wires) = build_compression();
    eprintln!(
        "  built: {} gates, {} wires, {} output bits",
        b.gates.len(),
        b.next_wire,
        output_wires.len()
    );

    let mut buf = Vec::new();
    b.write(&mut buf, 256 + 512, 0, &output_wires);

    if !validate_only {
        let path = "circuits/sha-256-compress.txt";
        let mut f = BufWriter::new(File::create(path)?);
        f.write_all(&buf)?;
        f.flush()?;
        eprintln!("wrote {} ({} bytes)", path, buf.len());
    }

    eprintln!("validating against sha2::compress256...");
    validate(&buf)?;
    Ok(())
}
