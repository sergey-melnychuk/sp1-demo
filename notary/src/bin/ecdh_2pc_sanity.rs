//! Offline sanity check for [`notary::ecdh`] leaky additive wire protocol.
//!
//! Does **not** touch TLS. Both parties still learn full IKM — see `ECDH.md`.
//!
//! ```text
//! # terminal A
//! cargo run --release --bin ecdh_2pc_sanity -- --listen 127.0.0.1:9010
//!
//! # terminal B
//! cargo run --release --bin ecdh_2pc_sanity -- --connect 127.0.0.1:9010
//!
//! # CI / quick check
//! cargo run --release --bin ecdh_2pc_sanity -- --self-test
//! ```

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

use anyhow::{Context, Result, bail};
use clap::Parser;
use notary::ecdh::{
    EcdhIkmDriver, LeakyAdditivePointEcdh, generate_share, host_run_leaky_additive,
    notary_run_leaky_additive,
};
use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser, Debug)]
#[command(about = "Leaky additive X25519 2PC wire sanity (no TLS)")]
struct Args {
    #[arg(long, conflicts_with = "connect")]
    listen: Option<String>,

    #[arg(long, conflicts_with = "listen")]
    connect: Option<String>,
    /// If set, run in-process pipe roundtrip (no network). Useful for CI.
    #[arg(long, conflicts_with_all = ["listen", "connect"])]
    self_test: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run_self_test() -> Result<()> {
    use notary::ecdh::reference_ikm;
    use rand::rngs::OsRng;
    use std::io::{Read, Write};

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
    let host_out = host_run_leaky_additive(&k_c, &server_epk, &mut host_io)?;
    let notary_out = notary.join().unwrap()?;

    let expect = reference_ikm(&k_c, &k_n, &server_epk);
    assert_eq!(host_out.ikm.0, expect.0);
    assert_eq!(notary_out.ikm.0, expect.0);
    eprintln!("self-test ok: IKM = {}", hex(&expect.0));
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    let driver = LeakyAdditivePointEcdh;
    eprintln!("driver: {}", driver.name());

    if args.self_test {
        return run_self_test();
    }

    match (args.listen, args.connect) {
        (Some(listen), None) => run_notary(&listen),
        (None, Some(addr)) => run_host(&addr),
        _ => bail!("specify exactly one of --listen or --connect"),
    }
}

fn run_notary(listen: &str) -> Result<()> {
    let listener = TcpListener::bind(listen).with_context(|| format!("bind {listen}"))?;
    eprintln!("notary: listening on {listen}");
    let (mut stream, peer) = listener.accept().context("accept")?;
    eprintln!("notary: connection from {peer}");
    stream.set_nodelay(true)?;

    let mut server_epk = [0u8; 32];
    stream.read_exact(&mut server_epk).context("read server_epk")?;
    eprintln!("notary: server_epk = {}", hex(&server_epk));

    let mut rng = OsRng;
    let share = generate_share(&mut rng);
    let out = notary_run_leaky_additive(&share, &server_epk, &mut stream, &mut rng)
        .context("notary_run_leaky_additive")?;

    eprintln!("notary: IKM            = {}", hex(&out.ikm.0));
    eprintln!("notary: IKM mask share = {}", hex(&out.notary_ikm_share));
    Ok(())
}

fn run_host(connect: &str) -> Result<()> {
    let mut stream = TcpStream::connect(connect).with_context(|| format!("connect {connect}"))?;
    stream.set_nodelay(true)?;

    let mut rng = OsRng;
    // Simulated TLS server ephemeral (host knows server_epk; notary learns it on the wire).
    let server_sk = StaticSecret::random_from_rng(&mut rng);
    let server_epk = *PublicKey::from(&server_sk).as_bytes();
    stream
        .write_all(&server_epk)
        .context("write server_epk")?;

    let k_c = generate_share(&mut rng);
    let out = host_run_leaky_additive(&k_c, &server_epk, &mut stream)
        .context("host_run_leaky_additive")?;

    let recon: [u8; 32] =
        std::array::from_fn(|i| out.host_ikm_share[i] ^ out.notary_ikm_share[i]);
    assert_eq!(recon, out.ikm.0, "XOR IKM shares must reconstruct IKM");

    eprintln!("host: IKM            = {}", hex(&out.ikm.0));
    eprintln!("host: host IKM share = {}", hex(&out.host_ikm_share));
    eprintln!("host: XOR recon ok");
    Ok(())
}
