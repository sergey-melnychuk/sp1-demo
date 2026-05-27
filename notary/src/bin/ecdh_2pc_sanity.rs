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
    EcdhIkmDriver, EcdhSetupOutcome, LeakyAdditivePointEcdh, OtX25519Blinded, generate_share,
    host_send_ecdh_leaky, host_send_ecdh_ot, notary_recv_ecdh_setup, share_from_bytes,
    share_to_bytes,
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

    /// With `--self-test`, run OT-blinded protocol instead of leaky additive.
    #[arg(long)]
    ot: bool,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run_self_test(ot: bool) -> Result<()> {
    use notary::ecdh::reference_ikm;
    use rand::rngs::OsRng;
    use std::io::{Read, Write};

    let mut rng = OsRng;
    let server_sk = StaticSecret::random_from_rng(&mut rng);
    let server_epk = *PublicKey::from(&server_sk).as_bytes();
    let k_c = generate_share(&mut rng);
    let k_n = generate_share(&mut rng);
    let expect = reference_ikm(&k_c, &k_n, &server_epk);

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

    if ot {
        let notary = std::thread::spawn(move || {
            let mut io = Duplex {
                r: n2h_r,
                w: h2n_w,
            };
            match notary_recv_ecdh_setup(&mut io, &k_n, &mut rng).unwrap() {
                EcdhSetupOutcome::Ot(o) => o,
                _ => panic!("expected OT ECDH"),
            }
        });
        let mut host_io = Duplex {
            r: h2n_r,
            w: n2h_w,
        };
        let host_out = host_send_ecdh_ot(&mut host_io, &k_c, &server_epk)?;
        let notary_out = notary.join().unwrap();
        assert_eq!(notary_out.ikm.0, expect.0);
        assert_eq!(host_out.host_ikm_share, notary_out.host_ikm_share);
        eprintln!("self-test (OT) ok: IKM = {}", hex(&expect.0));
        return Ok(());
    }

    let notary = std::thread::spawn(move || {
        let mut io = Duplex {
            r: n2h_r,
            w: h2n_w,
        };
        match notary_recv_ecdh_setup(&mut io, &k_n, &mut rng).unwrap() {
            EcdhSetupOutcome::Leaky(o) => o,
            _ => panic!("expected leaky ECDH"),
        }
    });

    let mut host_io = Duplex {
        r: h2n_r,
        w: n2h_w,
    };
    let host_out = host_send_ecdh_leaky(&mut host_io, &k_c, &k_n, &server_epk)?;
    let notary_out = notary.join().unwrap();

    assert_eq!(host_out.ikm.0, expect.0);
    assert_eq!(notary_out.ikm.0, expect.0);
    eprintln!("self-test ok: IKM = {}", hex(&expect.0));
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();
    if args.self_test {
        return run_self_test(args.ot);
    }

    let driver: &dyn EcdhIkmDriver = if args.ot {
        &OtX25519Blinded
    } else {
        &LeakyAdditivePointEcdh
    };
    eprintln!("driver: {}", driver.name());

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
    let host_share = share_from_bytes(
        &{
            let mut b = [0u8; 32];
            stream.read_exact(&mut b).context("read host share")?;
            b
        },
    );
    eprintln!("notary: server_epk = {}", hex(&server_epk));

    let mut rng = OsRng;
    let share = generate_share(&mut rng);
    stream
        .write_all(&share_to_bytes(&share))
        .context("write notary share")?;
    let out = notary::ecdh::notary_run_leaky_additive(
        &share,
        &host_share,
        &server_epk,
        &mut stream,
        &mut rng,
    )
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
    stream
        .write_all(&share_to_bytes(&k_c))
        .context("write host share")?;
    let mut notary_share_bytes = [0u8; 32];
    stream
        .read_exact(&mut notary_share_bytes)
        .context("read notary share")?;
    let k_n = share_from_bytes(&notary_share_bytes);
    let out = notary::ecdh::host_run_leaky_additive(&k_c, &k_n, &server_epk, &mut stream)
        .context("host_run_leaky_additive")?;

    let recon: [u8; 32] =
        std::array::from_fn(|i| out.host_ikm_share[i] ^ out.notary_ikm_share[i]);
    assert_eq!(recon, out.ikm.0, "XOR IKM shares must reconstruct IKM");

    eprintln!("host: IKM            = {}", hex(&out.ikm.0));
    eprintln!("host: host IKM share = {}", hex(&out.host_ikm_share));
    eprintln!("host: XOR recon ok");
    Ok(())
}
