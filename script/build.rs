use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=../program/src");
    println!("cargo:rerun-if-changed=../program/Cargo.toml");

    if env::var("SP1_SKIP_PROGRAM_BUILD").is_err() {
        let status = Command::new("cargo")
            .args(["prove", "build"])
            .current_dir("../program")
            .status()
            .expect("failed to run `cargo prove build`");
        assert!(status.success(), "cargo prove build failed");
    }

    // The ELF is placed at a deterministic path by cargo prove build.
    // Always emit the env var so include_elf! works regardless of skip flag.
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let elf = manifest_dir
        .join("../target/elf-compilation/riscv64im-succinct-zkvm-elf/release/sp1-https-json-program")
        .canonicalize()
        .expect("ELF not found — did `cargo prove build` succeed?");

    println!(
        "cargo:rustc-env=SP1_ELF_sp1-https-json-program={}",
        elf.display()
    );
}
