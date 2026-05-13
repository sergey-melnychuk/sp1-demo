use std::env;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};

fn main() {
    println!("cargo:rerun-if-changed=../program/src");
    println!("cargo:rerun-if-changed=../program/Cargo.toml");

    if env::var("SP1_SKIP_PROGRAM_BUILD").is_ok() {
        return;
    }

    let mut child = Command::new("cargo")
        .args(["prove", "build"])
        .current_dir("../program")
        .stdout(Stdio::piped())
        .spawn()
        .expect("failed to run `cargo prove build`");

    // Forward any cargo: directives (e.g. SP1_ELF_* env vars) to the outer build.
    let stdout = child.stdout.take().unwrap();
    for line in BufReader::new(stdout).lines().map_while(Result::ok) {
        if line.starts_with("cargo:") {
            println!("{line}");
        }
    }

    assert!(child.wait().expect("cargo prove build failed").success(), "cargo prove build failed");
}
