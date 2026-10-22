//! Command-line prover for agents. Reads one JSON request on stdin (except `secret`) and writes one
//! JSON answer on stdout; the commands and their JSON are those of `ostra_swap_circuit::api`, which the
//! WebAssembly build (privacy/wasm) runs too.
//!
//!   ostra-prove secret  -> {"digest": [8]}  a fresh random digest, for an sk or a note's rho
//!   ostra-prove note    {"sk", "rho", "asset", "amount"}
//!                       -> {"tag": [8], "commitment": [8], "nullifier": [8]}
//!   ostra-prove path    {"leaves": [[8], ...], "index": n} -> {"root": [8], "path": [[8] x 20]}
//!   ostra-prove prove   {"sk", "rho", "asset", "amount", "index", "path": [[8] x 20], "v", "fee",
//!                        "bind_hash": "0x.." (32 bytes), "root": [8] (optional),
//!                        "change_rho": [8] (optional)}
//!                       -> {"proof": "0x..", "public_values": [48], "change_rho": [8], "change_tag": [8]}

use std::io::Read;

fn fail(msg: &str) -> ! {
    eprintln!("ostra-prove: {msg}");
    std::process::exit(1)
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    let mut input = String::new();
    if cmd != "secret" {
        std::io::stdin().read_to_string(&mut input).unwrap_or_else(|_| fail("cannot read stdin"));
    }
    match ostra_swap_circuit::api::run(&cmd, &input) {
        Ok(answer) => println!("{answer}"),
        Err(msg) => fail(&msg),
    }
}
