//! Command-line prover for agents. Reads one JSON request on stdin (except `secret`) and writes one
//! JSON answer on stdout. Field elements are decimal strings or numbers below P; amounts are decimal
//! strings below 2^128; an asset is a 0x-prefixed 20-byte address; a digest is 8 field elements.
//!
//!   ostra-prove secret  -> {"digest": [8]}  a fresh random digest, for an sk or a note's rho
//!   ostra-prove note    {"sk", "rho", "asset", "amount"}
//!                       -> {"tag": [8], "commitment": [8], "nullifier": [8]}
//!   ostra-prove path    {"leaves": [[8], ...], "index": n} -> {"root": [8], "path": [[8] x 20]}
//!   ostra-prove prove   {"sk", "rho", "asset", "amount", "index", "path": [[8] x 20], "v", "fee",
//!                        "bind_hash": "0x.." (32 bytes), "root": [8] (optional),
//!                        "change_rho": [8] (optional)}
//!                       -> {"proof": "0x..", "public_values": [48], "change_rho": [8], "change_tag": [8]}
//!
//! sk comes from `secret` once per agent; every note gets a fresh rho from `secret` (one fresh tag per
//! note). The change note belongs to the same sk under change_rho: drawn here from the operating
//! system unless given, returned, and to be kept by the agent with the change note. bind_hash is the keccak-256 hash of the pool call the proof authorizes; the binding
//! values are derived from it as the pool derives them (Notes.bindOf). The proof's salts and random
//! codewords come from the operating system's random source.

use std::io::Read;

use ostra_swap_circuit::*;
use p3_field::PrimeField32;
use serde_json::{Value, json};

fn fail(msg: &str) -> ! {
    eprintln!("ostra-prove: {msg}");
    std::process::exit(1)
}

fn field(v: &Value) -> Val {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => fail("a field element must be a string or a number"),
    };
    parse_val(&s).unwrap_or_else(|| fail("field element out of range"))
}

fn digest(v: &Value) -> Digest {
    let a = v.as_array().unwrap_or_else(|| fail("a digest must be an array of 8 field elements"));
    if a.len() != 8 {
        fail("a digest must have 8 elements");
    }
    core::array::from_fn(|i| field(&a[i]))
}

fn amount(v: &Value) -> u128 {
    let s = v.as_str().unwrap_or_else(|| fail("an amount must be a decimal string"));
    s.parse::<u128>().unwrap_or_else(|_| fail("amount out of range"))
}

fn hex_bytes<const N: usize>(v: &Value, what: &str) -> [u8; N] {
    let s = v.as_str().and_then(|s| s.strip_prefix("0x")).unwrap_or_else(|| fail(&format!("{what} must be 0x-prefixed")));
    if !s.is_ascii() || s.len() != 2 * N {
        fail(&format!("{what} must be {N} bytes"));
    }
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_else(|_| fail(&format!("{what} is not hex"))))
}

fn out(d: &[Val]) -> Value {
    Value::Array(d.iter().map(|x| json!(x.as_canonical_u32().to_string())).collect())
}

fn main() {
    let cmd = std::env::args().nth(1).unwrap_or_default();
    if cmd == "secret" {
        let d = os_digest().unwrap_or_else(|_| fail("no operating system randomness"));
        println!("{}", json!({"digest": out(&d)}));
        return;
    }
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input).unwrap_or_else(|_| fail("cannot read stdin"));
    let q: Value = serde_json::from_str(&input).unwrap_or_else(|_| fail("stdin is not JSON"));
    let answer = match cmd.as_str() {
        "note" => {
            let sk = digest(&q["sk"]);
            let a = asset_limbs(&hex_bytes::<20>(&q["asset"], "asset"));
            let t = tag(&sk, &digest(&q["rho"]));
            let c = commitment(&value_digest(&a, &amount_limbs(amount(&q["amount"]))), &t);
            json!({"tag": out(&t), "commitment": out(&c), "nullifier": out(&nullifier(&digest(&q["rho"]), &c))})
        }
        "path" => {
            let leaves = q["leaves"].as_array().unwrap_or_else(|| fail("leaves must be an array"));
            let index = q["index"].as_u64().unwrap_or_else(|| fail("index must be a number")) as usize;
            if index >= leaves.len() {
                fail("index beyond the leaves");
            }
            if leaves.len() > 1 << DEPTH {
                fail("more leaves than the tree holds");
            }
            let mut tree = Tree::new();
            leaves.iter().for_each(|l| {
                tree.append(digest(l));
            });
            let path = tree.path(index);
            json!({"root": out(&tree.root()), "path": Value::Array(path.iter().map(|p| out(p)).collect())})
        }
        "prove" => {
            let p = q["path"].as_array().unwrap_or_else(|| fail("path must be an array"));
            if p.len() != DEPTH {
                fail("path must have 20 siblings");
            }
            let sk = digest(&q["sk"]);
            let rho = digest(&q["rho"]);
            let change_rho = if q["change_rho"].is_null() {
                os_digest().unwrap_or_else(|_| fail("no operating system randomness"))
            } else {
                digest(&q["change_rho"])
            };
            if change_rho == rho {
                fail("change_rho must be a fresh nonce, not the spent note's rho");
            }
            let spend = Spend {
                sk,
                rho,
                asset: hex_bytes::<20>(&q["asset"], "asset"),
                amount: amount(&q["amount"]),
                index: q["index"].as_u64().unwrap_or_else(|| fail("index must be a number")) as usize,
                path: core::array::from_fn(|i| digest(&p[i])),
                v: amount(&q["v"]),
                fee: amount(&q["fee"]),
                change_tag: tag(&sk, &change_rho),
                bind: bind_from_hash(&hex_bytes::<32>(&q["bind_hash"], "bind_hash")),
            };
            if !q["root"].is_null() && spend.root() != digest(&q["root"]) {
                fail("the note and path do not lead to the given root");
            }
            let seed = os_seed().unwrap_or_else(|_| fail("no operating system randomness"));
            let (proof, pv) = prove(&spend, seed).unwrap_or_else(|e| fail(&format!("invalid spend: {e:?}")));
            if !verify(&proof, &pv) {
                fail("the proof does not verify");
            }
            let flat = flat::encode(&proof);
            let hex: String = flat.iter().map(|b| format!("{b:02x}")).collect();
            json!({"proof": format!("0x{hex}"), "public_values": out(&pv), "change_rho": out(&change_rho), "change_tag": out(&spend.change_tag)})
        }
        _ => fail("usage: ostra-prove secret | note|path|prove < request.json"),
    };
    println!("{answer}");
}
