//! The prover's JSON interface, shared by the command-line prover (`ostra-prove`) and its WebAssembly build
//! (`privacy/wasm`): one command and one JSON request in, one JSON answer out. Field elements are decimal strings or
//! numbers below P; amounts are decimal strings below 2^128; an asset is a 0x-prefixed 20-byte address; a digest is 8
//! field elements.
//!
//!   secret  -> {"digest": [8]}  a fresh random digest, for an sk or a note's rho (no request)
//!   note    {"sk", "rho", "asset", "amount"}
//!           -> {"tag": [8], "commitment": [8], "nullifier": [8]}
//!   path    {"leaves": [[8], ...], "index": n} -> {"root": [8], "path": [[8] x 20]}
//!   prove   {"sk", "rho", "asset", "amount", "index", "path": [[8] x 20], "v", "fee",
//!            "bind_hash": "0x.." (32 bytes), "root": [8] (optional), "change_rho": [8] (optional)}
//!           -> {"proof": "0x..", "public_values": [48], "change_rho": [8], "change_tag": [8]}
//!
//!   rep-id     {"sk"} -> {"idc": [8]}  the identity commitment of a reputation secret (an sk from `secret` used for
//!              reputation only, never a note's sk)
//!   rep-record {"record": {"completed", "clients", "volume", "rejected", "expired", "tier", "first_day", "epoch"},
//!               "idc": [8]} -> {"record": [8], "leaf": [8]}  the leaf OstraReputation appends for that snapshot
//!   rep-prove  {"sk", "record": {fields as in rep-record, "epoch" optional}, "epoch", "index", "path": [[8] x 20],
//!               "root": [8], "scope": "0x.." (32 bytes), "thresholds": {"min_completed", "min_clients", "min_volume",
//!               "max_fail_permille", "min_tier", "max_first_day"}, "bind_hash": "0x.." (32 bytes)}
//!              -> {"proof": "0x..", "public_values": [43], "pseudonym": [8], "idc": [8]}
//!
//! Reputation counts are decimal strings or numbers below 2^32, volumes decimal strings below 2^128. A reputation proof's
//! epoch is the verifier's current one and must be the record's; its scope elements and binding values come from
//! `scope` and `bind_hash` as OstraReputation derives them (keccak256(abi.encode(scope)), Notes.bindOf of
//! keccak256(abi.encode(scope, recipient, challenge))).
//!
//! sk comes from `secret` once per agent; every note gets a fresh rho (one fresh tag per note). The change note
//! belongs to the same sk under change_rho: drawn here from the operating system unless given, returned, and to be
//! kept by the agent with the change note. bind_hash is the keccak-256 hash of the pool call the proof authorizes;
//! the binding values are derived from it as the pool derives them (Notes.bindOf). The proof's salts and random
//! codewords come from the operating system's random source (`os_seed`).

use p3_field::PrimeField32;
use serde_json::{Value, json};

use crate::*;

type R<T> = Result<T, String>;

fn field(v: &Value) -> R<Val> {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return Err("a field element must be a string or a number".into()),
    };
    parse_val(&s).ok_or_else(|| "field element out of range".into())
}

fn digest(v: &Value) -> R<Digest> {
    let a = v.as_array().ok_or("a digest must be an array of 8 field elements")?;
    if a.len() != 8 {
        return Err("a digest must have 8 elements".into());
    }
    let mut d = [Val::ZERO; 8];
    for (i, x) in d.iter_mut().enumerate() {
        *x = field(&a[i])?;
    }
    Ok(d)
}

fn amount(v: &Value) -> R<u128> {
    let s = v.as_str().ok_or("an amount must be a decimal string")?;
    s.parse::<u128>().map_err(|_| "amount out of range".into())
}

fn hex_bytes<const N: usize>(v: &Value, what: &str) -> R<[u8; N]> {
    let s = v.as_str().and_then(|s| s.strip_prefix("0x")).ok_or_else(|| format!("{what} must be 0x-prefixed"))?;
    if !s.is_ascii() || s.len() != 2 * N {
        return Err(format!("{what} must be {N} bytes"));
    }
    let mut b = [0u8; N];
    for (i, x) in b.iter_mut().enumerate() {
        *x = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|_| format!("{what} is not hex"))?;
    }
    Ok(b)
}

/// A leaf index: below 2^DEPTH on every target (usize is 32 bits in WebAssembly, so a larger value is refused, never
/// cut down).
fn index(v: &Value) -> R<usize> {
    let n = v.as_u64().ok_or("index must be a number")?;
    usize::try_from(n).ok().filter(|&i| i < 1 << DEPTH).ok_or_else(|| "index beyond the tree".into())
}

fn count(v: &Value, what: &str) -> R<u32> {
    let s = match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return Err(format!("{what} must be a decimal string or a number")),
    };
    s.parse::<u32>().map_err(|_| format!("{what} out of range"))
}

fn record(v: &Value, epoch: u32) -> R<rep::Record> {
    if !v.is_object() {
        return Err("record must be an object".into());
    }
    let r = rep::Record {
        completed: count(&v["completed"], "completed")?,
        clients: count(&v["clients"], "clients")?,
        volume: amount(&v["volume"])?,
        rejected: count(&v["rejected"], "rejected")?,
        expired: count(&v["expired"], "expired")?,
        tier: count(&v["tier"], "tier")?,
        first_day: count(&v["first_day"], "first_day")?,
        epoch,
    };
    if !r.in_range() {
        return Err("a record field is beyond what OstraReputation writes".into());
    }
    Ok(r)
}

fn thresholds(v: &Value) -> R<rep::Thresholds> {
    if !v.is_object() {
        return Err("thresholds must be an object".into());
    }
    let t = rep::Thresholds {
        min_completed: count(&v["min_completed"], "min_completed")?,
        min_clients: count(&v["min_clients"], "min_clients")?,
        min_volume: amount(&v["min_volume"])?,
        max_fail_permille: count(&v["max_fail_permille"], "max_fail_permille")?,
        min_tier: count(&v["min_tier"], "min_tier")?,
        max_first_day: count(&v["max_first_day"], "max_first_day")?,
    };
    rep::check_thresholds(&t).map_err(|_| "a threshold is out of range")?;
    Ok(t)
}

fn path(v: &Value) -> R<[Digest; DEPTH]> {
    let p = v.as_array().ok_or("path must be an array")?;
    if p.len() != DEPTH {
        return Err("path must have 20 siblings".into());
    }
    let mut siblings = [[Val::ZERO; 8]; DEPTH];
    for (i, s) in siblings.iter_mut().enumerate() {
        *s = digest(&p[i])?;
    }
    Ok(siblings)
}

fn out(d: &[Val]) -> Value {
    Value::Array(d.iter().map(|x| json!(x.as_canonical_u32().to_string())).collect())
}

const NO_RANDOMNESS: &str = "no operating system randomness";

/// Runs `command` on `request` (ignored by `secret`); the answer is one line of JSON, or an error message.
pub fn run(command: &str, request: &str) -> R<String> {
    if command == "secret" {
        let d = os_digest().map_err(|_| NO_RANDOMNESS)?;
        return Ok(json!({"digest": out(&d)}).to_string());
    }
    if !matches!(command, "note" | "path" | "prove" | "rep-id" | "rep-record" | "rep-prove") {
        return Err("usage: ostra-prove secret | note|path|prove|rep-id|rep-record|rep-prove < request.json".into());
    }
    let q: Value = serde_json::from_str(request).map_err(|_| "the request is not JSON")?;
    let answer = match command {
        "note" => {
            let sk = digest(&q["sk"])?;
            let rho = digest(&q["rho"])?;
            let a = asset_limbs(&hex_bytes::<20>(&q["asset"], "asset")?);
            let t = tag(&sk, &rho);
            let c = commitment(&value_digest(&a, &amount_limbs(amount(&q["amount"])?)), &t);
            json!({"tag": out(&t), "commitment": out(&c), "nullifier": out(&nullifier(&rho, &c))})
        }
        "path" => {
            let leaves = q["leaves"].as_array().ok_or("leaves must be an array")?;
            let i = index(&q["index"])?;
            if i >= leaves.len() {
                return Err("index beyond the leaves".into());
            }
            if leaves.len() > 1 << DEPTH {
                return Err("more leaves than the tree holds".into());
            }
            let mut tree = Tree::new();
            for l in leaves {
                tree.append(digest(l)?);
            }
            let path = tree.path(i);
            json!({"root": out(&tree.root()), "path": Value::Array(path.iter().map(|p| out(p)).collect())})
        }
        "rep-id" => json!({"idc": out(&rep::idc(&digest(&q["sk"])?))}),
        "rep-record" => {
            let r = record(&q["record"], count(&q["record"]["epoch"], "epoch")?)?;
            let id = digest(&q["idc"])?;
            json!({"record": out(&r.digest()), "leaf": out(&r.leaf(&id))})
        }
        "rep-prove" => {
            let epoch = count(&q["epoch"], "epoch")?;
            if !q["record"]["epoch"].is_null() && count(&q["record"]["epoch"], "epoch")? != epoch {
                return Err("the record is not of the given epoch".into());
            }
            let w = rep::Rep {
                sk: digest(&q["sk"])?,
                record: record(&q["record"], epoch)?,
                index: index(&q["index"])?,
                path: path(&q["path"])?,
                scope: rep::scope_elements(&hex_bytes::<32>(&q["scope"], "scope")?),
                thresholds: thresholds(&q["thresholds"])?,
                bind: bind_from_hash(&hex_bytes::<32>(&q["bind_hash"], "bind_hash")?),
            };
            if w.root() != digest(&q["root"])? {
                return Err("the record and path do not lead to the given root".into());
            }
            if !rep::meets(&w.record, &w.thresholds) {
                return Err("the record does not meet the thresholds".into());
            }
            let seed = os_seed().map_err(|_| NO_RANDOMNESS)?;
            let (proof, pv) = rep::prove_rep(&w, seed).map_err(|e| format!("invalid reputation proof: {e:?}"))?;
            if !rep::verify_rep(&proof, &pv) {
                return Err("the proof does not verify".into());
            }
            let flat = flat::encode_width(&proof, rep::REP_WIDTH);
            let hex: String = flat.iter().map(|b| format!("{b:02x}")).collect();
            json!({"proof": format!("0x{hex}"), "public_values": out(&pv), "pseudonym": out(&w.pseudonym()), "idc": out(&w.idc())})
        }
        _ => {
            let p = q["path"].as_array().ok_or("path must be an array")?;
            if p.len() != DEPTH {
                return Err("path must have 20 siblings".into());
            }
            let sk = digest(&q["sk"])?;
            let rho = digest(&q["rho"])?;
            let change_rho = if q["change_rho"].is_null() { os_digest().map_err(|_| NO_RANDOMNESS)? } else { digest(&q["change_rho"])? };
            if change_rho == rho {
                return Err("change_rho must be a fresh nonce, not the spent note's rho".into());
            }
            let mut siblings = [[Val::ZERO; 8]; DEPTH];
            for (i, s) in siblings.iter_mut().enumerate() {
                *s = digest(&p[i])?;
            }
            let spend = Spend {
                sk,
                rho,
                asset: hex_bytes::<20>(&q["asset"], "asset")?,
                amount: amount(&q["amount"])?,
                index: index(&q["index"])?,
                path: siblings,
                v: amount(&q["v"])?,
                fee: amount(&q["fee"])?,
                change_tag: tag(&sk, &change_rho),
                bind: bind_from_hash(&hex_bytes::<32>(&q["bind_hash"], "bind_hash")?),
            };
            if !q["root"].is_null() && spend.root() != digest(&q["root"])? {
                return Err("the note and path do not lead to the given root".into());
            }
            let seed = os_seed().map_err(|_| NO_RANDOMNESS)?;
            let (proof, pv) = prove(&spend, seed).map_err(|e| format!("invalid spend: {e:?}"))?;
            if !verify(&proof, &pv) {
                return Err("the proof does not verify".into());
            }
            let flat = flat::encode(&proof);
            let hex: String = flat.iter().map(|b| format!("{b:02x}")).collect();
            json!({"proof": format!("0x{hex}"), "public_values": out(&pv), "change_rho": out(&change_rho), "change_tag": out(&spend.change_tag)})
        }
    };
    Ok(answer.to_string())
}
