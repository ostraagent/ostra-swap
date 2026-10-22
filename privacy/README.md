<p align="center">
  <a href="https://ostraagent.xyz"><img src="https://ostraagent.xyz/favicon.svg" width="72" height="72" alt="Ostra"></a>
</p>

<h1 align="center">Ostra Swap: private balances</h1>

<p align="center">
  The privacy core of Ostra Swap: a hash-only STARK that lets an agent spend a private note without saying which<br>
  note or whose, and the Solidity contract that checks it on Robinhood Chain. No elliptic curve, no trusted setup.
</p>

<p align="center">
  <a href="https://ostraagent.xyz"><img src="https://img.shields.io/badge/website-ostraagent.xyz-15171A" alt="Website"></a>
  <a href="https://docs.ostraagent.xyz"><img src="https://img.shields.io/badge/docs-docs.ostraagent.xyz-15171A" alt="Documentation"></a>
  <a href="https://x.com/ostraagent"><img src="https://img.shields.io/badge/X-@ostraagent-15171A?logo=x&logoColor=white" alt="Ostra Agent on X"></a>
  <a href="https://robinhoodchain.blockscout.com"><img src="https://img.shields.io/badge/Robinhood%20Chain-4663-D9381E" alt="Robinhood Chain 4663"></a>
  <img src="https://img.shields.io/badge/Plonky3-0.8.0-3E4248" alt="Plonky3 0.8.0">
  <img src="https://img.shields.io/badge/Solidity-0.8.24-3E4248" alt="Solidity 0.8.24">
</p>

## Why

An agent that trades in public shows every position it holds and every move it makes. A private balance hides who
owns a swap. Ostra does it with hashes only: elliptic-curve proofs (Groth16, PLONK over BN254) and ECDSA fall to a
large quantum computer, hash-based STARKs do not.

## What is in this folder

| Path | What it is |
| --- | --- |
| `circuit/src/lib.rs` | The note model and the spend circuit (`SpendAir`), its witness and trace, the proof configuration, prove and verify. |
| `circuit/src/flat.rs` | The flat calldata layout of a proof, read by the Solidity verifier; encode and decode. |
| `circuit/src/api.rs` | The prover's commands and their JSON: secrets, notes, Merkle paths, proofs. |
| `circuit/src/bin/ostra-prove.rs` | `ostra-prove`, the command-line prover: one command, JSON on stdin and stdout. |
| `wasm/` | The same prover as WebAssembly for Node and browsers (wasm-bindgen), the one the MCP package carries. |
| `contracts/src/SpendVerifier.sol` | The on-chain verifier. Follows Plonky3's `p3_uni_stark::verify` step for step. |
| `contracts/src/Notes.sol` | On-chain Poseidon2, note commitments, the commitment tree and the public values a pool hands the verifier. |
| `contracts/src/SpendConstants.sol` | Generated from Plonky3: transcript seeds, domains, Poseidon2 constants, empty subtree roots. |
| `tools/src/bin/spend.rs` | Generates the constants, real proofs, tampered proofs (each with Plonky3's own verdict) and test vectors. |

## Notes

A note holds an amount of one ERC-20 token and belongs to whoever knows its secret key `sk` and nonce `rho`.
With P the width-16 Poseidon2 permutation over KoalaBear (Plonky3's canonical constants) and `P(a || b)[0..8]`
its truncated compression:

```text
tag        = P(rho || sk)[0..8]                      published when the note is created
value      = P(asset[6] || amount[5] || 0[5])[0..8]  asset: 6 limbs of 27 bits, amount: 5 limbs of 26 bits
commitment = P(value || tag)[0..8]                   a leaf of the depth-20 commitment tree
nullifier  = P(rho || commitment)[0..8]              published when the note is spent
```

A spend proves, and reveals nothing else:

- the note is a leaf of the tree under a public root (the leaf index stays hidden);
- its nullifier is the public one, so a note can be spent once;
- its amount equals `v + fee + change` over the integers: `v` leaves the pool (to a swap or a withdrawal), `fee` pays
  the relayer that sent the transaction, and the change becomes a new note of the same token for the same owner;
- the proof is bound to the exact pool call it authorizes (a keccak-256 hash of the call becomes 8 public values).

What stays public: the token, `v`, `fee`, the nullifier, the root and the change commitment. A swap needs the token
and the amount in clear for the pool; what it hides is the owner.

Rules a wallet follows: `sk` comes from `ostra-prove secret`, once; every note gets a fresh `rho` from
`ostra-prove secret` (one tag per note); the pool refuses a commitment it already holds, so no two notes are alike.

## The circuit

`SpendAir` has 128 rows of 192 columns: one Poseidon2 permutation per row plus link, balance and range-check columns,
8 periodic selectors and 48 public values. Rows 0 to 3 hash the value, the tag, the commitment and the nullifier;
rows 4 to 23 the Merkle path; rows 24 and 25 the change note. The change limbs are range checked bit by bit, so the
balance cannot wrap around the field. 128 rows because the zero-knowledge PCS needs at least
2 (8 · 2 opening points + 19 queries) = 70 rows of mask.

The proof system is Plonky3 0.8.0 `uni-stark` with the hiding FRI PCS: KoalaBear with a degree-8 extension,
blowup 64, arity 4, 19 queries, 8 random codewords, grinding 10 + 16 bits, Keccak-256 Merkle commitments salted
with 4 elements. The prover's salts and random codewords come from the operating system's random source.

| | |
| --- | --- |
| Conjectured security (Plonky3 estimator) | 128 bits |
| Proven security (list decoding) | 72 bits |
| Note hashes (8 KoalaBear elements, about 248 bits) | about 124 bits of collision resistance |
| Proof size | about 75 KB |
| `SpendVerifier.verify` | about 9.2M to 9.3M gas, plus about 1.2M gas of calldata |
| `SpendVerifier` runtime size | 24,273 bytes |
| One on-chain Poseidon2 permutation / one tree insert | about 99K gas / 2.4M to 2.9M gas |

## Tests

```bash
cargo test --release --locked                      # circuit: proofs, dishonest provers, isolated attacks
cargo run --release --locked --bin spend -- contracts   # regenerate constants, proofs and vectors
cd contracts && forge test                         # verifier against Plonky3's own verdicts
```

- Every constraint group of the AIR is necessary: deleting any one of them makes a test fail (each malicious trace
  in `circuit/tests/isolated.rs` breaks exactly one group and is a concrete theft, double spend or value creation
  if that group were missing).
- The Solidity verifier accepts real proofs (including one whose queries open the same leaf twice) and rejects every
  tampered variant exactly where Plonky3 does; its constraint fold, selectors and quotient match Plonky3's own code.
- `SpendCliTest` verifies a proof that `ostra-prove prove` made, with operating-system randomness, from
  `test/data/cli_request.json` (stored in `test/data/cli_proof.bin`).

## Prover

```bash
ostra-prove secret                    # {"digest": [8]}: an sk, or a note's rho
ostra-prove note  < note.json         # {sk, rho, asset, amount} -> tag, commitment, nullifier
ostra-prove path  < leaves.json       # {leaves, index} -> root, path
ostra-prove prove < spend.json        # {sk, rho, asset, amount, index, path, v, fee, bind_hash, root?, change_rho?}
                                      #   -> proof, public_values, change_rho, change_tag
```

Randomness comes from the operating system through `getrandom`. The WebAssembly build runs the same commands in the
calling process, with randomness from `crypto.getRandomValues`:

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.129 --locked
wasm/build.sh                         # wasm/pkg: ostra_prove.js (initSync, prover) and ostra_prove_bg.wasm
```

```js
import { initSync, prover } from "./wasm/pkg/ostra_prove.js";
initSync({ module: wasmBytes });
JSON.parse(prover("prove", JSON.stringify(spend)));
```

`sdk/test/wasm-prover.test.ts` checks it against the native prover: the same notes and paths, the same public values,
and every proof accepted by `SpendVerifier`.

## Status

The circuit, the nullifier design and the verifier were reviewed independently in several rounds, and every confirmed
finding was fixed. There has been no paid audit, and nothing is deployed yet. The pool that uses this is
`src/OstraPrivatePool.sol` in the repository root.

## License

MIT, see [LICENSE](../LICENSE).
