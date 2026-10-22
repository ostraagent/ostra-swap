//! The Ostra Swap spend circuit.
//!
//! A private balance is a set of notes. A note holds an amount of one ERC-20 asset and belongs to
//! whoever knows its secret key `sk` and its nonce `rho`:
//!
//! ```text
//!     tag        = P(rho || sk)[0..8]
//!     value      = P(asset[6] || amount[5] || 0[5])[0..8]
//!     commitment = P(value || tag)[0..8]
//!     nullifier  = P(rho || commitment)[0..8]
//! ```
//!
//! The nullifier is bound to the commitment, so two notes with different contents always have
//! different nullifiers, even under one tag; the pool refuses a commitment it already holds, so no two
//! notes are identical. It is keyed by the note's own nonce rho, so linking a nullifier to its
//! commitment takes that note's rho: neither sk alone nor anything public links them. Every note gets
//! a fresh rho (and so a fresh tag) from the operating system's random source.
//!
//! where P is the width-16 Poseidon2 permutation over KoalaBear with Plonky3's canonical round
//! constants, and `P(l || r)[0..8]` is Plonky3's `TruncatedPermutation` compression. Commitments are
//! the leaves of a depth-20 Merkle tree whose nodes are `P(left || right)[0..8]`.
//!
//! A spend proves, without revealing which note or whose: the note is in the tree under `root`; its
//! nullifier is `nullifier`; and its amount splits into a public amount `v` that leaves the pool, a
//! public relayer fee `fee`, and a change note `change_commitment` of the same asset whose owner
//! (its tag) the prover chooses. The binding values `bind` (a hash of the caller's call data) enter
//! the Fiat-Shamir transcript as public values, so a proof is valid for that call only.
//!
//! Amounts are below 2^128, held as five 26-bit limbs; an asset is an EVM address, held as six
//! 27-bit limbs. The change amount is range checked bit by bit, so `amount = v + fee + change`
//! holds over the integers.
//!
//! The proof system is Plonky3 0.8.0 uni-stark with the zero-knowledge (hiding) FRI PCS, a degree-8
//! extension of KoalaBear and Keccak-256 Merkle commitments: hashes only, no elliptic curve, no
//! trusted setup.

pub mod api;
pub mod flat;

use std::borrow::{Borrow, BorrowMut, Cow};
use std::mem::MaybeUninit;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_fri::{FriParameters, HidingFriPcs};
use p3_keccak::Keccak256Hash;
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_16_INTERNAL, KoalaBear,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Cols, RoundConstants, generate_trace_rows_for_perm, num_cols};
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::{Proof, StarkConfig};
use rand::SeedableRng;
use rand::rngs::StdRng;

// ------------------------------------------------------------------------------------------------
// Proof system configuration

pub const LOG_BLOWUP: usize = 6;
pub const MAX_LOG_ARITY: usize = 2;
pub const LOG_FINAL_POLY_LEN: usize = 4;
pub const NUM_QUERIES: usize = 19;
pub const QUERY_POW_BITS: usize = 16;
pub const BATCH_POW_BITS: usize = 10;
/// Random codewords mixed in by the hiding PCS: at least the extension degree.
pub const NUM_RANDOM_CODEWORDS: usize = 8;
/// Conjectured security target, in bits; the cap Keccak-256's collision resistance allows.
pub const SECURITY_BITS: usize = 128;
pub const COLLISION_BITS: usize = 128;

pub type Val = KoalaBear;
pub type Challenge = BinomialExtensionField<Val, 8>;

type ByteHash = Keccak256Hash;
type FieldHash = SerializingHasher<ByteHash>;
type Compress = CompressionFunctionFromHasher<ByteHash, 2, 32>;

pub type ValMmcs = MerkleTreeHidingMmcs<Val, u8, FieldHash, Compress, StdRng, 2, 32, 4>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
pub type Dft = p3_dft::Radix2Bowers;
pub type Pcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, StdRng>;
pub type Config = StarkConfig<Pcs, Challenge, Challenger>;

pub fn fri_parameters(val_mmcs: &ValMmcs) -> FriParameters<ChallengeMmcs> {
    FriParameters {
        log_blowup: LOG_BLOWUP,
        log_final_poly_len: LOG_FINAL_POLY_LEN,
        max_log_arity: MAX_LOG_ARITY,
        num_queries: NUM_QUERIES,
        batch_proof_of_work_bits: BATCH_POW_BITS,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: QUERY_POW_BITS,
        mmcs: ChallengeMmcs::new(val_mmcs.clone()),
    }
}

/// The configuration. `seed` feeds the prover's Merkle salts and random codewords, which carry the
/// zero-knowledge property: a real prover draws it from the operating system (see `os_seed`); the
/// verifier never draws from it.
pub fn config(seed: [u8; 32]) -> Config {
    let mut second = seed;
    second[31] ^= 0x5a;
    let val_mmcs = ValMmcs::new(FieldHash::new(ByteHash {}), Compress::new(ByteHash {}), 0, StdRng::from_seed(seed));
    let fri = fri_parameters(&val_mmcs);
    let pcs = Pcs::new(Dft::default(), val_mmcs, fri, NUM_RANDOM_CODEWORDS, StdRng::from_seed(second));
    Config::new(pcs, Challenger::from_hasher(vec![], ByteHash {}))
}

/// A deterministic seed, for tests and reproducible vectors only.
pub fn test_seed(n: u64) -> [u8; 32] {
    let mut s = [0u8; 32];
    s[..8].copy_from_slice(&n.to_le_bytes());
    s
}

/// 32 bytes from the operating system's random source (getrandom: the system call or its equivalent on each
/// operating system; `crypto.getRandomValues` in the WebAssembly build).
pub fn os_seed() -> std::io::Result<[u8; 32]> {
    let mut s = [0u8; 32];
    getrandom::fill(&mut s).map_err(std::io::Error::other)?;
    Ok(s)
}

// ------------------------------------------------------------------------------------------------
// Poseidon2 and note hashing

pub const WIDTH: usize = 16;
const SBOX_DEGREE: u64 = 3;
const SBOX_REGISTERS: usize = 0;
const HALF_FULL_ROUNDS: usize = 4;
const PARTIAL_ROUNDS: usize = 20;
/// Columns of one Poseidon2 permutation (Plonky3's Poseidon2Cols layout).
pub const P2_COLS: usize = num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
type LinearLayers = GenericPoseidon2LinearLayersKoalaBear;
type P2Cols<T> = Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

pub type Digest = [Val; 8];

fn round_constants() -> RoundConstants<Val, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    RoundConstants::new(
        KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
        KOALABEAR_POSEIDON2_RC_16_INTERNAL,
        KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    )
}

/// The trace row of one permutation, computed by Plonky3's own trace generation.
pub fn permutation_row(input: [Val; WIDTH]) -> Vec<Val> {
    let mut row = vec![MaybeUninit::<Val>::uninit(); P2_COLS];
    let cols: &mut P2Cols<MaybeUninit<Val>> = row.as_mut_slice().borrow_mut();
    generate_trace_rows_for_perm::<Val, LinearLayers, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(
        cols,
        input,
        &round_constants(),
    );
    // With no S-box registers every column is written.
    row.into_iter().map(|x| unsafe { x.assume_init() }).collect()
}

/// The permutation's output in a permutation row.
pub fn row_output(row: &[Val]) -> [Val; WIDTH] {
    let cols: &P2Cols<Val> = row[..P2_COLS].borrow();
    cols.ending_full_rounds[HALF_FULL_ROUNDS - 1].post
}

/// Column of output element `i` in a permutation row.
pub fn output_col(i: usize) -> usize {
    P2_COLS - WIDTH + i
}

pub fn permute(input: [Val; WIDTH]) -> [Val; WIDTH] {
    row_output(&permutation_row(input))
}

pub fn compress(l: &Digest, r: &Digest) -> Digest {
    let mut s = [Val::ZERO; WIDTH];
    s[..8].copy_from_slice(l);
    s[8..].copy_from_slice(r);
    permute(s)[..8].try_into().unwrap()
}

pub const AMOUNT_LIMBS: usize = 5;
pub const AMOUNT_LIMB_BITS: usize = 26;
pub const ASSET_LIMBS: usize = 6;
pub const ASSET_LIMB_BITS: usize = 27;

/// An amount below 2^128 as five little-endian 26-bit limbs.
pub fn amount_limbs(a: u128) -> [Val; AMOUNT_LIMBS] {
    core::array::from_fn(|i| Val::from_u32(((a >> (AMOUNT_LIMB_BITS * i)) & ((1 << AMOUNT_LIMB_BITS) - 1)) as u32))
}

/// A 20-byte address (big-endian) as six little-endian 27-bit limbs.
pub fn asset_limbs(addr: &[u8; 20]) -> [Val; ASSET_LIMBS] {
    let mut x = [0u8; 32];
    x[12..].copy_from_slice(addr);
    core::array::from_fn(|i| {
        let mut v: u64 = 0;
        for b in 0..ASSET_LIMB_BITS {
            let bit = ASSET_LIMB_BITS * i + b;
            if bit < 160 {
                let byte = x[31 - bit / 8];
                v |= (((byte >> (bit % 8)) & 1) as u64) << b;
            }
        }
        Val::from_u32(v as u32)
    })
}

pub fn value_input(asset: &[Val; ASSET_LIMBS], amount: &[Val; AMOUNT_LIMBS]) -> [Val; WIDTH] {
    let mut s = [Val::ZERO; WIDTH];
    s[..ASSET_LIMBS].copy_from_slice(asset);
    s[ASSET_LIMBS..ASSET_LIMBS + AMOUNT_LIMBS].copy_from_slice(amount);
    s
}

pub fn value_digest(asset: &[Val; ASSET_LIMBS], amount: &[Val; AMOUNT_LIMBS]) -> Digest {
    permute(value_input(asset, amount))[..8].try_into().unwrap()
}

pub fn tag(sk: &Digest, rho: &Digest) -> Digest {
    compress(rho, sk)
}

/// The nullifier of the note with this nonce and commitment.
pub fn nullifier(rho: &Digest, commitment: &Digest) -> Digest {
    compress(rho, commitment)
}

pub fn commitment(value: &Digest, tag: &Digest) -> Digest {
    compress(value, tag)
}

// ------------------------------------------------------------------------------------------------
// Commitment tree

pub const DEPTH: usize = 20;

/// Roots of empty subtrees: zeros[0] is the empty leaf (all zero), zeros[k + 1] = P(zeros[k] || zeros[k]).
pub fn empty_roots() -> Vec<Digest> {
    let mut z = vec![[Val::ZERO; 8]];
    for k in 0..DEPTH {
        z.push(compress(&z[k], &z[k]));
    }
    z
}

/// A sparse depth-20 tree of commitments appended left to right, as the pool contract keeps it.
pub struct Tree {
    pub leaves: Vec<Digest>,
    zeros: Vec<Digest>,
}

impl Default for Tree {
    fn default() -> Self {
        Self::new()
    }
}

impl Tree {
    pub fn new() -> Self {
        Self { leaves: Vec::new(), zeros: empty_roots() }
    }

    pub fn append(&mut self, leaf: Digest) -> usize {
        assert!(self.leaves.len() < 1 << DEPTH, "tree full");
        self.leaves.push(leaf);
        self.leaves.len() - 1
    }

    fn level(&self, k: usize) -> Vec<Digest> {
        let mut nodes = self.leaves.clone();
        for j in 0..k {
            let mut up = Vec::new();
            for i in (0..nodes.len()).step_by(2) {
                let r = if i + 1 < nodes.len() { nodes[i + 1] } else { self.zeros[j] };
                up.push(compress(&nodes[i], &r));
            }
            nodes = up;
        }
        nodes
    }

    pub fn root(&self) -> Digest {
        self.level(DEPTH).first().copied().unwrap_or(self.zeros[DEPTH])
    }

    /// Siblings from the leaf up (one pass over the levels).
    pub fn path(&self, index: usize) -> [Digest; DEPTH] {
        let mut path = [[Val::ZERO; 8]; DEPTH];
        let mut nodes = self.leaves.clone();
        for (k, sib) in path.iter_mut().enumerate() {
            let s = (index >> k) ^ 1;
            *sib = nodes.get(s).copied().unwrap_or(self.zeros[k]);
            let mut up = Vec::with_capacity(nodes.len().div_ceil(2));
            for i in (0..nodes.len()).step_by(2) {
                let r = if i + 1 < nodes.len() { nodes[i + 1] } else { self.zeros[k] };
                up.push(compress(&nodes[i], &r));
            }
            nodes = up;
        }
        path
    }
}

// ------------------------------------------------------------------------------------------------
// The AIR

/// 128 rows, of which 26 do work: the hiding PCS masks the trace with a polynomial of as many rows,
/// and its budget needs 2 (8 * 2 opening points + 19 queries) = 70 of them (hiding_pcs.rs).
pub const LOG_ROWS: usize = 7;
pub const ROWS: usize = 1 << LOG_ROWS;

// Row roles. Every row holds one permutation.
pub const R_VALUE: usize = 0; // P(asset || amount || 0)
pub const R_TAG: usize = 1; // P(rho || sk)
pub const R_LEAF: usize = 2; // P(value || tag) = the spent commitment
pub const R_NF: usize = 3; // P(rho || commitment)
pub const R_PATH: usize = 4; // rows 4..=23: the Merkle path, level 0 first
pub const R_ROOT: usize = R_PATH + DEPTH - 1; // 23
pub const R_CVALUE: usize = R_ROOT + 1; // 24: P(asset || change || 0)
pub const R_CHANGE: usize = R_CVALUE + 1; // 25: P(change value || change tag)

// Main trace columns after the permutation block.
pub const C_W: usize = P2_COLS; // 8: carried digest (value, rho, commitment) or Merkle sibling
pub const C_BIT: usize = C_W + 8; // 1: Merkle direction bit
pub const C_AMT: usize = C_BIT + 1; // 5: spent amount limbs, constant down the trace
pub const C_CARRY: usize = C_AMT + AMOUNT_LIMBS; // 4: balance carries
pub const C_ACC: usize = C_CARRY + AMOUNT_LIMBS - 1; // 5: change range-check accumulators
pub const C_BITS: usize = C_ACC + AMOUNT_LIMBS; // 5: change range-check bits
pub const TRACE_WIDTH: usize = C_BITS + AMOUNT_LIMBS;

// Public values.
pub const PV_ASSET: usize = 0; // 6
pub const PV_V: usize = PV_ASSET + ASSET_LIMBS; // 5
pub const PV_FEE: usize = PV_V + AMOUNT_LIMBS; // 5
pub const PV_NF: usize = PV_FEE + AMOUNT_LIMBS; // 8
pub const PV_ROOT: usize = PV_NF + 8; // 8
pub const PV_CHANGE: usize = PV_ROOT + 8; // 8
pub const PV_BIND: usize = PV_CHANGE + 8; // 8
pub const NUM_PUBLIC: usize = PV_BIND + 8;

// Periodic selectors, one period of ROWS values each.
pub const PER_VALUE: usize = 0;
pub const PER_TAG: usize = 1;
pub const PER_LEAF: usize = 2;
pub const PER_NF: usize = 3; // also the row whose next row is Merkle level 0 (node: the carried commitment)
pub const PER_PATH: usize = 4; // rows whose next row is Merkle level 1..19 (node: this row's output)
pub const PER_ROOT: usize = 5;
pub const PER_CVALUE: usize = 6;
pub const PER_CHANGE: usize = 7;
pub const NUM_PERIODIC: usize = 8;

/// The rows on which each periodic selector is one.
pub fn periodic_rows() -> [Vec<usize>; NUM_PERIODIC] {
    [
        vec![R_VALUE],
        vec![R_TAG],
        vec![R_LEAF],
        vec![R_NF],
        (R_PATH..R_ROOT).collect(),
        vec![R_ROOT],
        vec![R_CVALUE],
        vec![R_CHANGE],
    ]
}

#[derive(Clone)]
pub struct SpendAir {
    periodic: Vec<Vec<Val>>,
}

impl Default for SpendAir {
    fn default() -> Self {
        Self::new()
    }
}

impl SpendAir {
    pub fn new() -> Self {
        let periodic = periodic_rows()
            .iter()
            .map(|rows| (0..ROWS).map(|r| if rows.contains(&r) { Val::ONE } else { Val::ZERO }).collect())
            .collect();
        Self { periodic }
    }
}

impl BaseAir<Val> for SpendAir {
    fn width(&self) -> usize {
        TRACE_WIDTH
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC
    }

    fn num_periodic_columns(&self) -> usize {
        NUM_PERIODIC
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(&self.periodic)
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

/// The permutation's constraints on one row, exactly as Plonky3's Poseidon2Air emits them (S-box
/// x^3 without registers, 4 + 20 + 4 rounds).
fn eval_permutation<AB: AirBuilder<F = Val>>(builder: &mut AB, row: &[AB::Var]) {
    let mut state: [AB::Expr; WIDTH] = core::array::from_fn(|i| row[i].into());
    LinearLayers::external_linear_layer(&mut state);
    let mut col = WIDTH;
    let full_round = |builder: &mut AB, state: &mut [AB::Expr; WIDTH], rc: &[Val; WIDTH], col: usize| {
        for (s, r) in state.iter_mut().zip(rc.iter()) {
            *s = (s.clone() + *r).cube();
        }
        LinearLayers::external_linear_layer(state);
        for (i, s) in state.iter_mut().enumerate() {
            builder.assert_eq(s.clone(), row[col + i]);
            *s = row[col + i].into();
        }
    };
    for rc in KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL.iter() {
        full_round(builder, &mut state, rc, col);
        col += WIDTH;
    }
    for rc in KOALABEAR_POSEIDON2_RC_16_INTERNAL.iter() {
        state[0] = (state[0].clone() + *rc).cube();
        builder.assert_eq(state[0].clone(), row[col]);
        state[0] = row[col].into();
        col += 1;
        LinearLayers::internal_linear_layer(&mut state);
    }
    for rc in KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL.iter() {
        full_round(builder, &mut state, rc, col);
        col += WIDTH;
    }
    debug_assert_eq!(col, P2_COLS);
}

impl<AB: AirBuilder<F = Val>> Air<AB> for SpendAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local: Vec<AB::Var> = main.current_slice().to_vec();
        let next: Vec<AB::Var> = main.next_slice().to_vec();
        let pv: Vec<AB::Expr> = builder.public_values().iter().map(|&x| x.into()).collect();
        let per: Vec<AB::Expr> = builder.periodic_values().iter().map(|&x| x.into()).collect();
        let first = builder.is_first_row();
        let transition = builder.is_transition();
        let e = |v: AB::Var| -> AB::Expr { v.into() };
        let out = |j: usize| -> AB::Expr { local[output_col(j)].into() };
        let two26 = Val::from_u32(1 << AMOUNT_LIMB_BITS);

        // 1. The permutation of this row.
        eval_permutation(builder, &local);

        // 2. Unconditional: booleans and carry ranges.
        builder.assert_bool(local[C_BIT]);
        for i in 0..AMOUNT_LIMBS {
            builder.assert_bool(local[C_BITS + i]);
        }
        for i in 0..AMOUNT_LIMBS - 1 {
            let k = e(local[C_CARRY + i]);
            builder.assert_zero(k.clone() * (k.clone() - Val::ONE) * (k - Val::TWO));
        }

        // 3. The spent amount is constant; the change bits accumulate most significant first.
        for i in 0..AMOUNT_LIMBS {
            builder.assert_zero(transition.clone() * (e(next[C_AMT + i]) - e(local[C_AMT + i])));
        }
        for i in 0..AMOUNT_LIMBS {
            builder.assert_zero(first.clone() * (e(local[C_ACC + i]) - e(local[C_BITS + i])));
            builder.assert_zero(
                transition.clone() * (e(next[C_ACC + i]) - e(local[C_ACC + i]) * Val::TWO - e(next[C_BITS + i])),
            );
        }

        // 4. Value row: (asset, amount, 0); the value carries on.
        let s = per[PER_VALUE].clone();
        for j in 0..ASSET_LIMBS {
            builder.assert_zero(s.clone() * (e(local[j]) - pv[PV_ASSET + j].clone()));
        }
        for i in 0..AMOUNT_LIMBS {
            builder.assert_zero(s.clone() * (e(local[ASSET_LIMBS + i]) - e(local[C_AMT + i])));
        }
        for j in ASSET_LIMBS + AMOUNT_LIMBS..WIDTH {
            builder.assert_zero(s.clone() * e(local[j]));
        }
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[C_W + j]) - out(j)));
        }

        // 5. Tag row (rho || sk): the next row hashes (value || tag); rho carries on.
        let s = per[PER_TAG].clone();
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[j]) - e(local[C_W + j])));
        }
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[8 + j]) - out(j)));
        }
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[C_W + j]) - e(local[j])));
        }

        // 6. Leaf row: the next row hashes (rho || commitment); the commitment carries on.
        let s = per[PER_LEAF].clone();
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[j]) - e(local[C_W + j])));
        }
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[8 + j]) - out(j)));
        }
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[C_W + j]) - out(j)));
        }

        // 7. Nullifier row: public nullifier; the next row is Merkle level 0 over the carried
        //    commitment: (node || sibling) or (sibling || node), sibling and bit on the next row.
        let s = per[PER_NF].clone();
        for j in 0..8 {
            builder.assert_zero(s.clone() * (out(j) - pv[PV_NF + j].clone()));
        }
        let bit = e(next[C_BIT]);
        for j in 0..8 {
            let node = e(local[C_W + j]);
            let left = node.clone() + bit.clone() * (e(next[C_W + j]) - node);
            builder.assert_zero(s.clone() * (e(next[j]) - left));
        }
        for j in 0..8 {
            let node = e(local[C_W + j]);
            let right = e(next[C_W + j]) + bit.clone() * (node - e(next[C_W + j]));
            builder.assert_zero(s.clone() * (e(next[8 + j]) - right));
        }

        // 8. Merkle levels 1..19: the node is this row's output.
        let s = per[PER_PATH].clone();
        for j in 0..8 {
            let left = out(j) + bit.clone() * (e(next[C_W + j]) - out(j));
            builder.assert_zero(s.clone() * (e(next[j]) - left));
        }
        for j in 0..8 {
            let right = e(next[C_W + j]) + bit.clone() * (out(j) - e(next[C_W + j]));
            builder.assert_zero(s.clone() * (e(next[8 + j]) - right));
        }

        // 9. Root.
        let s = per[PER_ROOT].clone();
        for j in 0..8 {
            builder.assert_zero(s.clone() * (out(j) - pv[PV_ROOT + j].clone()));
        }

        // 10. Change value row: (asset, change, 0), the change limbs range checked, the balance
        //    v + fee + change = amount limb by limb with carries, and the next row hashes the change
        //    value with the change tag the prover picks.
        let s = per[PER_CVALUE].clone();
        for j in 0..ASSET_LIMBS {
            builder.assert_zero(s.clone() * (e(local[j]) - pv[PV_ASSET + j].clone()));
        }
        for j in ASSET_LIMBS + AMOUNT_LIMBS..WIDTH {
            builder.assert_zero(s.clone() * e(local[j]));
        }
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[j]) - out(j)));
        }
        for i in 0..AMOUNT_LIMBS {
            builder.assert_zero(s.clone() * (e(next[C_ACC + i]) - e(local[ASSET_LIMBS + i])));
        }
        for i in 0..AMOUNT_LIMBS {
            let carry_in = if i == 0 { AB::Expr::ZERO } else { e(local[C_CARRY + i - 1]) };
            let carry_out = if i == AMOUNT_LIMBS - 1 { AB::Expr::ZERO } else { e(local[C_CARRY + i]) };
            let lhs = pv[PV_V + i].clone() + pv[PV_FEE + i].clone() + e(local[ASSET_LIMBS + i]) + carry_in;
            let rhs = e(local[C_AMT + i]) + carry_out * two26;
            builder.assert_zero(s.clone() * (lhs - rhs));
        }

        // 11. Change commitment.
        let s = per[PER_CHANGE].clone();
        for j in 0..8 {
            builder.assert_zero(s.clone() * (out(j) - pv[PV_CHANGE + j].clone()));
        }
    }
}

// ------------------------------------------------------------------------------------------------
// Witness and trace

/// Everything the prover knows about one spend.
#[derive(Clone, Debug)]
pub struct Spend {
    pub sk: Digest,
    pub rho: Digest,
    pub asset: [u8; 20],
    pub amount: u128,
    pub index: usize,
    pub path: [Digest; DEPTH],
    pub v: u128,
    pub fee: u128,
    pub change_tag: Digest,
    pub bind: [Val; 8],
}

#[derive(Debug)]
pub enum SpendError {
    Overdrawn,
    IndexTooLarge,
}

impl Spend {
    pub fn change(&self) -> Result<u128, SpendError> {
        let out = self.v.checked_add(self.fee).ok_or(SpendError::Overdrawn)?;
        self.amount.checked_sub(out).ok_or(SpendError::Overdrawn)
    }

    pub fn commitment(&self) -> Digest {
        let a = asset_limbs(&self.asset);
        commitment(&value_digest(&a, &amount_limbs(self.amount)), &tag(&self.sk, &self.rho))
    }

    pub fn root(&self) -> Digest {
        let mut node = self.commitment();
        for (k, sib) in self.path.iter().enumerate() {
            node = if (self.index >> k) & 1 == 0 { compress(&node, sib) } else { compress(sib, &node) };
        }
        node
    }

    pub fn change_commitment(&self) -> Result<Digest, SpendError> {
        let a = asset_limbs(&self.asset);
        Ok(commitment(&value_digest(&a, &amount_limbs(self.change()?)), &self.change_tag))
    }

    pub fn public_values(&self) -> Result<Vec<Val>, SpendError> {
        let mut pv = Vec::with_capacity(NUM_PUBLIC);
        pv.extend_from_slice(&asset_limbs(&self.asset));
        pv.extend_from_slice(&amount_limbs(self.v));
        pv.extend_from_slice(&amount_limbs(self.fee));
        pv.extend_from_slice(&nullifier(&self.rho, &self.commitment()));
        pv.extend_from_slice(&self.root());
        pv.extend_from_slice(&self.change_commitment()?);
        pv.extend_from_slice(&self.bind);
        debug_assert_eq!(pv.len(), NUM_PUBLIC);
        Ok(pv)
    }

    pub fn trace(&self) -> Result<RowMajorMatrix<Val>, SpendError> {
        let change = self.change()?;
        if self.index >> DEPTH != 0 {
            return Err(SpendError::IndexTooLarge);
        }
        let asset = asset_limbs(&self.asset);
        let amt = amount_limbs(self.amount);
        let chg = amount_limbs(change);
        let tg = tag(&self.sk, &self.rho);
        let value = value_digest(&asset, &amt);
        let cvalue = value_digest(&asset, &chg);

        let cat = |l: &Digest, r: &Digest| -> [Val; WIDTH] {
            let mut s = [Val::ZERO; WIDTH];
            s[..8].copy_from_slice(l);
            s[8..].copy_from_slice(r);
            s
        };
        let mut inputs = vec![[Val::ZERO; WIDTH]; ROWS];
        let mut w = vec![[Val::ZERO; 8]; ROWS];
        let mut bits = vec![Val::ZERO; ROWS];
        let cm = commitment(&value, &tg);
        inputs[R_VALUE] = value_input(&asset, &amt);
        w[R_TAG] = value;
        inputs[R_TAG] = cat(&self.rho, &self.sk);
        w[R_LEAF] = self.rho;
        inputs[R_LEAF] = cat(&value, &tg);
        w[R_NF] = cm;
        inputs[R_NF] = cat(&self.rho, &cm);
        let mut node = cm;
        for k in 0..DEPTH {
            let r = R_PATH + k;
            let b = (self.index >> k) & 1;
            w[r] = self.path[k];
            bits[r] = Val::from_u32(b as u32);
            inputs[r] = if b == 0 { cat(&node, &self.path[k]) } else { cat(&self.path[k], &node) };
            node = permute(inputs[r])[..8].try_into().unwrap();
        }
        inputs[R_CVALUE] = value_input(&asset, &chg);
        inputs[R_CHANGE] = cat(&cvalue, &self.change_tag);

        // Balance carries: v_i + fee_i + change_i + k_(i-1) = amount_i + k_i 2^26.
        let vl = amount_limbs(self.v);
        let fl = amount_limbs(self.fee);
        let mut carries = [Val::ZERO; AMOUNT_LIMBS - 1];
        let mut k: u64 = 0;
        for i in 0..AMOUNT_LIMBS {
            let sum = vl[i].as_canonical_u32() as u64 + fl[i].as_canonical_u32() as u64 + chg[i].as_canonical_u32() as u64 + k;
            let a = amt[i].as_canonical_u32() as u64;
            assert!(sum >= a && (sum - a) % (1 << AMOUNT_LIMB_BITS) == 0, "balance limbs");
            k = (sum - a) >> AMOUNT_LIMB_BITS;
            if i < AMOUNT_LIMBS - 1 {
                carries[i] = Val::from_u32(k as u32);
            } else {
                assert_eq!(k, 0, "no final carry");
            }
        }

        let mut values = Vec::with_capacity(ROWS * TRACE_WIDTH);
        let mut acc = [Val::ZERO; AMOUNT_LIMBS];
        for r in 0..ROWS {
            let mut row = permutation_row(inputs[r]);
            row.extend_from_slice(&w[r]);
            row.push(bits[r]);
            row.extend_from_slice(&amt);
            row.extend_from_slice(&carries);
            // Bit r of the 26-bit change limb, most significant first, for rows 0..26.
            let mut b = [Val::ZERO; AMOUNT_LIMBS];
            for i in 0..AMOUNT_LIMBS {
                if r < AMOUNT_LIMB_BITS {
                    let bit = (chg[i].as_canonical_u32() >> (AMOUNT_LIMB_BITS - 1 - r)) & 1;
                    b[i] = Val::from_u32(bit);
                }
                acc[i] = if r == 0 { b[i] } else { acc[i] * Val::TWO + b[i] };
            }
            row.extend_from_slice(&acc);
            row.extend_from_slice(&b);
            debug_assert_eq!(row.len(), TRACE_WIDTH);
            values.extend_from_slice(&row);
        }
        Ok(RowMajorMatrix::new(values, TRACE_WIDTH))
    }
}

pub fn prove(spend: &Spend, seed: [u8; 32]) -> Result<(Proof<Config>, Vec<Val>), SpendError> {
    let air = SpendAir::new();
    let trace = spend.trace()?;
    let pv = spend.public_values()?;
    let proof = p3_uni_stark::prove(&config(seed), &air, trace, &pv).expect("prove");
    Ok((proof, pv))
}

pub fn verify(proof: &Proof<Config>, pv: &[Val]) -> bool {
    p3_uni_stark::verify(&config([0; 32]), &SpendAir::new(), proof, pv).is_ok()
}

/// The 8 binding values of a spend from a keccak-256 hash of its call, as the pool derives them
/// (Notes.bindOf): element i is bits [32 i, 32 i + 30) of the hash read as a big-endian integer.
pub fn bind_from_hash(h: &[u8; 32]) -> [Val; 8] {
    core::array::from_fn(|i| {
        let lane = u32::from_be_bytes([h[28 - 4 * i], h[29 - 4 * i], h[30 - 4 * i], h[31 - 4 * i]]);
        Val::from_u32(lane & 0x3fff_ffff)
    })
}

/// A digest as the pool packs it in a bytes32 (element i in bits [32 i, 32 i + 32)), big-endian bytes.
pub fn pack_digest(d: &Digest) -> [u8; 32] {
    let mut b = [0u8; 32];
    for (i, v) in d.iter().enumerate() {
        b[28 - 4 * i..32 - 4 * i].copy_from_slice(&v.as_canonical_u32().to_be_bytes());
    }
    b
}

/// A uniformly random digest (8 field elements) from the operating system's random source (`os_seed`'s), for a
/// secret key or a note nonce.
pub fn os_digest() -> std::io::Result<Digest> {
    let mut d = [Val::ZERO; 8];
    for x in d.iter_mut() {
        loop {
            let mut b = [0u8; 4];
            getrandom::fill(&mut b).map_err(std::io::Error::other)?;
            let v = u32::from_le_bytes(b) & 0x7fff_ffff;
            if v < Val::ORDER_U32 {
                *x = Val::from_u32(v);
                break;
            }
        }
    }
    Ok(d)
}

/// Decimal or 0x-hexadecimal text to a field element below P.
pub fn parse_val(s: &str) -> Option<Val> {
    let v = if let Some(h) = s.strip_prefix("0x") { u64::from_str_radix(h, 16).ok()? } else { s.parse::<u64>().ok()? };
    (v < Val::ORDER_U32 as u64).then(|| Val::from_u32(v as u32))
}
