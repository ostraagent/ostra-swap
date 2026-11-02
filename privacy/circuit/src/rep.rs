//! The Ostra reputation circuit (stage 1).
//!
//! An agent proves that the OstraPad provider record of one of its Ostra vaults meets public thresholds, without
//! showing which vault. OstraReputation (ostra-swap/src/OstraReputation.sol) reads the record from OstraPad's own state
//! when the vault authorizes a snapshot, and appends one leaf per vault and epoch to a depth-20 tree:
//!
//! ```text
//!     idc       = P(sk || [D_IDC, 0, 0, 0, 0, 0, 0, 0])[0..8]      the vault's identity commitment
//!     record    = P([D_REC, completed, clients, vol0..vol4, rejected, expired, tier, firstDay, epoch, 0, 0, 0])[0..8]
//!     leaf      = P(record || idc)[0..8]
//!     pseudonym = P(sk || scope)[0..8],  scope = [D_SCOPE, s1..s7]  one per vault, scope and idc
//! ```
//!
//! A vault has one leaf, so one idc, per epoch; a rotated idc (OstraReputation: at most once every 4 epochs) gives the
//! same vault a new pseudonym in the same scope from the epoch it takes effect. A verifier that wants one claim per
//! vault for a period puts the epoch (or a period id) into its scope.
//!
//! P is the width-16 Poseidon2 permutation of the spend circuit (`P(l || r)[0..8]` its truncated compression; the
//! record is one full permutation of a 16-element state, first 8 outputs). sk is a reputation-only secret (never a
//! note's sk). A proof shows, for public root, pseudonym, scope, bind, epoch and thresholds: a leaf under `root` holds
//! a record of `epoch` and the idc of the same sk the pseudonym comes from, and the record meets every threshold:
//!
//! ```text
//!     completed >= minCompleted, clients >= minClients, volume >= minVolume (five 26-bit limbs),
//!     1000 (rejected + expired) < maxFailPermille (completed + rejected + expired)   (strict),
//!     tier >= minTier, firstDay <= maxFirstDay.
//! ```
//!
//! Every comparison is a difference range checked bit by bit (an accumulator column, most significant bit first,
//! read on the row where its last bit lands), and every record field used in a comparison is range checked to the
//! width the contract writes. The verifier (the contract, or an off-chain one through `check_thresholds`) supplies
//! scope, epoch, thresholds and bind itself and keeps the thresholds in the ranges that make each comparison exact
//! (see `check_thresholds`). bind (from a keccak-256 hash, as Notes.bindOf) only enters the Fiat-Shamir transcript.

use std::borrow::Cow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::CryptographicHasher;
use p3_uni_stark::Proof;

use crate::{
    AMOUNT_LIMB_BITS, AMOUNT_LIMBS, Config, DEPTH, Digest, P2_COLS, ROWS, Val, WIDTH, amount_limbs, compress, config,
    eval_permutation, output_col, permutation_row, permute,
};

// ------------------------------------------------------------------------------------------------
// Domain constants (distinct, nonzero, above 2^16 so no record field can take their place, below 2^30)

pub const D_IDC: u32 = 0x2049_4443; // " IDC"
pub const D_SCOPE: u32 = 0x2053_4350; // " SCP"
pub const D_REC: u32 = 0x2052_4543; // " REC"

// ------------------------------------------------------------------------------------------------
// Field widths

pub const COUNT_BITS: usize = 19; // completed, clients (the contract clamps at 2^19 - 1)
pub const FAIL_BITS: usize = 16; // rejected, expired (the contract refuses 2^16 and more)
pub const TIER_BITS: usize = 2;
pub const DAY_BITS: usize = 29; // firstDay
pub const DIFF_BITS: usize = 30; // the differences of the comparisons
/// The largest maxFailPermille.
pub const PERMILLE: u32 = 1000;
/// Bound of minCompleted, minClients and maxFirstDay (see check_thresholds).
pub const THRESHOLD_BOUND: u32 = 1 << 29;
pub const MAX_TIER: u32 = 3;

// ------------------------------------------------------------------------------------------------
// Rows (each holds one permutation)

pub const R_IDC: usize = 0; // P(sk || D_IDC vector)
pub const R_REC: usize = 1; // the record permutation
pub const R_LEAF: usize = 2; // P(record || idc)
pub const R_PATH: usize = 3; // rows 3..=22: Merkle levels 0..19
pub const R_ROOT: usize = R_PATH + DEPTH - 1; // 22
pub const R_PSEUDO: usize = R_ROOT + 1; // 23: P(sk || scope)

// Record state positions (row R_REC's permutation input).
pub const S_DOMAIN: usize = 0;
pub const S_COMPLETED: usize = 1;
pub const S_CLIENTS: usize = 2;
pub const S_VOL: usize = 3; // 5 limbs
pub const S_REJECTED: usize = 8;
pub const S_EXPIRED: usize = 9;
pub const S_TIER: usize = 10;
pub const S_FIRST_DAY: usize = 11;
pub const S_EPOCH: usize = 12;
pub const S_PAD: usize = 13; // 13..16 zero

// Record fields carried down the trace (the comparisons read them on their own rows).
pub const F_COMPLETED: usize = 0;
pub const F_CLIENTS: usize = 1;
pub const F_VOL: usize = 2; // 5
pub const F_REJECTED: usize = 7;
pub const F_EXPIRED: usize = 8;
pub const F_TIER: usize = 9;
pub const F_FIRST_DAY: usize = 10;
pub const NUM_FIELDS: usize = 11;
/// The record state position of each carried field.
pub const FIELD_POS: [usize; NUM_FIELDS] =
    [S_COMPLETED, S_CLIENTS, S_VOL, S_VOL + 1, S_VOL + 2, S_VOL + 3, S_VOL + 4, S_REJECTED, S_EXPIRED, S_TIER, S_FIRST_DAY];

// Range-check slots: each an accumulator column and a bit column.
pub const K_COMPLETED: usize = 0;
pub const K_CLIENTS: usize = 1;
pub const K_VOL: usize = 2; // 5
pub const K_REJECTED: usize = 7;
pub const K_EXPIRED: usize = 8;
pub const K_TIER: usize = 9;
pub const K_FIRST_DAY: usize = 10;
pub const K_D_COMPLETED: usize = 11; // completed - minCompleted
pub const K_D_CLIENTS: usize = 12; // clients - minClients
pub const K_D_VOL: usize = 13; // 5: the borrow chain's difference limbs
pub const K_D_FAIL: usize = 18; // maxFailPermille T - 1000 f - 1
pub const K_D_TIER: usize = 19; // tier - minTier
pub const K_D_DAY: usize = 20; // maxFirstDay - firstDay
pub const NUM_RANGE: usize = 21;

/// The width of each range-check slot.
pub const RANGE_BITS: [usize; NUM_RANGE] = [
    COUNT_BITS,
    COUNT_BITS,
    AMOUNT_LIMB_BITS,
    AMOUNT_LIMB_BITS,
    AMOUNT_LIMB_BITS,
    AMOUNT_LIMB_BITS,
    AMOUNT_LIMB_BITS,
    FAIL_BITS,
    FAIL_BITS,
    TIER_BITS,
    DAY_BITS,
    DIFF_BITS,
    DIFF_BITS,
    AMOUNT_LIMB_BITS,
    AMOUNT_LIMB_BITS,
    AMOUNT_LIMB_BITS,
    AMOUNT_LIMB_BITS,
    AMOUNT_LIMB_BITS,
    DIFF_BITS,
    TIER_BITS,
    DIFF_BITS,
];

// Main trace columns after the permutation block.
pub const C_SK: usize = P2_COLS; // 8: sk, constant down the trace
pub const C_W: usize = C_SK + 8; // 8: the idc carried into the record row, or a Merkle sibling
pub const C_BIT: usize = C_W + 8; // 1: Merkle direction bit
pub const C_FIELD: usize = C_BIT + 1; // 11: record fields, constant down the trace
pub const C_BORROW: usize = C_FIELD + NUM_FIELDS; // 4: the volume comparison's borrows
pub const C_ACC: usize = C_BORROW + AMOUNT_LIMBS - 1; // 21: range-check accumulators
pub const C_RBIT: usize = C_ACC + NUM_RANGE; // 21: range-check bits
pub const REP_WIDTH: usize = C_RBIT + NUM_RANGE;

// Public values.
pub const PV_ROOT: usize = 0; // 8
pub const PV_PSEUDO: usize = 8; // 8
pub const PV_SCOPE: usize = 16; // 8
pub const PV_BIND: usize = 24; // 8
pub const PV_EPOCH: usize = 32;
pub const PV_MIN_COMPLETED: usize = 33;
pub const PV_MIN_CLIENTS: usize = 34;
pub const PV_MIN_VOL: usize = 35; // 5
pub const PV_MAX_FAIL: usize = 40;
pub const PV_MIN_TIER: usize = 41;
pub const PV_MAX_FIRST_DAY: usize = 42;
pub const REP_PUBLIC: usize = 43;

// Periodic selectors, one period of ROWS values each.
pub const PER_IDC: usize = 0;
pub const PER_REC: usize = 1; // also where the 2-bit ranges end
pub const PER_PATH: usize = 2; // rows whose next row is Merkle level 0..19 (node: this row's output)
pub const PER_ROOT: usize = 3;
pub const PER_PSEUDO: usize = 4;
pub const PER_T16: usize = 5; // rows where a range of 16, 19, 26, 29 or 30 bits ends
pub const PER_T19: usize = 6;
pub const PER_T26: usize = 7;
pub const PER_T29: usize = 8;
pub const PER_T30: usize = 9;
pub const REP_PERIODIC: usize = 10;

/// The rows on which each periodic selector is one. A range of w bits ends on row w - 1.
pub fn rep_periodic_rows() -> [Vec<usize>; REP_PERIODIC] {
    [
        vec![R_IDC],
        vec![R_REC],
        (R_LEAF..R_ROOT).collect(),
        vec![R_ROOT],
        vec![R_PSEUDO],
        vec![FAIL_BITS - 1],
        vec![COUNT_BITS - 1],
        vec![AMOUNT_LIMB_BITS - 1],
        vec![DAY_BITS - 1],
        vec![DIFF_BITS - 1],
    ]
}

#[derive(Clone)]
pub struct RepAir {
    periodic: Vec<Vec<Val>>,
}

impl Default for RepAir {
    fn default() -> Self {
        Self::new()
    }
}

impl RepAir {
    pub fn new() -> Self {
        assert_eq!(R_REC, TIER_BITS - 1, "the 2-bit ranges end on the record row");
        let periodic = rep_periodic_rows()
            .iter()
            .map(|rows| (0..ROWS).map(|r| if rows.contains(&r) { Val::ONE } else { Val::ZERO }).collect())
            .collect();
        Self { periodic }
    }
}

impl BaseAir<Val> for RepAir {
    fn width(&self) -> usize {
        REP_WIDTH
    }

    fn num_public_values(&self) -> usize {
        REP_PUBLIC
    }

    fn num_periodic_columns(&self) -> usize {
        REP_PERIODIC
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val>]> {
        Cow::Borrowed(&self.periodic)
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder<F = Val>> Air<AB> for RepAir {
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
        let field = |f: usize| -> AB::Expr { local[C_FIELD + f].into() };
        let acc = |k: usize| -> AB::Expr { local[C_ACC + k].into() };
        let two26 = Val::from_u32(1 << AMOUNT_LIMB_BITS);

        // 1. The permutation of this row.
        eval_permutation(builder, &local);

        // 2. Booleans: the Merkle bit, the borrows, the range-check bits.
        builder.assert_bool(local[C_BIT]);
        for i in 0..AMOUNT_LIMBS - 1 {
            builder.assert_bool(local[C_BORROW + i]);
        }
        for k in 0..NUM_RANGE {
            builder.assert_bool(local[C_RBIT + k]);
        }

        // 3. sk and the record fields are constant down the trace.
        for j in 0..8 {
            builder.assert_zero(transition.clone() * (e(next[C_SK + j]) - e(local[C_SK + j])));
        }
        for f in 0..NUM_FIELDS {
            builder.assert_zero(transition.clone() * (e(next[C_FIELD + f]) - field(f)));
        }

        // 4. Range-check accumulators: most significant bit first from row 0.
        for k in 0..NUM_RANGE {
            builder.assert_zero(first.clone() * (acc(k) - e(local[C_RBIT + k])));
            builder.assert_zero(
                transition.clone() * (e(next[C_ACC + k]) - acc(k) * Val::TWO - e(next[C_RBIT + k])),
            );
        }

        // 5. Group 1, idc row: P(sk || D_IDC, 0..0); the idc carries into the record row.
        let s = per[PER_IDC].clone();
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(local[j]) - e(local[C_SK + j])));
        }
        builder.assert_zero(s.clone() * (e(local[8]) - Val::from_u32(D_IDC)));
        for j in 9..WIDTH {
            builder.assert_zero(s.clone() * e(local[j]));
        }
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[C_W + j]) - out(j)));
        }

        // 6. Record row. Group 2: domain, zero pad, the hashed fields are the carried ones. Group 5: its epoch is the
        //    public epoch. Group 3: the next row hashes (record || idc). The 2-bit ranges end here (groups 9, 11).
        let s = per[PER_REC].clone();
        builder.assert_zero(s.clone() * (e(local[S_DOMAIN]) - Val::from_u32(D_REC)));
        for j in S_PAD..WIDTH {
            builder.assert_zero(s.clone() * e(local[j]));
        }
        for (f, &pos) in FIELD_POS.iter().enumerate() {
            builder.assert_zero(s.clone() * (e(local[pos]) - field(f)));
        }
        builder.assert_zero(s.clone() * (e(local[S_EPOCH]) - pv[PV_EPOCH].clone()));
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[j]) - out(j)));
        }
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(next[8 + j]) - e(local[C_W + j])));
        }
        builder.assert_zero(s.clone() * (acc(K_TIER) - field(F_TIER)));
        builder.assert_zero(s.clone() * (acc(K_D_TIER) - (field(F_TIER) - pv[PV_MIN_TIER].clone())));

        // 7. Group 3, Merkle levels 0..19 (the node is this row's output: the leaf, then each level's), and the root.
        let s = per[PER_PATH].clone();
        let bit = e(next[C_BIT]);
        for j in 0..8 {
            let left = out(j) + bit.clone() * (e(next[C_W + j]) - out(j));
            builder.assert_zero(s.clone() * (e(next[j]) - left));
        }
        for j in 0..8 {
            let right = e(next[C_W + j]) + bit.clone() * (out(j) - e(next[C_W + j]));
            builder.assert_zero(s.clone() * (e(next[8 + j]) - right));
        }
        let s = per[PER_ROOT].clone();
        for j in 0..8 {
            builder.assert_zero(s.clone() * (out(j) - pv[PV_ROOT + j].clone()));
        }

        // 8. Group 4, pseudonym row: P(sk || scope), scope[0] = D_SCOPE.
        let s = per[PER_PSEUDO].clone();
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(local[j]) - e(local[C_SK + j])));
        }
        builder.assert_zero(s.clone() * (e(local[8]) - Val::from_u32(D_SCOPE)));
        for j in 0..8 {
            builder.assert_zero(s.clone() * (e(local[8 + j]) - pv[PV_SCOPE + j].clone()));
        }
        for j in 0..8 {
            builder.assert_zero(s.clone() * (out(j) - pv[PV_PSEUDO + j].clone()));
        }

        // 9. Where the longer ranges end. Group 11: rejected and expired (16 bits), completed and clients (19),
        //    the volume limbs (26), firstDay (29). Group 7: volume - minVolume limb by limb with borrows,
        //    d_i = vol_i - min_i - b_(i-1) + 2^26 b_i, b_(-1) = b_4 = 0, each d_i 26 bits. Groups 6, 8, 10 (30 bits).
        let s = per[PER_T16].clone();
        builder.assert_zero(s.clone() * (acc(K_REJECTED) - field(F_REJECTED)));
        builder.assert_zero(s.clone() * (acc(K_EXPIRED) - field(F_EXPIRED)));
        let s = per[PER_T19].clone();
        builder.assert_zero(s.clone() * (acc(K_COMPLETED) - field(F_COMPLETED)));
        builder.assert_zero(s.clone() * (acc(K_CLIENTS) - field(F_CLIENTS)));
        let s = per[PER_T26].clone();
        for i in 0..AMOUNT_LIMBS {
            builder.assert_zero(s.clone() * (acc(K_VOL + i) - field(F_VOL + i)));
        }
        for i in 0..AMOUNT_LIMBS {
            let borrow_in = if i == 0 { AB::Expr::ZERO } else { e(local[C_BORROW + i - 1]) };
            let borrow_out = if i == AMOUNT_LIMBS - 1 { AB::Expr::ZERO } else { e(local[C_BORROW + i]) * two26 };
            let d = field(F_VOL + i) - pv[PV_MIN_VOL + i].clone() - borrow_in + borrow_out;
            builder.assert_zero(s.clone() * (acc(K_D_VOL + i) - d));
        }
        let s = per[PER_T29].clone();
        builder.assert_zero(s.clone() * (acc(K_FIRST_DAY) - field(F_FIRST_DAY)));
        let s = per[PER_T30].clone();
        builder.assert_zero(s.clone() * (acc(K_D_COMPLETED) - (field(F_COMPLETED) - pv[PV_MIN_COMPLETED].clone())));
        builder.assert_zero(s.clone() * (acc(K_D_CLIENTS) - (field(F_CLIENTS) - pv[PV_MIN_CLIENTS].clone())));
        let fails = field(F_REJECTED) + field(F_EXPIRED);
        let total = field(F_COMPLETED) + fails.clone();
        let margin = pv[PV_MAX_FAIL].clone() * total - fails * Val::from_u32(PERMILLE) - Val::ONE;
        builder.assert_zero(s.clone() * (acc(K_D_FAIL) - margin));
        builder.assert_zero(s * (acc(K_D_DAY) - (pv[PV_MAX_FIRST_DAY].clone() - field(F_FIRST_DAY))));
    }
}

// ------------------------------------------------------------------------------------------------
// Hashes

/// The record, as the contract writes it (already clamped).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Record {
    pub completed: u32,
    pub clients: u32,
    pub volume: u128,
    pub rejected: u32,
    pub expired: u32,
    pub tier: u32,
    pub first_day: u32,
    pub epoch: u32,
}

/// The verifier's thresholds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Thresholds {
    pub min_completed: u32,
    pub min_clients: u32,
    pub min_volume: u128,
    pub max_fail_permille: u32,
    pub min_tier: u32,
    pub max_first_day: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RepError {
    /// A record field beyond the width the circuit range checks.
    FieldOutOfRange,
    /// A threshold outside the range where the comparison is exact.
    ThresholdOutOfRange,
    /// The record does not meet the thresholds.
    NotMet,
    IndexTooLarge,
}

fn digest_of(state: [Val; WIDTH]) -> Digest {
    permute(state)[..8].try_into().unwrap()
}

pub fn idc_input(sk: &Digest) -> [Val; WIDTH] {
    let mut s = [Val::ZERO; WIDTH];
    s[..8].copy_from_slice(sk);
    s[8] = Val::from_u32(D_IDC);
    s
}

/// The identity commitment of a reputation secret.
pub fn idc(sk: &Digest) -> Digest {
    digest_of(idc_input(sk))
}

/// The 8 scope elements of a verifier's 32-byte scope: D_SCOPE, then bits [30 (i - 1), 30 i) of keccak256(scope) read
/// as a big-endian integer, i = 1..7.
pub fn scope_elements(scope: &[u8; 32]) -> [Val; 8] {
    let h: [u8; 32] = p3_keccak::Keccak256Hash {}.hash_iter(scope.iter().copied());
    let mut out = [Val::ZERO; 8];
    out[0] = Val::from_u32(D_SCOPE);
    for (i, o) in out.iter_mut().enumerate().skip(1) {
        let mut v: u32 = 0;
        for b in 0..30 {
            let bit = 30 * (i - 1) + b;
            v |= (((h[31 - bit / 8] >> (bit % 8)) & 1) as u32) << b;
        }
        *o = Val::from_u32(v);
    }
    out
}

pub fn pseudonym(sk: &Digest, scope: &[Val; 8]) -> Digest {
    compress(sk, scope)
}

impl Record {
    /// Whether every field fits the width the circuit range checks (the contract writes no other).
    pub fn in_range(&self) -> bool {
        self.completed < 1 << COUNT_BITS
            && self.clients < 1 << COUNT_BITS
            && self.rejected < 1 << FAIL_BITS
            && self.expired < 1 << FAIL_BITS
            && self.tier < 1 << TIER_BITS
            && self.first_day < 1 << DAY_BITS
            && self.epoch < Val::ORDER_U32
    }

    pub fn input(&self) -> [Val; WIDTH] {
        let mut s = [Val::ZERO; WIDTH];
        s[S_DOMAIN] = Val::from_u32(D_REC);
        s[S_COMPLETED] = Val::from_u32(self.completed);
        s[S_CLIENTS] = Val::from_u32(self.clients);
        s[S_VOL..S_VOL + AMOUNT_LIMBS].copy_from_slice(&amount_limbs(self.volume));
        s[S_REJECTED] = Val::from_u32(self.rejected);
        s[S_EXPIRED] = Val::from_u32(self.expired);
        s[S_TIER] = Val::from_u32(self.tier);
        s[S_FIRST_DAY] = Val::from_u32(self.first_day);
        s[S_EPOCH] = Val::from_u32(self.epoch);
        s
    }

    pub fn digest(&self) -> Digest {
        digest_of(self.input())
    }

    pub fn leaf(&self, idc: &Digest) -> Digest {
        compress(&self.digest(), idc)
    }

    /// The record fields carried down the trace, in F_ order.
    pub fn fields(&self) -> [Val; NUM_FIELDS] {
        let s = self.input();
        core::array::from_fn(|f| s[FIELD_POS[f]])
    }
}

/// The thresholds a verifier may ask for: minCompleted, minClients and maxFirstDay below 2^29 (so that every
/// difference of a comparison that does not hold wraps to at least P - 2^29 > 2^30), maxFailPermille at most 1000, minTier
/// at most 3 (a volume below 2^128 is any u128).
pub fn check_thresholds(t: &Thresholds) -> Result<(), RepError> {
    if t.min_completed >= THRESHOLD_BOUND
        || t.min_clients >= THRESHOLD_BOUND
        || t.max_first_day >= THRESHOLD_BOUND
        || t.max_fail_permille > PERMILLE
        || t.min_tier > MAX_TIER
    {
        return Err(RepError::ThresholdOutOfRange);
    }
    Ok(())
}

/// The fail-ratio margin maxFailPermille (completed + f) - 1000 f - 1 over the integers, f = rejected + expired.
pub fn fail_margin(r: &Record, t: &Thresholds) -> i64 {
    let f = r.rejected as i64 + r.expired as i64;
    t.max_fail_permille as i64 * (r.completed as i64 + f) - PERMILLE as i64 * f - 1
}

/// Whether `r` meets `t` (over the integers).
pub fn meets(r: &Record, t: &Thresholds) -> bool {
    r.completed >= t.min_completed
        && r.clients >= t.min_clients
        && r.volume >= t.min_volume
        && fail_margin(r, t) >= 0
        && r.tier >= t.min_tier
        && r.first_day <= t.max_first_day
}

/// Everything the prover knows about one reputation proof.
#[derive(Clone, Debug)]
pub struct Rep {
    pub sk: Digest,
    pub record: Record,
    pub index: usize,
    pub path: [Digest; DEPTH],
    /// The scope elements (scope_elements of the verifier's scope).
    pub scope: [Val; 8],
    pub thresholds: Thresholds,
    pub bind: [Val; 8],
}

fn diff(a: u32, b: u32) -> u32 {
    a.wrapping_sub(b)
}

impl Rep {
    pub fn idc(&self) -> Digest {
        idc(&self.sk)
    }

    pub fn leaf(&self) -> Digest {
        self.record.leaf(&self.idc())
    }

    pub fn root(&self) -> Digest {
        let mut node = self.leaf();
        for (k, sib) in self.path.iter().enumerate() {
            node = if (self.index >> k) & 1 == 0 { compress(&node, sib) } else { compress(sib, &node) };
        }
        node
    }

    pub fn pseudonym(&self) -> Digest {
        pseudonym(&self.sk, &self.scope)
    }

    pub fn check(&self) -> Result<(), RepError> {
        if !self.record.in_range() {
            return Err(RepError::FieldOutOfRange);
        }
        check_thresholds(&self.thresholds)?;
        if !meets(&self.record, &self.thresholds) {
            return Err(RepError::NotMet);
        }
        if self.index >> DEPTH != 0 {
            return Err(RepError::IndexTooLarge);
        }
        Ok(())
    }

    pub fn public_values(&self) -> Vec<Val> {
        let t = &self.thresholds;
        let mut pv = Vec::with_capacity(REP_PUBLIC);
        pv.extend_from_slice(&self.root());
        pv.extend_from_slice(&self.pseudonym());
        pv.extend_from_slice(&self.scope);
        pv.extend_from_slice(&self.bind);
        pv.push(Val::from_u32(self.record.epoch));
        pv.push(Val::from_u32(t.min_completed));
        pv.push(Val::from_u32(t.min_clients));
        pv.extend_from_slice(&amount_limbs(t.min_volume));
        pv.push(Val::from_u32(t.max_fail_permille));
        pv.push(Val::from_u32(t.min_tier));
        pv.push(Val::from_u32(t.max_first_day));
        debug_assert_eq!(pv.len(), REP_PUBLIC);
        pv
    }

    /// The value each range-check slot holds, as an integer below 2^width.
    pub fn range_values(&self) -> ([u32; NUM_RANGE], [u32; AMOUNT_LIMBS - 1]) {
        let r = &self.record;
        let t = &self.thresholds;
        let vol = amount_limbs(r.volume).map(|v| v.as_canonical_u32());
        let min = amount_limbs(t.min_volume).map(|v| v.as_canonical_u32());
        // Borrow chain: d_i = vol_i - min_i - b_(i-1) + 2^26 b_i.
        let mut d = [0u32; AMOUNT_LIMBS];
        let mut borrows = [0u32; AMOUNT_LIMBS - 1];
        let mut b_in: i64 = 0;
        for i in 0..AMOUNT_LIMBS {
            let mut x = vol[i] as i64 - min[i] as i64 - b_in;
            let b_out = if x < 0 { 1 } else { 0 };
            x += b_out << AMOUNT_LIMB_BITS;
            d[i] = x as u32;
            if i < AMOUNT_LIMBS - 1 {
                borrows[i] = b_out as u32;
            } else {
                assert_eq!(b_out, 0, "volume below the minimum");
            }
            b_in = b_out;
        }
        let mut v = [0u32; NUM_RANGE];
        v[K_COMPLETED] = r.completed;
        v[K_CLIENTS] = r.clients;
        v[K_VOL..K_VOL + AMOUNT_LIMBS].copy_from_slice(&vol);
        v[K_REJECTED] = r.rejected;
        v[K_EXPIRED] = r.expired;
        v[K_TIER] = r.tier;
        v[K_FIRST_DAY] = r.first_day;
        v[K_D_COMPLETED] = diff(r.completed, t.min_completed);
        v[K_D_CLIENTS] = diff(r.clients, t.min_clients);
        v[K_D_VOL..K_D_VOL + AMOUNT_LIMBS].copy_from_slice(&d);
        v[K_D_FAIL] = u32::try_from(fail_margin(r, t)).expect("fail ratio within the limit");
        v[K_D_TIER] = diff(r.tier, t.min_tier);
        v[K_D_DAY] = diff(t.max_first_day, r.first_day);
        for k in 0..NUM_RANGE {
            assert!(v[k] >> RANGE_BITS[k] == 0, "range slot {k}");
        }
        (v, borrows)
    }

    pub fn trace(&self) -> Result<RowMajorMatrix<Val>, RepError> {
        self.check()?;
        let cat = |l: &Digest, r: &Digest| -> [Val; WIDTH] {
            let mut s = [Val::ZERO; WIDTH];
            s[..8].copy_from_slice(l);
            s[8..].copy_from_slice(r);
            s
        };
        let id = self.idc();
        let rec = self.record.digest();
        let mut inputs = vec![[Val::ZERO; WIDTH]; ROWS];
        let mut w = vec![[Val::ZERO; 8]; ROWS];
        let mut bits = vec![Val::ZERO; ROWS];
        inputs[R_IDC] = idc_input(&self.sk);
        w[R_REC] = id;
        inputs[R_REC] = self.record.input();
        inputs[R_LEAF] = cat(&rec, &id);
        let mut node = compress(&rec, &id);
        for k in 0..DEPTH {
            let r = R_PATH + k;
            let b = (self.index >> k) & 1;
            w[r] = self.path[k];
            bits[r] = Val::from_u32(b as u32);
            inputs[r] = if b == 0 { cat(&node, &self.path[k]) } else { cat(&self.path[k], &node) };
            node = digest_of(inputs[r]);
        }
        inputs[R_PSEUDO] = cat(&self.sk, &self.scope);

        let fields = self.record.fields();
        let (values, borrows) = self.range_values();
        let borrows = borrows.map(Val::from_u32);
        let mut values_out = Vec::with_capacity(ROWS * REP_WIDTH);
        let mut acc = [Val::ZERO; NUM_RANGE];
        for r in 0..ROWS {
            let mut row = permutation_row(inputs[r]);
            row.extend_from_slice(&self.sk);
            row.extend_from_slice(&w[r]);
            row.push(bits[r]);
            row.extend_from_slice(&fields);
            row.extend_from_slice(&borrows);
            // Bit r of each slot's value, most significant first, for rows below its width.
            let mut b = [Val::ZERO; NUM_RANGE];
            for k in 0..NUM_RANGE {
                if r < RANGE_BITS[k] {
                    b[k] = Val::from_u32((values[k] >> (RANGE_BITS[k] - 1 - r)) & 1);
                }
                acc[k] = if r == 0 { b[k] } else { acc[k] * Val::TWO + b[k] };
            }
            row.extend_from_slice(&acc);
            row.extend_from_slice(&b);
            debug_assert_eq!(row.len(), REP_WIDTH);
            values_out.extend_from_slice(&row);
        }
        Ok(RowMajorMatrix::new(values_out, REP_WIDTH))
    }
}

pub fn prove_rep(rep: &Rep, seed: [u8; 32]) -> Result<(Proof<Config>, Vec<Val>), RepError> {
    let trace = rep.trace()?;
    let pv = rep.public_values();
    let proof = p3_uni_stark::prove(&config(seed), &RepAir::new(), trace, &pv).expect("prove");
    Ok((proof, pv))
}

/// Plonky3's verdict on a reputation proof for these public values. The verifier must also hold the thresholds in
/// range (check_thresholds), scope[0] = D_SCOPE, a known root and the current epoch: verify_rep does the first two.
pub fn verify_rep_proof(proof: &Proof<Config>, pv: &[Val]) -> bool {
    p3_uni_stark::verify(&config([0; 32]), &RepAir::new(), proof, pv).is_ok()
}

/// The thresholds the public values carry.
pub fn thresholds_of(pv: &[Val]) -> Option<Thresholds> {
    if pv.len() != REP_PUBLIC {
        return None;
    }
    let u = |i: usize| pv[i].as_canonical_u32();
    // Five 26-bit limbs of a value below 2^128: the top limb has 24 bits.
    let mut vol: u128 = 0;
    for i in (0..AMOUNT_LIMBS).rev() {
        let bits = if i == AMOUNT_LIMBS - 1 { 128 - AMOUNT_LIMB_BITS * (AMOUNT_LIMBS - 1) } else { AMOUNT_LIMB_BITS };
        if u(PV_MIN_VOL + i) >> bits != 0 {
            return None;
        }
        vol = (vol << AMOUNT_LIMB_BITS) | u(PV_MIN_VOL + i) as u128;
    }
    Some(Thresholds {
        min_completed: u(PV_MIN_COMPLETED),
        min_clients: u(PV_MIN_CLIENTS),
        min_volume: vol,
        max_fail_permille: u(PV_MAX_FAIL),
        min_tier: u(PV_MIN_TIER),
        max_first_day: u(PV_MAX_FIRST_DAY),
    })
}

/// A reputation proof checked as a verifier must: the public thresholds in range, scope[0] = D_SCOPE, then Plonky3.
/// (The root and the epoch are the caller's to check against the contract.)
pub fn verify_rep(proof: &Proof<Config>, pv: &[Val]) -> bool {
    let Some(t) = thresholds_of(pv) else { return false };
    check_thresholds(&t).is_ok() && pv[PV_SCOPE] == Val::from_u32(D_SCOPE) && verify_rep_proof(proof, pv)
}
