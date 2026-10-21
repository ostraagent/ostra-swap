// Isolated malicious traces (from the independent review of 21 Oct 2026, adapted to the nullifier
// bound to the commitment). Each one is a fully consistent trace (every
// permutation row recomputed, every other link honest) that breaks exactly one constraint group of
// SpendAir, and realises a concrete exploit if that group were missing. The full AIR must reject
// every one; with the matching group deleted (mutation run), the matching test must fail.
use ostra_swap_circuit::*;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

fn digest(n: u32) -> Digest {
    core::array::from_fn(|i| Val::from_u32(n.wrapping_mul(2654435761).wrapping_add(i as u32 * 7919) % 2130706433))
}

#[derive(Clone)]
struct W {
    inp: Vec<[Val; WIDTH]>,
    cw: Vec<[Val; 8]>,
    bit: Vec<Val>,
    amt: Vec<[Val; AMOUNT_LIMBS]>,
    carry: Vec<[Val; AMOUNT_LIMBS - 1]>,
    acc: Vec<[Val; AMOUNT_LIMBS]>,
    cbits: Vec<[Val; AMOUNT_LIMBS]>,
    pv: Vec<Val>,
}

fn from_trace(t: &RowMajorMatrix<Val>, pv: Vec<Val>) -> W {
    let w = t.width();
    let g = |r: usize, c: usize| t.values[r * w + c];
    W {
        inp: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, i))).collect(),
        cw: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_W + i))).collect(),
        bit: (0..ROWS).map(|r| g(r, C_BIT)).collect(),
        amt: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_AMT + i))).collect(),
        carry: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_CARRY + i))).collect(),
        acc: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_ACC + i))).collect(),
        cbits: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_BITS + i))).collect(),
        pv,
    }
}

fn mat(w: &W) -> RowMajorMatrix<Val> {
    let mut v = Vec::with_capacity(ROWS * TRACE_WIDTH);
    for r in 0..ROWS {
        v.extend(permutation_row(w.inp[r]));
        v.extend_from_slice(&w.cw[r]);
        v.push(w.bit[r]);
        v.extend_from_slice(&w.amt[r]);
        v.extend_from_slice(&w.carry[r]);
        v.extend_from_slice(&w.acc[r]);
        v.extend_from_slice(&w.cbits[r]);
    }
    RowMajorMatrix::new(v, TRACE_WIDTH)
}

fn out(w: &W, r: usize) -> Digest {
    permute(w.inp[r])[..8].try_into().unwrap()
}

fn cat(l: &Digest, r: &[Val]) -> [Val; WIDTH] {
    let mut s = [Val::ZERO; WIDTH];
    s[..8].copy_from_slice(l);
    s[8..].copy_from_slice(&r[..8]);
    s
}

// Re-applies the honest links on rows >= from (permutation inputs and carried digests), then the
// public nullifier, root and change commitment.
fn relink(w: &mut W, from: usize) {
    for r in from..ROWS {
        match r {
            // Tag row: carries the value digest.
            1 => w.cw[1] = out(w, 0),
            // Leaf row: (value || tag); carries rho.
            2 => {
                w.inp[2] = cat(&w.cw[1], &out(w, 1));
                let i1 = w.inp[1];
                w.cw[2].copy_from_slice(&i1[..8]);
            }
            // Nullifier row: (rho || commitment); carries the commitment.
            3 => {
                w.inp[3] = cat(&w.cw[2], &out(w, 2));
                w.cw[3] = out(w, 2);
            }
            4..=23 => {
                let node = if r == R_PATH { w.cw[R_NF] } else { out(w, r - 1) };
                let sib = w.cw[r];
                w.inp[r] = if w.bit[r] == Val::ZERO { cat(&node, &sib) } else { cat(&sib, &node) };
            }
            25 => {
                let tag = w.inp[25];
                w.inp[25] = cat(&out(w, 24), &tag[8..]);
            }
            _ => {}
        }
    }
    let (nf, root, ch) = (out(w, R_NF), out(w, R_ROOT), out(w, R_CHANGE));
    w.pv[PV_NF..PV_NF + 8].copy_from_slice(&nf);
    w.pv[PV_ROOT..PV_ROOT + 8].copy_from_slice(&root);
    w.pv[PV_CHANGE..PV_CHANGE + 8].copy_from_slice(&ch);
}

fn two26() -> Val {
    Val::from_u32(1 << AMOUNT_LIMB_BITS)
}

// Honest range-check bits and accumulators for canonical change limbs.
fn honest_bits(w: &mut W, chg: &[Val; AMOUNT_LIMBS]) {
    let mut acc = [Val::ZERO; AMOUNT_LIMBS];
    for r in 0..ROWS {
        for i in 0..AMOUNT_LIMBS {
            let b = if r < AMOUNT_LIMB_BITS { (chg[i].as_canonical_u32() >> (AMOUNT_LIMB_BITS - 1 - r)) & 1 } else { 0 };
            w.cbits[r][i] = Val::from_u32(b);
            acc[i] = if r == 0 { w.cbits[r][i] } else { acc[i] * Val::TWO + w.cbits[r][i] };
        }
        w.acc[r] = acc;
    }
}

// Carries k_i = (v_i + fee_i + chg_i + k_(i-1) - amt_i) / 2^26 in the field, on every row.
fn field_carries(w: &mut W, v: &[Val], fee: &[Val], chg: &[Val], amt: &[Val]) -> Val {
    let inv = two26().inverse();
    let mut k = Val::ZERO;
    let mut ks = [Val::ZERO; AMOUNT_LIMBS - 1];
    for i in 0..AMOUNT_LIMBS - 1 {
        k = (v[i] + fee[i] + chg[i] + k - amt[i]) * inv;
        ks[i] = k;
    }
    for r in 0..ROWS {
        w.carry[r] = ks;
    }
    // Residual of the last limb equation (must be zero for the balance to hold).
    v[4] + fee[4] + chg[4] + k - amt[4]
}

fn set_change_limbs(w: &mut W, chg: &[Val; AMOUNT_LIMBS]) {
    w.inp[R_CVALUE][ASSET_LIMBS..ASSET_LIMBS + AMOUNT_LIMBS].copy_from_slice(chg);
}

fn set_pv_amounts(w: &mut W, v: &[Val; AMOUNT_LIMBS], fee: &[Val; AMOUNT_LIMBS]) {
    w.pv[PV_V..PV_V + AMOUNT_LIMBS].copy_from_slice(v);
    w.pv[PV_FEE..PV_FEE + AMOUNT_LIMBS].copy_from_slice(fee);
}

fn holds(w: &W) -> bool {
    let air = SpendAir::new();
    let t = mat(w);
    let pv = w.pv.clone();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let ok = std::panic::catch_unwind(|| p3_air::check_constraints(&air, &t, &pv)).is_ok();
    std::panic::set_hook(hook);
    ok
}

const ASSET: [u8; 20] = [0x22; 20];
const AMOUNT: u128 = 5_000_000;

struct Setup {
    w: W,
    tree: Tree,
    victim_tag: Digest,
    victim_index: usize,
    own_index: usize,
}

// A tree with a victim's note (index 1, amount AMOUNT, tag known to whoever paid it) and the
// attacker's own note (index 2, amount AMOUNT); the honest witness spends the attacker's note.
fn setup() -> Setup {
    let a = asset_limbs(&ASSET);
    let (vsk, vrho) = (digest(900), digest(901));
    let victim_tag = tag(&vsk, &vrho);
    let (sk, rho) = (digest(5), digest(6));
    let mut tree = Tree::new();
    tree.append(digest(50));
    let victim_index = tree.append(commitment(&value_digest(&a, &amount_limbs(AMOUNT)), &victim_tag));
    let own_index = tree.append(commitment(&value_digest(&a, &amount_limbs(AMOUNT)), &tag(&sk, &rho)));
    tree.append(digest(51));
    let s = Spend {
        sk,
        rho,
        asset: ASSET,
        amount: AMOUNT,
        index: own_index,
        path: tree.path(own_index),
        v: 3_000_000,
        fee: 20_000,
        change_tag: digest(7),
        bind: digest(8),
    };
    let w = from_trace(&s.trace().unwrap(), s.public_values().unwrap());
    assert!(holds(&w), "honest witness");
    Setup { w, tree, victim_tag, victim_index, own_index }
}

fn set_path(w: &mut W, tree: &Tree, index: usize) {
    let p = tree.path(index);
    for k in 0..DEPTH {
        w.cw[R_PATH + k] = p[k];
        w.bit[R_PATH + k] = Val::from_u32(((index >> k) & 1) as u32);
    }
}

fn limbs(a: u128) -> [Val; AMOUNT_LIMBS] {
    amount_limbs(a)
}

// Withdraws v = 10,000,000 from a 5,000,000 note: the change limb is the field element
// 5,000,000 - 10,000,000 (negative); the range-check "bits" spell it with one non-boolean bit.
#[test]
fn iso_a2_change_bits_not_boolean() {
    let mut w = setup().w;
    let (v, fee) = (limbs(10_000_000), limbs(0));
    let amt = limbs(AMOUNT);
    let mut chg = [Val::ZERO; AMOUNT_LIMBS];
    chg[0] = amt[0] - v[0];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &[Val::ZERO; AMOUNT_LIMBS]);
    // bit 25 (weight 1) of limb 0 carries the whole negative value.
    w.cbits[25][0] = chg[0];
    let mut acc = Val::ZERO;
    for r in 0..ROWS {
        acc = if r == 0 { w.cbits[0][0] } else { acc * Val::TWO + w.cbits[r][0] };
        w.acc[r][0] = acc;
    }
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &amt), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, R_CHANGE);
    assert!(!holds(&w), "non-boolean change bits accepted: withdraws 2x the note");
}

// Withdraws more than the note with a zero change and carries that are field elements outside
// {0, 1, 2}: v = v0 + v1 2^26 with v0 > amount, k0 = (v0 - a0) / 2^26, v1 = -k0 (searched < 2^26).
#[test]
fn iso_a3_carry_out_of_range() {
    let mut w = setup().w;
    let amt = limbs(AMOUNT);
    let inv = two26().inverse();
    let mut found = None;
    for d in 1u32..1 << 20 {
        let k0 = Val::from_u32(d) * inv;
        let v1 = (Val::ZERO - k0).as_canonical_u32();
        if v1 < 1 << AMOUNT_LIMB_BITS {
            found = Some((d, v1));
            break;
        }
    }
    let (d, v1) = found.expect("a small excess with an in-range high limb");
    let mut v = [Val::ZERO; AMOUNT_LIMBS];
    v[0] = amt[0] + Val::from_u32(d);
    v[1] = Val::from_u32(v1);
    let fee = [Val::ZERO; AMOUNT_LIMBS];
    let chg = [Val::ZERO; AMOUNT_LIMBS];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &chg);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &amt), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, R_CHANGE);
    let withdrawn = (v[0].as_canonical_u32() as u128) + ((v1 as u128) << 26);
    assert!(withdrawn > AMOUNT);
    assert!(!holds(&w), "out-of-range carries accepted: withdraws {withdrawn} from {AMOUNT}");
}

// Negative change via the first accumulator: acc_0 = X / 2^25 with every bit zero.
#[test]
fn iso_a5_first_accumulator() {
    let mut w = setup().w;
    let (v, fee, amt) = (limbs(10_000_000), limbs(0), limbs(AMOUNT));
    let mut chg = [Val::ZERO; AMOUNT_LIMBS];
    chg[0] = amt[0] - v[0];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &[Val::ZERO; AMOUNT_LIMBS]);
    let c = chg[0] * Val::from_u32(1 << 25).inverse();
    let mut acc = c;
    for r in 0..ROWS {
        w.acc[r][0] = acc;
        acc = acc * Val::TWO;
    }
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &amt), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, R_CHANGE);
    assert!(!holds(&w), "free first accumulator accepted");
}

// Negative change via one broken accumulator step (row 24 to 25).
#[test]
fn iso_a6_accumulator_step() {
    let mut w = setup().w;
    let (v, fee, amt) = (limbs(10_000_000), limbs(0), limbs(AMOUNT));
    let mut chg = [Val::ZERO; AMOUNT_LIMBS];
    chg[0] = amt[0] - v[0];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &[Val::ZERO; AMOUNT_LIMBS]);
    let mut acc = chg[0];
    for r in R_CHANGE..ROWS {
        w.acc[r][0] = acc;
        acc = acc * Val::TWO;
    }
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &amt), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, R_CHANGE);
    assert!(!holds(&w), "accumulator jump accepted");
}

// Negative change limb not tied to the (honest, zero) accumulator.
#[test]
fn iso_a22_change_limb_not_accumulated() {
    let mut w = setup().w;
    let (v, fee, amt) = (limbs(10_000_000), limbs(0), limbs(AMOUNT));
    let mut chg = [Val::ZERO; AMOUNT_LIMBS];
    chg[0] = amt[0] - v[0];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &[Val::ZERO; AMOUNT_LIMBS]);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &amt), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, R_CHANGE);
    assert!(!holds(&w), "change limb off the accumulator accepted");
}

// Public v raised with everything else honest (change for the original v).
#[test]
fn iso_a23_balance() {
    let mut w = setup().w;
    w.pv[PV_V + 1] += Val::ONE;
    assert!(!holds(&w), "unbalanced spend accepted");
}

// The amount column claims 10x the note: row 2 hashes the real amount, the balance uses the column.
#[test]
fn iso_a12_amount_column_not_the_note() {
    let mut w = setup().w;
    let big = limbs(AMOUNT * 10);
    for r in 0..ROWS {
        w.amt[r] = big;
    }
    let (v, fee) = (limbs(AMOUNT * 10), limbs(0));
    let chg = [Val::ZERO; AMOUNT_LIMBS];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &chg);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &big), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, R_CHANGE);
    assert!(!holds(&w), "amount column above the note accepted");
}

// The amount column jumps to 10x between rows 12 and 13 (row 2 real, row 24 inflated).
#[test]
fn iso_a4_amount_column_jumps() {
    let mut w = setup().w;
    let big = limbs(AMOUNT * 10);
    for r in 13..ROWS {
        w.amt[r] = big;
    }
    let (v, fee) = (limbs(AMOUNT * 10), limbs(0));
    let chg = [Val::ZERO; AMOUNT_LIMBS];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &chg);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &big), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, R_CHANGE);
    assert!(!holds(&w), "amount column jump accepted");
}

// Spends a note of asset X as asset Y: the input note (in the tree) is X, the public asset and the
// change note are Y.
#[test]
fn iso_a11_input_asset() {
    let s0 = setup();
    let mut w = s0.w;
    let x = asset_limbs(&[0x77; 20]);
    let y = asset_limbs(&ASSET);
    let mut tree = Tree::new();
    tree.append(digest(50));
    let t = out(&w, R_TAG);
    let idx = tree.append(commitment(&value_digest(&x, &amount_limbs(AMOUNT)), &t));
    w.inp[R_VALUE][..ASSET_LIMBS].copy_from_slice(&x);
    set_path(&mut w, &tree, idx);
    relink(&mut w, 1);
    assert_eq!(&w.pv[PV_ASSET..PV_ASSET + ASSET_LIMBS], &y);
    assert_eq!(out(&w, R_ROOT), tree.root());
    assert!(!holds(&w), "input asset differs from the public asset");
    let _ = s0.tree;
}

// The change note gets another asset than the input and the public asset.
#[test]
fn iso_a19_change_asset() {
    let mut w = setup().w;
    let z = asset_limbs(&[0x99; 20]);
    w.inp[R_CVALUE][..ASSET_LIMBS].copy_from_slice(&z);
    relink(&mut w, R_CHANGE);
    assert!(!holds(&w), "change asset differs");
}

// A note whose value preimage has a nonzero pad (only reachable if such a leaf were inserted).
#[test]
fn iso_a13_input_pad() {
    let mut w = setup().w;
    w.inp[R_VALUE][13] = Val::ONE;
    let mut tree = Tree::new();
    tree.append(digest(50));
    let leaf = compress(&out(&w, R_VALUE), &out(&w, R_TAG));
    let idx = tree.append(leaf);
    set_path(&mut w, &tree, idx);
    relink(&mut w, 1);
    assert!(!holds(&w), "input value pad accepted");
}

// The change value preimage with a nonzero pad.
#[test]
fn iso_a20_change_pad() {
    let mut w = setup().w;
    w.inp[R_CVALUE][15] = Val::from_u32(12345);
    relink(&mut w, R_CHANGE);
    assert!(!holds(&w), "change value pad accepted");
}

// Double spend: the same note with a second nullifier, from another rho in the nullifier row.
#[test]
fn iso_a7a_nullifier_rho_free() {
    let mut w = setup().w;
    w.inp[R_NF][0] += Val::ONE;
    relink(&mut w, R_PATH);
    assert!(!holds(&w), "nullifier from another rho accepted");
}

// Double spend: a second nullifier over another commitment, the path still from the real one.
#[test]
fn iso_a7b_nullifier_commitment_free() {
    let mut w = setup().w;
    w.inp[R_NF][8] += Val::ONE;
    relink(&mut w, R_PATH);
    assert!(!holds(&w), "nullifier of another commitment accepted");
}

// Double spend: rho carried into the nullifier row differs from the tag's rho.
#[test]
fn iso_a7c_rho_not_carried() {
    let mut w = setup().w;
    w.cw[R_LEAF][3] += Val::ONE;
    relink(&mut w, R_NF);
    assert!(!holds(&w), "nullifier from a rho other than the tag's accepted");
}

// Value creation: the value row hashes 10x the amount (and the balance uses it); the value digest
// carried to the leaf is the real one of the attacker's own note.
#[test]
fn iso_a10_value_not_carried() {
    let s = setup();
    let mut w = s.w;
    let real = out(&w, R_VALUE);
    let big = limbs(AMOUNT * 10);
    w.inp[R_VALUE][ASSET_LIMBS..ASSET_LIMBS + AMOUNT_LIMBS].copy_from_slice(&big);
    for r in 0..ROWS {
        w.amt[r] = big;
    }
    let (v, fee) = (big, limbs(0));
    let chg = [Val::ZERO; AMOUNT_LIMBS];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &chg);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &big), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    w.cw[R_TAG] = real;
    relink(&mut w, R_LEAF);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    assert!(!holds(&w), "inflated value row accepted");
}

// Spending a note that is not in the tree: a fake 10^30 note whose nullifier is honest, while the
// commitment carried into the path is the attacker's real leaf.
#[test]
fn iso_a27_commitment_not_carried() {
    let s = setup();
    let mut w = s.w;
    let real_leaf = s.tree.leaves[s.own_index];
    let fake = limbs(10u128.pow(30));
    w.inp[R_VALUE][ASSET_LIMBS..ASSET_LIMBS + AMOUNT_LIMBS].copy_from_slice(&fake);
    for r in 0..ROWS {
        w.amt[r] = fake;
    }
    let (v, fee) = (fake, limbs(0));
    let chg = [Val::ZERO; AMOUNT_LIMBS];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &chg);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &fake), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, 1);
    w.cw[R_NF] = real_leaf;
    relink(&mut w, R_PATH);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    assert!(!holds(&w), "note outside the tree accepted (commitment carry)");
}

#[test]
fn iso_a15_leaf_right_not_tag() {
    let s = setup();
    let mut w = s.w;
    let left = out(&w, R_VALUE);
    w.inp[R_LEAF] = cat(&left, &s.victim_tag);
    set_path(&mut w, &s.tree, s.victim_index);
    w.inp[R_NF] = cat(&w.cw[R_LEAF], &out(&w, R_LEAF));
    w.cw[R_NF] = out(&w, R_LEAF);
    relink(&mut w, R_PATH);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    assert!(!holds(&w), "victim's note spent with the attacker's key");
}

// Value creation: the value row hashes 10x the amount (and the balance uses it), the leaf row hashes
// the real value digest of the attacker's own note.
#[test]
fn iso_a14_leaf_left_not_value() {
    let s = setup();
    let mut w = s.w;
    let real = out(&w, R_VALUE);
    let big = limbs(AMOUNT * 10);
    w.inp[R_VALUE][ASSET_LIMBS..ASSET_LIMBS + AMOUNT_LIMBS].copy_from_slice(&big);
    for r in 0..ROWS {
        w.amt[r] = big;
    }
    let (v, fee) = (big, limbs(0));
    let chg = [Val::ZERO; AMOUNT_LIMBS];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &chg);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &big), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, 1);
    let tg = out(&w, R_TAG);
    w.inp[R_LEAF] = cat(&real, &tg);
    w.inp[R_NF] = cat(&w.cw[R_LEAF], &out(&w, R_LEAF));
    w.cw[R_NF] = out(&w, R_LEAF);
    relink(&mut w, R_PATH);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    assert!(!holds(&w), "inflated value row accepted");
}

// Spending a note that is not in the tree: a fake 10^30 note, and at level 0 the real leaf at
// index 0 swapped in for its commitment (bit 0: the left input must be the node).
#[test]
fn iso_a16_path_left() {
    let s = setup();
    let mut w = s.w;
    let fake = limbs(10u128.pow(30));
    w.inp[R_VALUE][ASSET_LIMBS..ASSET_LIMBS + AMOUNT_LIMBS].copy_from_slice(&fake);
    for r in 0..ROWS {
        w.amt[r] = fake;
    }
    let (v, fee) = (fake, limbs(0));
    let chg = [Val::ZERO; AMOUNT_LIMBS];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &chg);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &fake), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, 1);
    set_path(&mut w, &s.tree, 0);
    let leaf0 = s.tree.leaves[0];
    w.inp[R_PATH] = cat(&leaf0, &w.cw[R_PATH]);
    relink(&mut w, R_PATH + 1);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    assert!(!holds(&w), "note outside the tree accepted (left)");
}

#[test]
fn iso_a17_path_right() {
    let s = setup();
    let mut w = s.w;
    let fake = limbs(10u128.pow(30));
    w.inp[R_VALUE][ASSET_LIMBS..ASSET_LIMBS + AMOUNT_LIMBS].copy_from_slice(&fake);
    for r in 0..ROWS {
        w.amt[r] = fake;
    }
    let (v, fee) = (fake, limbs(0));
    let chg = [Val::ZERO; AMOUNT_LIMBS];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &chg);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &fake), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, 1);
    set_path(&mut w, &s.tree, 1);
    let leaf1 = s.tree.leaves[1];
    w.inp[R_PATH] = cat(&w.cw[R_PATH], &leaf1);
    relink(&mut w, R_PATH + 1);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    assert!(!holds(&w), "note outside the tree accepted (right)");
}

// The last Merkle level replaced by the real root's two children (depth one short).
#[test]
fn iso_a25_last_level_free() {
    let s = setup();
    let mut w = s.w;
    let fake = limbs(10u128.pow(30));
    w.inp[R_VALUE][ASSET_LIMBS..ASSET_LIMBS + AMOUNT_LIMBS].copy_from_slice(&fake);
    for r in 0..ROWS {
        w.amt[r] = fake;
    }
    let (v, fee) = (fake, limbs(0));
    let chg = [Val::ZERO; AMOUNT_LIMBS];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &chg);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &fake), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    relink(&mut w, 1);
    // The real root is P(level-19 node of index 0 || empty root of depth 19).
    let p = s.tree.path(s.own_index);
    let mut node = commitment(&value_digest(&asset_limbs(&ASSET), &amount_limbs(AMOUNT)), &tag(&digest(5), &digest(6)));
    for (k, sib) in p.iter().enumerate().take(DEPTH - 1) {
        node = if (s.own_index >> k) & 1 == 0 { compress(&node, sib) } else { compress(sib, &node) };
    }
    w.inp[R_ROOT] = cat(&node, &p[DEPTH - 1]);
    relink(&mut w, R_ROOT + 1);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    assert!(!holds(&w), "top level unconstrained accepted");
}

// Value creation in the change note: row 24 hashes the honest change, row 25 hashes the value digest
// of a 10^30 change.
#[test]
fn iso_a21_change_left_not_cvalue() {
    let mut w = setup().w;
    let big = value_digest(&asset_limbs(&ASSET), &limbs(10u128.pow(30)));
    let tg = w.inp[R_CHANGE];
    w.inp[R_CHANGE] = cat(&big, &tg[8..]);
    relink(&mut w, R_CHANGE + 1);
    assert!(!holds(&w), "inflated change note accepted");
}

// Any nullifier: the nullifier row's output columns replaced, its permutation columns otherwise
// honest (only the permutation's last-round constraints of row 1 break).
#[test]
fn iso_a26_permutation() {
    let mut w = setup().w;
    let t = mat(&w);
    let mut t2 = t.clone();
    let wd = t2.width();
    for j in 0..8 {
        t2.values[R_NF * wd + output_col(j)] += Val::ONE;
        w.pv[PV_NF + j] += Val::ONE;
    }
    let air = SpendAir::new();
    let pv = w.pv.clone();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let ok = std::panic::catch_unwind(|| p3_air::check_constraints(&air, &t2, &pv)).is_ok();
    std::panic::set_hook(hook);
    assert!(!ok, "free permutation output accepted");
}

#[test]
fn honest_setup_holds() {
    let s = setup();
    assert!(holds(&s.w));
    let mut w = s.w.clone();
    relink(&mut w, 1);
    assert!(holds(&w), "relink is honest");
}

// Spending a note that is not in the tree, through a higher level: a fake 10^30 note at index 2,
// and at level 1 (node on the right) the real level-1 node of leaves 2 and 3 swapped in.
#[test]
fn iso_a17b_path_right_level_one() {
    let s = setup();
    let mut w = s.w;
    let fake = limbs(10u128.pow(30));
    w.inp[R_VALUE][ASSET_LIMBS..ASSET_LIMBS + AMOUNT_LIMBS].copy_from_slice(&fake);
    for r in 0..ROWS {
        w.amt[r] = fake;
    }
    let (v, fee) = (fake, limbs(0));
    let chg = [Val::ZERO; AMOUNT_LIMBS];
    set_change_limbs(&mut w, &chg);
    honest_bits(&mut w, &chg);
    assert_eq!(field_carries(&mut w, &v, &fee, &chg, &fake), Val::ZERO);
    set_pv_amounts(&mut w, &v, &fee);
    set_path(&mut w, &s.tree, 2);
    relink(&mut w, 1);
    let real = compress(&s.tree.leaves[2], &s.tree.leaves[3]);
    let r = R_PATH + 1;
    w.inp[r] = cat(&w.cw[r], &real);
    relink(&mut w, r + 1);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    assert!(!holds(&w), "note outside the tree accepted (right, level 1)");
}
