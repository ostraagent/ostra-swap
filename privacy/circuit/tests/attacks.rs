// A dishonest prover's traces: each one changes the honest witness in one way and must break a
// constraint (Plonky3's own constraint checker decides).
use ostra_swap_circuit::*;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

fn digest(n: u32) -> Digest {
    core::array::from_fn(|i| Val::from_u32(n.wrapping_mul(2654435761).wrapping_add(i as u32 * 7919) % 2130706433))
}

fn honest() -> Spend {
    let asset = [0x22u8; 20];
    let (sk, rho) = (digest(5), digest(6));
    let amount = 5_000_000u128;
    let mut tree = Tree::new();
    tree.append(digest(50));
    let index = tree.append(commitment(&value_digest(&asset_limbs(&asset), &amount_limbs(amount)), &tag(&sk, &rho)));
    Spend { sk, rho, asset, amount, index, path: tree.path(index), v: 3_000_000, fee: 20_000, change_tag: digest(7), bind: digest(8) }
}

fn holds(t: &RowMajorMatrix<Val>, pv: &[Val]) -> bool {
    let air = SpendAir::new();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let ok = std::panic::catch_unwind(|| p3_air::check_constraints(&air, t, pv)).is_ok();
    std::panic::set_hook(hook);
    ok
}

fn set(t: &mut RowMajorMatrix<Val>, r: usize, c: usize, v: Val) {
    let w = t.width();
    t.values[r * w + c] = v;
}

fn get(t: &RowMajorMatrix<Val>, r: usize, c: usize) -> Val {
    t.values[r * t.width() + c]
}

// Replace the permutation input of row r and recompute the row honestly.
fn rehash(t: &mut RowMajorMatrix<Val>, r: usize, input: [Val; WIDTH]) {
    let row = permutation_row(input);
    let w = t.width();
    t.values[r * w..r * w + P2_COLS].copy_from_slice(&row);
}

fn input(t: &RowMajorMatrix<Val>, r: usize) -> [Val; WIDTH] {
    core::array::from_fn(|i| get(t, r, i))
}

#[test]
fn honest_trace_holds() {
    let s = honest();
    assert!(holds(&s.trace().unwrap(), &s.public_values().unwrap()));
}

#[test]
fn every_attack_breaks_a_constraint() {
    let s = honest();
    let t0 = s.trace().unwrap();
    let pv0 = s.public_values().unwrap();
    let mut cases: Vec<(&str, RowMajorMatrix<Val>, Vec<Val>)> = Vec::new();
    let mut add = |name: &'static str, f: &dyn Fn(&mut RowMajorMatrix<Val>, &mut Vec<Val>)| {
        let mut t = t0.clone();
        let mut pv = pv0.clone();
        f(&mut t, &mut pv);
        cases.push((name, t, pv));
    };
    add("public v raised", &|_, pv| pv[PV_V] += Val::ONE);
    add("public fee raised in a high limb", &|_, pv| pv[PV_FEE + 3] += Val::ONE);
    add("other asset", &|_, pv| pv[PV_ASSET + 2] += Val::ONE);
    add("other nullifier", &|_, pv| pv[PV_NF + 1] += Val::ONE);
    add("other root", &|_, pv| pv[PV_ROOT + 7] += Val::ONE);
    add("other change commitment", &|_, pv| pv[PV_CHANGE] += Val::ONE);
    add("carry of three", &|t, _| set(t, R_CVALUE, C_CARRY, Val::from_u32(3)));
    add("carry minus one", &|t, _| set(t, R_CVALUE, C_CARRY + 1, Val::NEG_ONE));
    add("merkle bit two", &|t, _| set(t, R_PATH + 4, C_BIT, Val::TWO));
    add("range bit two", &|t, _| set(t, 10, C_BITS + 2, Val::TWO));
    add("spent amount changes midway", &|t, _| set(t, 60, C_AMT + 1, get(t, 60, C_AMT + 1) + Val::ONE));
    add("accumulator off", &|t, _| set(t, R_CHANGE, C_ACC, get(t, R_CHANGE, C_ACC) + Val::ONE));
    add("value not carried", &|t, _| set(t, R_TAG, C_W + 3, get(t, R_TAG, C_W + 3) + Val::ONE));
    add("rho not carried", &|t, _| set(t, R_LEAF, C_W + 1, get(t, R_LEAF, C_W + 1) + Val::ONE));
    add("commitment not carried", &|t, _| set(t, R_NF, C_W + 7, get(t, R_NF, C_W + 7) + Val::ONE));
    add("sibling swapped without its bit", &|t, _| {
        let r = R_PATH + 2;
        let i = input(t, r);
        let mut j = i;
        j[..8].copy_from_slice(&i[8..]);
        j[8..].copy_from_slice(&i[..8]);
        rehash(t, r, j);
    });
    add("nullifier of another commitment", &|t, _| {
        let mut i = input(t, R_NF);
        i[8] += Val::ONE;
        rehash(t, R_NF, i);
    });
    add("value row with a nonzero pad", &|t, _| {
        let mut i = input(t, R_VALUE);
        i[13] = Val::ONE;
        rehash(t, R_VALUE, i);
    });
    add("change limb outside 26 bits", &|t, pv| {
        // Move 2^26 from limb 1 into limb 0 of the change: the same integer with limb 0 out of range.
        // The balance carries, the change commitment and its public value are made consistent; the
        // link from the change limb to its 26-bit accumulator rejects it.
        let mut i = input(t, R_CVALUE);
        i[ASSET_LIMBS] += Val::from_u32(1 << 26);
        i[ASSET_LIMBS + 1] -= Val::ONE;
        rehash(t, R_CVALUE, i);
        let vd: Digest = core::array::from_fn(|j| get(t, R_CVALUE, output_col(j)));
        let mut c = input(t, R_CHANGE);
        c[..8].copy_from_slice(&vd);
        rehash(t, R_CHANGE, c);
        for j in 0..8 {
            pv[PV_CHANGE + j] = get(t, R_CHANGE, output_col(j));
        }
        let k0 = get(t, R_CVALUE, C_CARRY);
        for r in 0..ROWS {
            set(t, r, C_CARRY, k0 + Val::ONE);
        }
    });
    for (name, t, pv) in &cases {
        assert!(!holds(t, pv), "attack accepted: {name}");
    }
    println!("{} attacks rejected", cases.len());
}
