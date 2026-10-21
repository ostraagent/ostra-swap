// Extra checks from the re-review of 21 Oct 2026: constraint degree, cells no constraint reads, and
// an isolated non-boolean Merkle bit.
use ostra_swap_circuit::*;
use p3_air::BaseAir;
use p3_air::symbolic::{AirLayout, get_max_constraint_degree};
use p3_field::{PrimeCharacteristicRing};
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
    tree.append(digest(51));
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
fn rehash(t: &mut RowMajorMatrix<Val>, r: usize, input: [Val; WIDTH]) {
    let row = permutation_row(input);
    let w = t.width();
    t.values[r * w..r * w + P2_COLS].copy_from_slice(&row);
}

#[test]
fn degree_is_three() {
    let air = SpendAir::new();
    let layout = AirLayout::from_air::<Val>(&air);
    let d = get_max_constraint_degree::<Val, _>(&air, layout, ROWS);
    println!("symbolic max constraint degree {d}");
    assert!(d <= 3);
    let _ = BaseAir::<Val>::width(&air);
}

// Cells no constraint reads: randomising them keeps an honest trace valid (harmless freedom).
#[test]
fn free_cells() {
    let s = honest();
    let pv = s.public_values().unwrap();
    let mut t = s.trace().unwrap();
    for j in 0..8 {
        set(&mut t, R_VALUE, C_W + j, Val::from_u32(777 + j as u32));
        set(&mut t, R_CVALUE, C_W + j, Val::from_u32(888 + j as u32));
        set(&mut t, 127, C_W + j, Val::from_u32(999 + j as u32));
    }
    for r in [0usize, 1, 2, 3, 24, 25, 26, 127] {
        set(&mut t, r, C_BIT, Val::ONE);
    }
    for r in 26..ROWS {
        rehash(&mut t, r, core::array::from_fn(|i| Val::from_u32((r * 31 + i) as u32)));
    }
    assert!(holds(&t, &pv), "free cells");
}

// A non-boolean Merkle bit with the row made consistent: only the C_BIT boolean constraint breaks.
#[test]
fn merkle_bit_two_consistent() {
    let s = honest();
    let pv0 = s.public_values().unwrap();
    let mut t = s.trace().unwrap();
    let r = R_PATH + 4; // level 4, bit 0 honestly
    let node: Digest = core::array::from_fn(|j| get(&t, r - 1, output_col(j)));
    let sib: Digest = core::array::from_fn(|j| get(&t, r, C_W + j));
    let b = Val::TWO;
    set(&mut t, r, C_BIT, b);
    let mut inp = [Val::ZERO; WIDTH];
    for j in 0..8 {
        inp[j] = node[j] + b * (sib[j] - node[j]);
        inp[8 + j] = sib[j] + b * (node[j] - sib[j]);
    }
    rehash(&mut t, r, inp);
    // relink levels above
    for k in r + 1..=R_ROOT {
        let nd: Digest = core::array::from_fn(|j| get(&t, k - 1, output_col(j)));
        let sb: Digest = core::array::from_fn(|j| get(&t, k, C_W + j));
        let bit = get(&t, k, C_BIT);
        let mut i2 = [Val::ZERO; WIDTH];
        for j in 0..8 {
            i2[j] = nd[j] + bit * (sb[j] - nd[j]);
            i2[8 + j] = sb[j] + bit * (nd[j] - sb[j]);
        }
        rehash(&mut t, k, i2);
    }
    let mut pv = pv0.clone();
    for j in 0..8 {
        pv[PV_ROOT + j] = get(&t, R_ROOT, output_col(j));
    }
    let full = holds(&t, &pv);
    println!("full AIR accepts: {full}");
    assert!(!full);
}
