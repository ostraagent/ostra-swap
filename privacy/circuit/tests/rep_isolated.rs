// Isolated malicious traces for RepAir, after circuit/tests/isolated.rs. Each one is a fully consistent trace (every
// permutation row recomputed, every other link honest) that breaks exactly one constraint of RepAir and would let a
// concrete cheat through if that constraint were missing; each says what it cheats. The full AIR must reject every one,
// and Plonky3's own checker (check_all_constraints) must find it failing on that one constraint only (caught_by_one).
// Some cheats need a leaf the contract never writes (a field outside what OstraReputation clamps to, another record
// layout): those insert such a leaf in the test tree, as isolated.rs does for a note with a nonzero pad.
use ostra_swap_circuit::rep::*;
use ostra_swap_circuit::{AMOUNT_LIMB_BITS, AMOUNT_LIMBS, DEPTH, Digest, ROWS, Tree, Val, WIDTH, amount_limbs, compress, permutation_row, permute};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;

fn digest(n: u32) -> Digest {
    core::array::from_fn(|i| Val::from_u32(n.wrapping_mul(2654435761).wrapping_add(i as u32 * 7919) % 2130706433))
}

#[derive(Clone)]
struct W {
    inp: Vec<[Val; WIDTH]>,
    sk: Vec<[Val; 8]>,
    cw: Vec<[Val; 8]>,
    bit: Vec<Val>,
    field: Vec<[Val; NUM_FIELDS]>,
    borrow: Vec<[Val; AMOUNT_LIMBS - 1]>,
    acc: Vec<[Val; NUM_RANGE]>,
    rbit: Vec<[Val; NUM_RANGE]>,
    pv: Vec<Val>,
}

fn from_trace(t: &RowMajorMatrix<Val>, pv: Vec<Val>) -> W {
    let w = REP_WIDTH;
    let g = |r: usize, c: usize| t.values[r * w + c];
    W {
        inp: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, i))).collect(),
        sk: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_SK + i))).collect(),
        cw: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_W + i))).collect(),
        bit: (0..ROWS).map(|r| g(r, C_BIT)).collect(),
        field: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_FIELD + i))).collect(),
        borrow: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_BORROW + i))).collect(),
        acc: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_ACC + i))).collect(),
        rbit: (0..ROWS).map(|r| core::array::from_fn(|i| g(r, C_RBIT + i))).collect(),
        pv,
    }
}

fn mat(w: &W) -> RowMajorMatrix<Val> {
    let mut v = Vec::with_capacity(ROWS * REP_WIDTH);
    for r in 0..ROWS {
        v.extend(permutation_row(w.inp[r]));
        v.extend_from_slice(&w.sk[r]);
        v.extend_from_slice(&w.cw[r]);
        v.push(w.bit[r]);
        v.extend_from_slice(&w.field[r]);
        v.extend_from_slice(&w.borrow[r]);
        v.extend_from_slice(&w.acc[r]);
        v.extend_from_slice(&w.rbit[r]);
    }
    RowMajorMatrix::new(v, REP_WIDTH)
}

fn out(w: &W, r: usize) -> Digest {
    permute(w.inp[r])[..8].try_into().unwrap()
}

fn cat(l: &[Val], r: &[Val]) -> [Val; WIDTH] {
    let mut s = [Val::ZERO; WIDTH];
    s[..8].copy_from_slice(&l[..8]);
    s[8..].copy_from_slice(&r[..8]);
    s
}

// The constraints that fail on a trace, by their index in RepAir::eval's order (Plonky3's check_all_constraints).
fn failing(w: &W) -> Vec<usize> {
    let report = p3_air::check_all_constraints(&RepAir::new(), &mat(w), &w.pv, None);
    let mut ids: Vec<usize> = report.failures.iter().map(|f| f.constraint).collect();
    ids.sort();
    ids.dedup();
    ids
}

fn holds(w: &W) -> bool {
    let t = mat(w);
    let pv = w.pv.clone();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let ok = std::panic::catch_unwind(|| p3_air::check_constraints(&RepAir::new(), &t, &pv)).is_ok();
    std::panic::set_hook(hook);
    ok
}

// The cheat is caught, and by exactly one constraint (one assertion, or the lanes of one digest equality: a single run
// of at most 8 consecutive constraint indices): with it deleted the trace would pass.
fn caught_by_one(w: &W) {
    assert!(!holds(w), "the full AIR accepts the cheat");
    let f = failing(w);
    println!("caught by constraints {f:?}");
    assert!(!f.is_empty() && f.len() <= 8, "the trace breaks exactly one constraint, not {f:?}");
    assert_eq!(f[f.len() - 1] - f[0] + 1, f.len(), "one run of lanes, not {f:?}");
}

// Honest links on rows >= from: the idc carry, the leaf row, the Merkle path; then the public root and pseudonym.
fn relink(w: &mut W, from: usize) {
    for r in from.max(1)..ROWS {
        match r {
            R_REC => w.cw[R_REC] = out(w, R_IDC),
            R_LEAF => w.inp[R_LEAF] = cat(&out(w, R_REC), &w.cw[R_REC]),
            R_PATH..=R_ROOT => {
                let node = out(w, r - 1);
                let sib = w.cw[r];
                w.inp[r] = if w.bit[r] == Val::ZERO { cat(&node, &sib) } else { cat(&sib, &node) };
            }
            _ => {}
        }
    }
    let (root, ps) = (out(w, R_ROOT), out(w, R_PSEUDO));
    w.pv[PV_ROOT..PV_ROOT + 8].copy_from_slice(&root);
    w.pv[PV_PSEUDO..PV_PSEUDO + 8].copy_from_slice(&ps);
}

fn set_path(w: &mut W, tree: &Tree, index: usize) {
    let p = tree.path(index);
    for k in 0..DEPTH {
        w.cw[R_PATH + k] = p[k];
        w.bit[R_PATH + k] = Val::from_u32(((index >> k) & 1) as u32);
    }
}

// Range slot k holds `value` (any field element): honest bits when it fits the slot, else all-zero bits.
fn set_slot(w: &mut W, k: usize, value: Val) {
    let bits = RANGE_BITS[k];
    let v = value.as_canonical_u32();
    let fits = v >> bits == 0;
    let mut acc = Val::ZERO;
    for r in 0..ROWS {
        let b = if fits && r < bits { (v >> (bits - 1 - r)) & 1 } else { 0 };
        w.rbit[r][k] = Val::from_u32(b);
        acc = if r == 0 { w.rbit[r][k] } else { acc * Val::TWO + w.rbit[r][k] };
        w.acc[r][k] = acc;
    }
}

// The record fields on every row, and the record row's input hashing them (epoch kept).
fn set_record(w: &mut W, r: &Record) {
    let f = r.fields();
    for row in 0..ROWS {
        w.field[row] = f;
    }
    w.inp[R_REC] = r.input();
}

// Honest range slots for record r and thresholds t (both met, in range), from the trace generator itself.
fn honest_slots(w: &mut W, r: &Record, t: &Thresholds, sk: &Digest, scope: &[Val; 8]) {
    let s = Rep { sk: *sk, record: *r, index: 0, path: [[Val::ZERO; 8]; DEPTH], scope: *scope, thresholds: *t, bind: [Val::ZERO; 8] };
    let (values, borrows) = s.range_values();
    for k in 0..NUM_RANGE {
        set_slot(w, k, Val::from_u32(values[k]));
    }
    for row in 0..ROWS {
        w.borrow[row] = borrows.map(Val::from_u32);
    }
}

fn set_thresholds(w: &mut W, t: &Thresholds) {
    w.pv[PV_MIN_COMPLETED] = Val::from_u32(t.min_completed);
    w.pv[PV_MIN_CLIENTS] = Val::from_u32(t.min_clients);
    w.pv[PV_MIN_VOL..PV_MIN_VOL + AMOUNT_LIMBS].copy_from_slice(&amount_limbs(t.min_volume));
    w.pv[PV_MAX_FAIL] = Val::from_u32(t.max_fail_permille);
    w.pv[PV_MIN_TIER] = Val::from_u32(t.min_tier);
    w.pv[PV_MAX_FIRST_DAY] = Val::from_u32(t.max_first_day);
}

const EPOCH: u32 = 9;

// The attacker's modest record, the victim's excellent one, and the thresholds the victim meets.
fn own() -> Record {
    Record { completed: 12, clients: 5, volume: 120_000_000, rejected: 2, expired: 1, tier: 1, first_day: 40, epoch: EPOCH }
}
fn victim() -> Record {
    Record { completed: 400, clients: 90, volume: 50_000_000_000, rejected: 3, expired: 1, tier: 3, first_day: 2, epoch: EPOCH }
}
fn high() -> Thresholds {
    Thresholds { min_completed: 200, min_clients: 50, min_volume: 10_000_000_000, max_fail_permille: 50, min_tier: 3, max_first_day: 10 }
}
fn low() -> Thresholds {
    Thresholds { min_completed: 10, min_clients: 5, min_volume: 100_000_000, max_fail_permille: 300, min_tier: 1, max_first_day: 60 }
}

struct Setup {
    w: W,
    tree: Tree,
    sk: Digest,
    scope: [Val; 8],
    victim_idc: Digest,
    victim_index: usize,
    own_index: usize,
}

// A tree with the victim's leaf (index 1) and the attacker's (index 2); the honest witness proves the attacker's own
// record against `low` thresholds.
fn setup() -> Setup {
    let sk = digest(5);
    let victim_idc = idc(&digest(900));
    let mut tree = Tree::new();
    tree.append(digest(50));
    let victim_index = tree.append(victim().leaf(&victim_idc));
    let own_index = tree.append(own().leaf(&idc(&sk)));
    tree.append(digest(51));
    let scope = scope_elements(&[0x77; 32]);
    let s = Rep { sk, record: own(), index: own_index, path: tree.path(own_index), scope, thresholds: low(), bind: digest(8) };
    let w = from_trace(&s.trace().unwrap(), s.public_values());
    assert!(holds(&w) && failing(&w).is_empty(), "honest witness");
    Setup { w, tree, sk, scope, victim_idc, victim_index, own_index }
}

// The trace proving record r (its leaf at `index` of `tree`) against t, with every link honest.
fn prove_as(s: &Setup, r: &Record, t: &Thresholds, tree: &Tree, index: usize) -> W {
    let mut w = s.w.clone();
    set_record(&mut w, r);
    honest_slots(&mut w, r, t, &s.sk, &s.scope);
    set_thresholds(&mut w, t);
    set_path(&mut w, tree, index);
    relink(&mut w, 1);
    w
}

#[test]
fn honest_setup_holds() {
    let s = setup();
    let mut w = s.w.clone();
    relink(&mut w, 1);
    assert!(holds(&w), "relink is honest");
    let w = prove_as(&s, &own(), &low(), &s.tree, s.own_index);
    assert!(holds(&w), "prove_as is honest");
    assert_eq!(out(&w, R_ROOT), s.tree.root());
}

// ---- Group 1: idc row

// Sybil: the idc row hashes the attacker's own sk (its vault's idc, its own leaf), but the carried sk is any other:
// a fresh pseudonym for the same vault in the same scope, as many as it likes.
#[test]
fn g1_idc_row_not_the_carried_sk() {
    let s = setup();
    let mut w = s.w.clone();
    let other = digest(4242);
    for r in 0..ROWS {
        w.sk[r] = other;
    }
    w.inp[R_PSEUDO] = cat(&other, &s.scope);
    w.inp[R_IDC][..8].copy_from_slice(&s.sk);
    relink(&mut w, 1);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    assert_ne!(out(&w, R_PSEUDO), s.w.pv[PV_PSEUDO..PV_PSEUDO + 8]);
    caught_by_one(&w);
}

// The victim's record under the attacker's key: the idc row hashes the attacker's sk, the leaf takes the victim's
// (public) idc instead of the carried one.
#[test]
fn g1_idc_not_carried() {
    let s = setup();
    let mut w = prove_as(&s, &victim(), &high(), &s.tree, s.victim_index);
    w.cw[R_REC] = s.victim_idc;
    relink(&mut w, R_LEAF);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    caught_by_one(&w);
}

// The idc pin: an idc outside the D_IDC domain (here P(sk || scope), the pseudonym of that scope). No gain to the
// prover (it only links its own vault to that scope); kept as the spec fixes D_IDC in the AIR. Needs such an idc
// registered.
#[test]
fn g1_idc_pad() {
    let s = setup();
    let mut w = s.w.clone();
    w.inp[R_IDC] = cat(&s.sk, &s.scope);
    let fake_idc = out(&w, R_IDC);
    let mut tree = Tree::new();
    tree.append(digest(50));
    let index = tree.append(own().leaf(&fake_idc));
    set_path(&mut w, &tree, index);
    relink(&mut w, 1);
    assert_eq!(fake_idc, s.w.pv[PV_PSEUDO..PV_PSEUDO + 8]);
    caught_by_one(&w);
}

// ---- Group 2: record row

// Inflation: the record row hashes the attacker's real record (12 completed) while the comparisons read 500.
#[test]
fn g2_field_not_hashed() {
    let s = setup();
    let mut real = own();
    let mut w = prove_as(&s, &own(), &low(), &s.tree, s.own_index);
    real.completed = 500;
    let t = Thresholds { min_completed: 500, ..low() };
    let f = real.fields();
    for r in 0..ROWS {
        w.field[r] = f;
    }
    honest_slots(&mut w, &real, &t, &s.sk, &s.scope);
    set_thresholds(&mut w, &t);
    relink(&mut w, 1);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    caught_by_one(&w);
}

// Inflation: the carried completed count jumps from 12 (rows 0 and 1, the hashed one) to 500 on row 2.
#[test]
fn g2_field_jumps() {
    let s = setup();
    let mut big = own();
    big.completed = 500;
    let t = Thresholds { min_completed: 500, ..low() };
    let mut w = prove_as(&s, &own(), &low(), &s.tree, s.own_index);
    honest_slots(&mut w, &big, &t, &s.sk, &s.scope);
    set_thresholds(&mut w, &t);
    for r in R_LEAF..ROWS {
        w.field[r] = big.fields();
    }
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    caught_by_one(&w);
}

// A leaf of another layout (element 0 is not D_REC: here a sixth volume limb of 2^28, a volume beyond 2^130 that no
// record holds). Needs such a leaf in the tree.
#[test]
fn g2_domain() {
    let s = setup();
    let mut w = prove_as(&s, &own(), &low(), &s.tree, s.own_index);
    w.inp[R_REC][S_DOMAIN] = Val::from_u32(1 << 28);
    let mut tree = Tree::new();
    tree.append(digest(50));
    let index = tree.append(compress(&out(&w, R_REC), &idc(&s.sk)));
    set_path(&mut w, &tree, index);
    relink(&mut w, 1);
    caught_by_one(&w);
}

// A leaf with a nonzero pad (an extra field after the epoch). Needs such a leaf in the tree.
#[test]
fn g2_pad() {
    let s = setup();
    let mut w = prove_as(&s, &own(), &low(), &s.tree, s.own_index);
    w.inp[R_REC][S_PAD + 1] = Val::from_u32(12345);
    let mut tree = Tree::new();
    let index = tree.append(compress(&out(&w, R_REC), &idc(&s.sk)));
    set_path(&mut w, &tree, index);
    relink(&mut w, 1);
    caught_by_one(&w);
}

// ---- Group 3: leaf and Merkle path

// Inflation: the record row hashes a fake record meeting `high`; the leaf row hashes the attacker's real record digest.
#[test]
fn g3_leaf_left_not_record() {
    let s = setup();
    let mut fake = victim();
    fake.first_day = own().first_day.min(10);
    let mut w = prove_as(&s, &fake, &high(), &s.tree, s.own_index);
    w.inp[R_LEAF] = cat(&own().digest(), &idc(&s.sk));
    relink(&mut w, R_PATH);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    caught_by_one(&w);
}

// The victim's record under the attacker's key: the leaf row hashes the victim's leaf (its record is public, so is
// its idc), the carried idc being the attacker's.
#[test]
fn g3_leaf_right_not_idc() {
    let s = setup();
    let mut w = prove_as(&s, &victim(), &high(), &s.tree, s.victim_index);
    w.inp[R_LEAF] = cat(&victim().digest(), &s.victim_idc);
    relink(&mut w, R_PATH);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    caught_by_one(&w);
}

// A fake record that is in no leaf: at level 0 (bit 0) the left input is the real leaf at index 2, not the node.
#[test]
fn g3_path_left() {
    let s = setup();
    let mut w = prove_as(&s, &victim(), &high(), &s.tree, s.own_index);
    w.inp[R_PATH] = cat(&s.tree.leaves[s.own_index], &w.cw[R_PATH]);
    relink(&mut w, R_PATH + 1);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    caught_by_one(&w);
}

// The same at level 0 with bit 1 (index 1, the victim's position): the right input is not the node.
#[test]
fn g3_path_right() {
    let s = setup();
    let mut w = prove_as(&s, &victim(), &high(), &s.tree, s.victim_index);
    w.cw[R_REC] = idc(&s.sk);
    w.inp[R_LEAF] = cat(&victim().digest(), &idc(&s.sk));
    w.inp[R_PATH] = cat(&w.cw[R_PATH], &s.tree.leaves[s.victim_index]);
    relink(&mut w, R_PATH + 1);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    caught_by_one(&w);
}

// The last level hashes the real root's children instead of the path's node.
#[test]
fn g3_last_level() {
    let s = setup();
    let mut w = prove_as(&s, &victim(), &high(), &s.tree, s.own_index);
    let p = s.tree.path(s.own_index);
    let mut node = s.tree.leaves[s.own_index];
    for (k, sib) in p.iter().enumerate().take(DEPTH - 1) {
        node = if (s.own_index >> k) & 1 == 0 { compress(&node, sib) } else { compress(sib, &node) };
    }
    w.inp[R_ROOT] = cat(&node, &p[DEPTH - 1]);
    relink(&mut w, R_ROOT + 1);
    assert_eq!(out(&w, R_ROOT), s.tree.root());
    caught_by_one(&w);
}

// A fake record in a tree of the attacker's own, shown against a real root it never reaches.
#[test]
fn g3_root() {
    let s = setup();
    let mut tree = Tree::new();
    let index = tree.append(victim().leaf(&idc(&s.sk)));
    let mut w = prove_as(&s, &victim(), &high(), &tree, index);
    w.pv[PV_ROOT..PV_ROOT + 8].copy_from_slice(&s.tree.root());
    caught_by_one(&w);
}

// ---- Group 4: pseudonym row

// Sybil: the pseudonym row hashes any sk, not the carried one.
#[test]
fn g4_pseudonym_sk_not_carried() {
    let s = setup();
    let mut w = s.w.clone();
    w.inp[R_PSEUDO] = cat(&digest(31337), &s.scope);
    relink(&mut w, R_PSEUDO);
    caught_by_one(&w);
}

// Sybil: the carried sk changes after the idc row.
#[test]
fn g4_sk_jumps() {
    let s = setup();
    let mut w = s.w.clone();
    for r in R_LEAF..ROWS {
        w.sk[r] = digest(31337);
    }
    w.inp[R_PSEUDO] = cat(&digest(31337), &s.scope);
    relink(&mut w, R_PSEUDO);
    caught_by_one(&w);
}

// Sybil: in scope S the pseudonym of another scope T (one per T, so as many as it likes in S).
#[test]
fn g4_scope_not_public() {
    let s = setup();
    let mut w = s.w.clone();
    w.inp[R_PSEUDO] = cat(&s.sk, &scope_elements(&[0x78; 32]));
    relink(&mut w, R_PSEUDO);
    caught_by_one(&w);
}

// Linking: a verifier's scope [D_IDC, 0, ..] makes the pseudonym the vault's public idc.
#[test]
fn g4_scope_domain() {
    let s = setup();
    let mut w = s.w.clone();
    let mut scope = [Val::ZERO; 8];
    scope[0] = Val::from_u32(D_IDC);
    w.pv[PV_SCOPE..PV_SCOPE + 8].copy_from_slice(&scope);
    w.inp[R_PSEUDO] = cat(&s.sk, &scope);
    relink(&mut w, R_PSEUDO);
    assert_eq!(out(&w, R_PSEUDO), idc(&s.sk));
    caught_by_one(&w);
}

// Sybil: any public pseudonym.
#[test]
fn g4_pseudonym_output() {
    let s = setup();
    let mut w = s.w.clone();
    w.pv[PV_PSEUDO] += Val::ONE;
    caught_by_one(&w);
}

// ---- Group 5: epoch

// A stale record: the vault's leaf of an earlier epoch (before its rejections) proved in the current epoch.
#[test]
fn g5_epoch() {
    let s = setup();
    let mut old = victim();
    old.epoch = EPOCH - 3;
    old.rejected = 0;
    let mut tree = s.tree.clone_tree();
    let index = tree.append(old.leaf(&idc(&s.sk)));
    let t = Thresholds { max_fail_permille: 3, ..high() };
    let mut w = prove_as(&s, &old, &t, &tree, index);
    w.pv[PV_EPOCH] = Val::from_u32(EPOCH);
    caught_by_one(&w);
}

// ---- Groups 6 to 10: a comparison's difference not tied to its slot (the slot honest for 0)

fn tie_broken(r: Record, t: Thresholds, slot: usize) {
    let s = setup();
    let mut tree = s.tree.clone_tree();
    let index = tree.append(r.leaf(&idc(&s.sk)));
    let mut met = t;
    // Honest slots for thresholds the record meets, then the public thresholds it does not.
    met.min_completed = met.min_completed.min(r.completed);
    met.min_clients = met.min_clients.min(r.clients);
    met.min_volume = met.min_volume.min(r.volume);
    met.min_tier = met.min_tier.min(r.tier);
    met.max_first_day = met.max_first_day.max(r.first_day);
    if fail_margin(&r, &met) < 0 {
        met.max_fail_permille = PERMILLE;
    }
    let mut w = prove_as(&s, &r, &met, &tree, index);
    set_thresholds(&mut w, &t);
    set_slot(&mut w, slot, Val::ZERO);
    caught_by_one(&w);
}

// Group 6: 3 completed jobs against a minimum of 10; 2 clients against 5.
#[test]
fn g6_completed() {
    tie_broken(Record { completed: 3, ..own() }, Thresholds { max_fail_permille: 1000, ..low() }, K_D_COMPLETED);
}
#[test]
fn g6_clients() {
    tie_broken(Record { clients: 2, ..own() }, Thresholds { max_fail_permille: 1000, ..low() }, K_D_CLIENTS);
}

// Group 8: 3 fails of 15 (200 per mille) under a limit of 100.
#[test]
fn g8_fail_ratio() {
    tie_broken(own(), Thresholds { max_fail_permille: 100, ..low() }, K_D_FAIL);
}

// Group 9: tier 1 against a minimum of 3.
#[test]
fn g9_tier() {
    tie_broken(own(), Thresholds { min_tier: 3, ..low() }, K_D_TIER);
}

// Group 10: first snapshot on day 40 against a latest of day 10.
#[test]
fn g10_first_day() {
    tie_broken(own(), Thresholds { max_first_day: 10, ..low() }, K_D_DAY);
}

// Group 7: 120 USDG against 130 USDG (they differ in limb 0 only): limb 0's difference is negative, its slot honest
// for 0, no borrows.
#[test]
fn g7_volume_limb() {
    let r = own();
    let t = Thresholds { min_volume: 130_000_000, max_fail_permille: 1000, ..low() };
    let s = setup();
    let mut tree = s.tree.clone_tree();
    let index = tree.append(r.leaf(&idc(&s.sk)));
    let mut w = prove_as(&s, &r, &Thresholds { min_volume: r.volume, ..t }, &tree, index);
    set_thresholds(&mut w, &t);
    let v = amount_limbs(r.volume);
    let m = amount_limbs(t.min_volume);
    assert_ne!(v[0], m[0]);
    for i in 1..AMOUNT_LIMBS {
        assert_eq!(v[i], m[i], "only limb 0 differs");
    }
    for row in 0..ROWS {
        w.borrow[row] = [Val::ZERO; AMOUNT_LIMBS - 1];
    }
    for i in 0..AMOUNT_LIMBS {
        set_slot(&mut w, K_D_VOL + i, Val::ZERO);
    }
    caught_by_one(&w);
}

// Group 7: volume below the minimum by 2^26 through a non-boolean borrow out of limb 1 (a small negative
// field element), every difference limb in range.
#[test]
fn g7_borrow_not_boolean() {
    let r = Record { volume: 5u128 << 26, ..own() };
    let min = 6u128 << 26;
    let t = Thresholds { min_volume: min, max_fail_permille: 1000, ..low() };
    let s = setup();
    let mut tree = s.tree.clone_tree();
    let index = tree.append(r.leaf(&idc(&s.sk)));
    let mut w = prove_as(&s, &r, &Thresholds { min_volume: r.volume, ..t }, &tree, index);
    set_thresholds(&mut w, &t);
    let inv = Val::from_u32(1 << AMOUNT_LIMB_BITS).inverse();
    // d1 = 5 - 6 - 0 + 2^26 beta, d2 = 0 - 0 - beta + 0: beta = -k, d2 = k, d1 = -1 - 2^26 k; both below 2^26.
    let mut found = None;
    for d1 in 0u32..1 << 26 {
        let k = (Val::ZERO - Val::ONE - Val::from_u32(d1)) * inv;
        let kk = k.as_canonical_u32();
        if kk < 1 << 26 {
            found = Some((d1, Val::ZERO - k));
            break;
        }
    }
    let (d1, beta) = found.expect("a borrow");
    let v = amount_limbs(r.volume);
    let m = amount_limbs(t.min_volume);
    assert_eq!(v[1] - m[1] + Val::from_u32(1 << 26) * beta, Val::from_u32(d1));
    for row in 0..ROWS {
        w.borrow[row] = [Val::ZERO, beta, Val::ZERO, Val::ZERO];
    }
    set_slot(&mut w, K_D_VOL, Val::ZERO);
    set_slot(&mut w, K_D_VOL + 1, Val::from_u32(d1));
    set_slot(&mut w, K_D_VOL + 2, Val::ZERO - beta);
    set_slot(&mut w, K_D_VOL + 3, Val::ZERO);
    set_slot(&mut w, K_D_VOL + 4, Val::ZERO);
    caught_by_one(&w);
}

// ---- The range machinery (groups 6 to 11): a negative difference spelled by its bits

fn negative_completed() -> (W, Val) {
    let s = setup();
    let r = Record { completed: 3, ..own() };
    let t = Thresholds { max_fail_permille: 1000, ..low() };
    let mut tree = s.tree.clone_tree();
    let index = tree.append(r.leaf(&idc(&s.sk)));
    let mut w = prove_as(&s, &r, &Thresholds { min_completed: 3, ..t }, &tree, index);
    set_thresholds(&mut w, &t);
    (w, Val::from_u32(3) - Val::from_u32(10))
}

// The last bit (row 29) carries the whole negative difference: a non-boolean bit.
#[test]
fn range_bit_not_boolean() {
    let (mut w, x) = negative_completed();
    let k = K_D_COMPLETED;
    set_slot(&mut w, k, Val::ZERO);
    let last = DIFF_BITS - 1;
    w.rbit[last][k] = x;
    let mut acc = Val::ZERO;
    for r in 0..ROWS {
        acc = if r == 0 { w.rbit[0][k] } else { acc * Val::TWO + w.rbit[r][k] };
        w.acc[r][k] = acc;
    }
    caught_by_one(&w);
}

// The first accumulator is x / 2^29 with every bit zero.
#[test]
fn range_first_accumulator() {
    let (mut w, x) = negative_completed();
    let k = K_D_COMPLETED;
    set_slot(&mut w, k, Val::ZERO);
    let mut acc = x * Val::from_u32(1 << (DIFF_BITS - 1)).inverse();
    for r in 0..ROWS {
        w.acc[r][k] = acc;
        acc = acc * Val::TWO;
    }
    caught_by_one(&w);
}

// The accumulator jumps to x on row 29.
#[test]
fn range_accumulator_step() {
    let (mut w, x) = negative_completed();
    let k = K_D_COMPLETED;
    set_slot(&mut w, k, Val::ZERO);
    let mut acc = x;
    for r in DIFF_BITS - 1..ROWS {
        w.acc[r][k] = acc;
        acc = acc * Val::TWO;
    }
    caught_by_one(&w);
}

// ---- Group 11: record fields beyond what the contract writes (each needs such a leaf in the tree)

fn crafted(r: Record, t: Thresholds, slot: usize) {
    let s = setup();
    let mut w = s.w.clone();
    w.inp[R_REC] = r.input();
    tie_crafted(&s, &mut w, &t, slot);
}

// The record row's input as it stands is a leaf of the tree, its fields carried, every slot honest from those field
// values but the out-of-range field's own (honest for 0).
fn tie_crafted(s: &Setup, w: &mut W, t: &Thresholds, slot: usize) {
    let mut tree = s.tree.clone_tree();
    let index = tree.append(compress(&out(w, R_REC), &idc(&s.sk)));
    let f: [Val; NUM_FIELDS] = core::array::from_fn(|i| w.inp[R_REC][FIELD_POS[i]]);
    for row in 0..ROWS {
        w.field[row] = f;
    }
    set_thresholds(w, t);
    set_path(w, &tree, index);
    relink(w, 1);
    let fe = |i: usize| f[i];
    let pv = &w.pv.clone();
    let fails = fe(F_REJECTED) + fe(F_EXPIRED);
    let vals: [Val; NUM_RANGE] = {
        let mut v = [Val::ZERO; NUM_RANGE];
        v[K_COMPLETED] = fe(F_COMPLETED);
        v[K_CLIENTS] = fe(F_CLIENTS);
        for i in 0..AMOUNT_LIMBS {
            v[K_VOL + i] = fe(F_VOL + i);
            v[K_D_VOL + i] = fe(F_VOL + i) - pv[PV_MIN_VOL + i];
        }
        v[K_REJECTED] = fe(F_REJECTED);
        v[K_EXPIRED] = fe(F_EXPIRED);
        v[K_TIER] = fe(F_TIER);
        v[K_FIRST_DAY] = fe(F_FIRST_DAY);
        v[K_D_COMPLETED] = fe(F_COMPLETED) - pv[PV_MIN_COMPLETED];
        v[K_D_CLIENTS] = fe(F_CLIENTS) - pv[PV_MIN_CLIENTS];
        v[K_D_FAIL] = pv[PV_MAX_FAIL] * (fe(F_COMPLETED) + fails) - fails * Val::from_u32(PERMILLE) - Val::ONE;
        v[K_D_TIER] = fe(F_TIER) - pv[PV_MIN_TIER];
        v[K_D_DAY] = pv[PV_MAX_FIRST_DAY] - fe(F_FIRST_DAY);
        v
    };
    for row in 0..ROWS {
        w.borrow[row] = [Val::ZERO; AMOUNT_LIMBS - 1];
    }
    for k in 0..NUM_RANGE {
        let v = vals[k].as_canonical_u32();
        assert!(k == slot || v >> RANGE_BITS[k] == 0, "slot {k} must be honest");
        assert!(k != slot || v >> RANGE_BITS[k] != 0, "the crafted field is out of range");
        set_slot(w, k, if k == slot { Val::ZERO } else { vals[k] });
    }
    caught_by_one(w);
}

// rejected = -3 (P - 3) with 3 expired: no fail at all, a 1000-job record with 3 expiries passes a limit of 1 per mille.
#[test]
fn g11_rejected_negative() {
    let s = setup();
    let r = Record { completed: 1000, clients: 5, rejected: 0, expired: 3, ..own() };
    let mut w = s.w.clone();
    w.inp[R_REC] = r.input();
    w.inp[R_REC][S_REJECTED] = Val::ZERO - Val::from_u32(3);
    tie_crafted(&s, &mut w, &Thresholds { max_fail_permille: 1, ..low() }, K_REJECTED);
}

#[test]
fn g11_expired_negative() {
    let s = setup();
    let r = Record { completed: 1000, clients: 5, rejected: 3, expired: 0, ..own() };
    let mut w = s.w.clone();
    w.inp[R_REC] = r.input();
    w.inp[R_REC][S_EXPIRED] = Val::ZERO - Val::from_u32(3);
    tie_crafted(&s, &mut w, &Thresholds { max_fail_permille: 1, ..low() }, K_EXPIRED);
}

// firstDay 2^30 - 1 against a latest day of 0: the difference wraps to P - 2^30 + 1 < 2^30. (Why firstDay is 29 bits.)
#[test]
fn g11_first_day_wraps() {
    let s = setup();
    let r = own();
    let mut w = s.w.clone();
    w.inp[R_REC] = r.input();
    w.inp[R_REC][S_FIRST_DAY] = Val::from_u32((1 << 30) - 1);
    tie_crafted(&s, &mut w, &Thresholds { max_first_day: 0, ..low() }, K_FIRST_DAY);
}

// A count above the contract's clamp (2^19 - 1): 2^25 completed jobs pass a minimum of 2^25.
#[test]
fn g11_completed_above_clamp() {
    crafted(Record { completed: 1 << 25, ..own() }, Thresholds { min_completed: 1 << 25, max_fail_permille: 20, ..low() }, K_COMPLETED);
}

#[test]
fn g11_clients_above_clamp() {
    crafted(Record { clients: 1 << 25, ..own() }, Thresholds { min_clients: 1 << 25, ..low() }, K_CLIENTS);
}

// A tier that does not exist (5) passes a minimum of 3.
#[test]
fn g11_tier_above_three() {
    let s = setup();
    let r = own();
    let mut w = s.w.clone();
    w.inp[R_REC] = r.input();
    w.inp[R_REC][S_TIER] = Val::from_u32(5);
    tie_crafted(&s, &mut w, &Thresholds { min_tier: 3, ..low() }, K_TIER);
}

// A volume limb beyond 26 bits is refused (limb 2 = 2^26 + 3 fails its own slot). No cheat needs it: the borrow chain
// over limbs in (-2^26 - 2, 2^26] proves volume >= minVolume for the integer the limbs spell, and a limb outside that
// fails the chain. Kept as the spec range checks every limb (see the report).
#[test]
fn g11_volume_limb_refused() {
    let s = setup();
    let mut w = s.w.clone();
    w.inp[R_REC][S_VOL + 2] = Val::from_u32((1 << 26) + 3);
    let mut tree = s.tree.clone_tree();
    let index = tree.append(compress(&out(&w, R_REC), &idc(&s.sk)));
    let f: [Val; NUM_FIELDS] = core::array::from_fn(|i| w.inp[R_REC][FIELD_POS[i]]);
    for row in 0..ROWS {
        w.field[row] = f;
    }
    set_path(&mut w, &tree, index);
    relink(&mut w, 1);
    assert!(!holds(&w));
    assert!(!failing(&w).is_empty());
}

trait CloneTree {
    fn clone_tree(&self) -> Tree;
}

impl CloneTree for Tree {
    fn clone_tree(&self) -> Tree {
        let mut t = Tree::new();
        for l in &self.leaves {
            t.append(*l);
        }
        t
    }
}
