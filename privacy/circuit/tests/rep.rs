// The reputation circuit: honest proofs, boundary values, the scope pin, and the verifier's checks.
use std::time::Instant;

use ostra_swap_circuit::rep::*;
use ostra_swap_circuit::{Digest, ROWS, Tree, Val, api, bind_from_hash, flat, test_seed};
use p3_air::symbolic::{AirLayout, get_max_constraint_degree};
use p3_field::{PrimeCharacteristicRing, PrimeField32};

fn digest(n: u32) -> Digest {
    core::array::from_fn(|i| Val::from_u32(n.wrapping_mul(2654435761).wrapping_add(i as u32 * 7919) % 2130706433))
}

fn record(completed: u32, clients: u32, volume: u128, rejected: u32, expired: u32, tier: u32, first_day: u32) -> Record {
    Record { completed, clients, volume, rejected, expired, tier, first_day, epoch: 7 }
}

fn met_by(r: &Record) -> Thresholds {
    Thresholds {
        min_completed: r.completed,
        min_clients: r.clients,
        min_volume: r.volume,
        max_fail_permille: PERMILLE,
        min_tier: r.tier,
        max_first_day: r.first_day,
    }
}

/// A tree with a few other leaves and this agent's leaf at `position`.
fn sample(r: Record, t: Thresholds, position: usize) -> Rep {
    let sk = digest(1);
    let mut tree = Tree::new();
    for i in 0..position {
        tree.append(digest(100 + i as u32));
    }
    let index = tree.append(r.leaf(&idc(&sk)));
    tree.append(digest(999));
    let rep = Rep { sk, record: r, index, path: tree.path(index), scope: scope_elements(&[0x5c; 32]), thresholds: t, bind: digest(4) };
    assert_eq!(rep.root(), tree.root());
    rep
}

fn holds(rep: &Rep) -> bool {
    let t = rep.trace().unwrap();
    let pv = rep.public_values();
    let hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let ok = std::panic::catch_unwind(|| p3_air::check_constraints(&RepAir::new(), &t, &pv)).is_ok();
    std::panic::set_hook(hook);
    ok
}

#[test]
fn degree_is_three() {
    let air = RepAir::new();
    let d = get_max_constraint_degree::<Val, _>(&air, AirLayout::from_air::<Val>(&air), ROWS);
    println!("symbolic max constraint degree {d}, width {REP_WIDTH}, public values {REP_PUBLIC}");
    assert!(d <= 3);
}

#[test]
fn proves_and_verifies() {
    let r = record(12, 6, 150_000_000, 1, 0, 1, 3);
    let t = Thresholds { min_completed: 10, min_clients: 5, min_volume: 100_000_000, max_fail_permille: 200, min_tier: 1, max_first_day: 30 };
    for pos in [0usize, 5] {
        let s = sample(r, t, pos);
        let start = Instant::now();
        let (proof, pv) = prove_rep(&s, test_seed(1)).unwrap();
        let took = start.elapsed();
        assert!(verify_rep(&proof, &pv), "valid proof verifies");
        let f = flat::encode_width(&proof, REP_WIDTH);
        let back = flat::decode_width(&f, REP_WIDTH).unwrap();
        assert!(verify_rep(&back, &pv), "the flat layout round-trips");
        println!("prove {:?}, flat proof {} bytes, degree_bits {}", took, f.len(), proof.degree_bits);
        for k in [PV_ROOT, PV_PSEUDO + 3, PV_SCOPE + 1, PV_BIND + 7, PV_EPOCH, PV_MIN_COMPLETED, PV_MIN_CLIENTS, PV_MIN_VOL + 2, PV_MAX_FAIL, PV_MIN_TIER, PV_MAX_FIRST_DAY] {
            let mut bad = pv.clone();
            bad[k] += Val::ONE;
            assert!(!verify_rep_proof(&proof, &bad), "changed public value {k} rejects");
        }
    }
}

// Every field at the widest value the contract writes, every threshold met with equality.
#[test]
fn boundaries_prove() {
    let r = Record {
        completed: (1 << 19) - 1,
        clients: (1 << 19) - 1,
        volume: u128::MAX,
        rejected: (1 << 16) - 1,
        expired: (1 << 16) - 1,
        tier: 3,
        first_day: (1 << 29) - 1,
        epoch: 2_000_000,
    };
    let mut t = met_by(&r);
    t.max_first_day = (1 << 29) - 1;
    // f = 131070 of T = 655357: 199.997 per mille, below 200.
    t.max_fail_permille = 200;
    assert!(fail_margin(&r, &t) >= 0);
    let s = sample(r, t, 3);
    let (proof, pv) = prove_rep(&s, test_seed(2)).unwrap();
    assert!(verify_rep(&proof, &pv));
    // 199 per mille is below the record's ratio.
    t.max_fail_permille = 199;
    assert_eq!(sample(r, t, 3).trace().unwrap_err(), RepError::NotMet);
}

#[test]
fn equality_at_every_threshold_holds() {
    let r = record(50, 20, 1_000_000_000, 2, 3, 2, 17);
    let mut t = met_by(&r);
    // 5 fails of 55: 90.9 per mille; 91 is the least limit it is below.
    t.max_fail_permille = 91;
    assert!(holds(&sample(r, t, 1)));
    for (k, bump) in [(0, 1u32), (1, 1), (3, 1), (4, 1), (5, 1)] {
        let mut u = t;
        match k {
            0 => u.min_completed += bump,
            1 => u.min_clients += bump,
            3 => u.max_fail_permille -= bump,
            4 => u.min_tier += bump,
            _ => u.max_first_day -= bump,
        }
        assert_eq!(sample(r, u, 1).trace().unwrap_err(), RepError::NotMet, "threshold {k} one step beyond");
    }
    let mut u = t;
    u.min_volume += 1;
    assert_eq!(sample(r, u, 1).trace().unwrap_err(), RepError::NotMet);
}

#[test]
fn volume_limbs_at_max_and_borrows() {
    // Volumes whose comparison borrows through several limbs, and limbs at their maximum.
    let cases: [(u128, u128); 4] = [
        (u128::MAX, u128::MAX),
        (u128::MAX, 0),
        ((1u128 << 104) + 5, (1u128 << 104) - 1),
        ((1u128 << 78) | ((1 << 26) - 1), (1u128 << 52) | ((1 << 26) - 1)),
    ];
    for (vol, min) in cases {
        let r = record(1, 1, vol, 0, 0, 0, 0);
        let mut t = met_by(&r);
        t.min_volume = min;
        assert!(holds(&sample(r, t, 0)), "volume {vol} >= {min}");
    }
    let r = record(1, 1, 1u128 << 104, 0, 0, 0, 0);
    let mut t = met_by(&r);
    t.min_volume = (1u128 << 104) + 1;
    assert_eq!(sample(r, t, 0).trace().unwrap_err(), RepError::NotMet);
}

#[test]
fn fail_limits_zero_and_thousand() {
    let r = record(1, 1, 1_000_000, 0, 0, 0, 0);
    let mut t = met_by(&r);
    // 0 per mille: nothing is below it.
    t.max_fail_permille = 0;
    assert_eq!(sample(r, t, 0).trace().unwrap_err(), RepError::NotMet);
    // 1000: any record with a completed job.
    t.max_fail_permille = 1000;
    assert!(holds(&sample(r, t, 0)));
    let bad = record(1, 1, 1_000_000, 900, 99, 0, 0);
    let mut u = met_by(&bad);
    u.max_fail_permille = 1000;
    assert!(holds(&sample(bad, u, 0)));
    // No completed job: no fail ratio is below any limit (strict).
    let none = record(0, 0, 0, 0, 3, 0, 0);
    let mut u = met_by(&none);
    u.max_fail_permille = 1000;
    assert_eq!(sample(none, u, 0).trace().unwrap_err(), RepError::NotMet);
    let empty = record(0, 0, 0, 0, 0, 0, 0);
    assert_eq!(sample(empty, u, 0).trace().unwrap_err(), RepError::NotMet);
}

#[test]
fn out_of_range_inputs_are_refused() {
    let r = record(1 << 19, 1, 1, 0, 0, 0, 0);
    assert_eq!(sample(r, met_by(&r), 0).trace().unwrap_err(), RepError::FieldOutOfRange);
    let r = record(1, 1, 1, 1 << 16, 0, 0, 0);
    let mut t = met_by(&r);
    t.max_fail_permille = 1000;
    assert_eq!(sample(r, t, 0).trace().unwrap_err(), RepError::FieldOutOfRange);
    let r = record(1, 1, 1, 0, 0, 4, 0);
    assert_eq!(sample(r, met_by(&r), 0).trace().unwrap_err(), RepError::FieldOutOfRange);
    let r = record(1, 1, 1, 0, 0, 0, 1 << 29);
    assert_eq!(sample(r, met_by(&r), 0).trace().unwrap_err(), RepError::FieldOutOfRange);
    let r = record(1, 1, 1, 0, 0, 0, 0);
    for bad in [
        Thresholds { min_completed: 1 << 29, ..met_by(&r) },
        Thresholds { min_clients: 1 << 29, ..met_by(&r) },
        Thresholds { max_first_day: 1 << 29, ..met_by(&r) },
        Thresholds { max_fail_permille: 1001, ..met_by(&r) },
        Thresholds { min_tier: 4, ..met_by(&r) },
    ] {
        assert_eq!(check_thresholds(&bad), Err(RepError::ThresholdOutOfRange));
    }
}

// The verifier refuses public thresholds outside their ranges, and a scope whose element 0 is not D_SCOPE.
#[test]
fn verifier_checks_publics() {
    let r = record(12, 6, 150_000_000, 1, 0, 1, 3);
    let mut t = met_by(&r);
    t.max_fail_permille = 1000;
    let s = sample(r, t, 0);
    let (proof, pv) = prove_rep(&s, test_seed(3)).unwrap();
    assert!(verify_rep(&proof, &pv));
    let mut bad = pv.clone();
    bad[PV_MAX_FAIL] = Val::from_u32(1001);
    assert!(!verify_rep(&proof, &bad));
    let mut bad = pv.clone();
    bad[PV_MIN_COMPLETED] = Val::from_u32(1 << 29);
    assert!(!verify_rep(&proof, &bad));
    let mut bad = pv.clone();
    bad[PV_MIN_VOL + 4] = Val::from_u32(1 << 24);
    assert!(!verify_rep(&proof, &bad));
}

// Without the verifier's bound on minCompleted the comparison would wrap: completed 0 against minCompleted
// 2^30 - 1 gives P - 2^30 + 1 < 2^30. The bound 2^29 makes every failing difference at least P - 2^29.
#[test]
fn threshold_bound_is_needed() {
    let p = Val::ORDER_U32 as u64;
    let wrapped = p - ((1u64 << 30) - 1);
    assert!(wrapped < 1 << 30, "an unbounded threshold wraps into range");
    assert!(p - (1u64 << 29) >= 1 << 30, "the bound keeps a failing difference out of range");
}

#[test]
fn wrong_scope_domain_is_rejected() {
    let r = record(12, 6, 150_000_000, 1, 0, 1, 3);
    let mut t = met_by(&r);
    t.max_fail_permille = 1000;
    let mut s = sample(r, t, 0);
    // A scope with the idc's domain would make the pseudonym the vault's public idc.
    let mut scope = [Val::ZERO; 8];
    scope[0] = Val::from_u32(D_IDC);
    s.scope = scope;
    assert_eq!(s.pseudonym(), s.idc());
    assert!(!holds(&s), "scope[0] != D_SCOPE accepted");
    // Any other element 0 is refused as well.
    s.scope = scope_elements(&[0x5c; 32]);
    s.scope[0] = Val::from_u32(D_SCOPE + 1);
    assert!(!holds(&s));
}

#[test]
fn pseudonym_idc_and_scopes_are_distinct() {
    let sk = digest(77);
    let a = scope_elements(&[1; 32]);
    let b = scope_elements(&[2; 32]);
    assert_eq!(a[0], Val::from_u32(D_SCOPE));
    assert_ne!(pseudonym(&sk, &a), idc(&sk));
    assert_ne!(pseudonym(&sk, &a), pseudonym(&sk, &b));
    assert_ne!(pseudonym(&sk, &a), pseudonym(&digest(78), &a));
    for x in &a[1..] {
        assert!(x.as_canonical_u32() < 1 << 30);
    }
    assert!(D_IDC != D_SCOPE && D_SCOPE != D_REC && D_IDC != D_REC);
    for d in [D_IDC, D_SCOPE, D_REC] {
        assert!(d >= 1 << 16 && d < 1 << 30);
    }
}

// The prover's JSON commands end to end.
#[test]
fn api_commands() {
    let sk = digest(1);
    let d = |x: &Digest| format!("[{}]", x.iter().map(|v| format!("\"{}\"", v.as_canonical_u32())).collect::<Vec<_>>().join(","));
    let id = api::run("rep-id", &format!("{{\"sk\":{}}}", d(&sk))).unwrap();
    assert!(id.contains(&d(&idc(&sk))));
    let r = record(12, 6, 150_000_000, 1, 0, 1, 3);
    let rj = format!(
        "{{\"completed\":{},\"clients\":\"{}\",\"volume\":\"{}\",\"rejected\":{},\"expired\":{},\"tier\":{},\"first_day\":{},\"epoch\":{}}}",
        r.completed, r.clients, r.volume, r.rejected, r.expired, r.tier, r.first_day, r.epoch
    );
    let out = api::run("rep-record", &format!("{{\"record\":{rj},\"idc\":{}}}", d(&idc(&sk)))).unwrap();
    assert!(out.contains(&d(&r.digest())) && out.contains(&d(&r.leaf(&idc(&sk)))));
    let s = sample(r, Thresholds { min_completed: 10, min_clients: 5, min_volume: 100_000_000, max_fail_permille: 200, min_tier: 1, max_first_day: 30 }, 2);
    let path = format!("[{}]", s.path.iter().map(d).collect::<Vec<_>>().join(","));
    let req = format!(
        "{{\"sk\":{},\"record\":{rj},\"epoch\":7,\"index\":{},\"path\":{path},\"root\":{},\"scope\":\"0x{}\",\"thresholds\":{{\"min_completed\":10,\"min_clients\":5,\"min_volume\":\"100000000\",\"max_fail_permille\":200,\"min_tier\":1,\"max_first_day\":30}},\"bind_hash\":\"0x{}\"}}",
        d(&sk), s.index, d(&s.root()), "5c".repeat(32), "ab".repeat(32)
    );
    let out = api::run("rep-prove", &req).unwrap();
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let pv: Vec<Val> = v["public_values"].as_array().unwrap().iter().map(|x| Val::from_u32(x.as_str().unwrap().parse().unwrap())).collect();
    assert_eq!(pv.len(), REP_PUBLIC);
    let hex = v["proof"].as_str().unwrap().strip_prefix("0x").unwrap();
    let bytes: Vec<u8> = (0..hex.len() / 2).map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap()).collect();
    let proof = flat::decode_width(&bytes, REP_WIDTH).unwrap();
    assert!(verify_rep(&proof, &pv));
    let mut want = s.clone();
    want.bind = bind_from_hash(&[0xab; 32]);
    assert_eq!(pv, want.public_values());
    // Thresholds the record misses, a wrong root, a record of another epoch: refused.
    assert!(api::run("rep-prove", &req.replace("\"min_completed\":10", "\"min_completed\":13")).is_err());
    assert!(api::run("rep-prove", &req.replace("\"epoch\":7,\"index\"", "\"epoch\":8,\"index\"")).is_err());
    assert!(api::run("rep-prove", &req.replace("\"max_fail_permille\":200", "\"max_fail_permille\":1001")).is_err());
}
