use ostra_swap_circuit::*;
use p3_field::PrimeCharacteristicRing;

fn digest(n: u32) -> Digest {
    core::array::from_fn(|i| Val::from_u32(n.wrapping_mul(2654435761).wrapping_add(i as u32 * 7919) % 2130706433))
}

/// A tree with a few notes and a spend of one of them.
pub fn sample(amount: u128, v: u128, fee: u128, position: usize) -> Spend {
    let asset = [0x11u8; 20];
    let sk = digest(1);
    let rho = digest(2);
    let mut tree = Tree::new();
    let mine = commitment(&value_digest(&asset_limbs(&asset), &amount_limbs(amount)), &tag(&sk, &rho));
    for i in 0..position {
        tree.append(digest(100 + i as u32));
    }
    let index = tree.append(mine);
    tree.append(digest(999));
    let s = Spend { sk, rho, asset, amount, index, path: tree.path(index), v, fee, change_tag: digest(3), bind: digest(4) };
    assert_eq!(s.root(), tree.root());
    s
}

#[test]
fn proves_and_verifies() {
    for (amount, v, fee, pos) in [(1_000_000u128, 600_000u128, 1_000u128, 0usize), (u128::MAX, u128::MAX - 5, 5, 3), (77, 0, 0, 2)] {
        let s = sample(amount, v, fee, pos);
        let (proof, pv) = prove(&s, test_seed(1)).unwrap();
        assert!(verify(&proof, &pv), "valid spend verifies");
        for k in [PV_ASSET, PV_V, PV_FEE + 2, PV_NF + 7, PV_ROOT, PV_CHANGE + 3, PV_BIND + 5] {
            let mut bad = pv.clone();
            bad[k] += Val::ONE;
            assert!(!verify(&proof, &bad), "changed public value {k} rejects");
        }
        println!("degree_bits {} quotient chunks {}", proof.degree_bits, proof.opened_values.quotient_chunks.len());
    }
}

// Two notes under one tag (same sk and rho) but different amounts: different nullifiers.
#[test]
fn one_tag_two_notes_two_nullifiers() {
    let a = asset_limbs(&[0x33u8; 20]);
    let (sk, rho) = (digest(11), digest(12));
    let t = tag(&sk, &rho);
    let c1 = commitment(&value_digest(&a, &amount_limbs(100)), &t);
    let c2 = commitment(&value_digest(&a, &amount_limbs(5_000_000)), &t);
    assert_ne!(nullifier(&rho, &c1), nullifier(&rho, &c2));
}

#[test]
fn overdraw_is_refused() {
    let s = sample(100, 90, 11, 0);
    assert!(s.trace().is_err());
}

#[test]
fn permutation_matches_plonky3() {
    use p3_symmetric::Permutation;
    let perm = p3_koala_bear::default_koalabear_poseidon2_16();
    let input: [Val; 16] = core::array::from_fn(|i| Val::from_u32(i as u32 * 12345 + 1));
    assert_eq!(permute(input), perm.permute(input));
}
