// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SpendConstants} from "./SpendConstants.sol";

// The base-field Poseidon2 permutation of the spend circuit (width 16 over KoalaBear, S-box x^3,
// 4 + 20 + 4 rounds, Plonky3's canonical round constants), the note hashes built on it, and the
// encodings the pool uses to talk to the spend verifier. Every function matches circuit/src/lib.rs
// (tested against vectors from Plonky3: test/NotesTest.t.sol).
//
// A digest is 8 field elements packed in a bytes32, element i in bits [32 i, 32 i + 32).
library Poseidon2 {
    uint256 internal constant P = 2130706433;

    // mds_light_permutation: M4 on each block of four, then every element plus the sum of its column;
    // reduced at the end (inputs canonical, so every value stays below 35 P).
    function externalLayer(uint256[16] memory s) private pure {
        assembly {
            for { let c := 0 } lt(c, 512) { c := add(c, 128) } {
                let p := add(s, c)
                let x0 := mload(p)
                let x1 := mload(add(p, 32))
                let x2 := mload(add(p, 64))
                let x3 := mload(add(p, 96))
                let t01 := add(x0, x1)
                let t23 := add(x2, x3)
                let t0123 := add(t01, t23)
                let t01123 := add(t0123, x1)
                let t01233 := add(t0123, x3)
                mstore(add(p, 96), add(t01233, add(x0, x0)))
                mstore(add(p, 32), add(t01123, add(x2, x2)))
                mstore(p, add(t01123, t01))
                mstore(add(p, 64), add(t01233, t23))
            }
            for { let k := 0 } lt(k, 128) { k := add(k, 32) } {
                let p := add(s, k)
                let sm := add(add(mload(p), mload(add(p, 128))), add(mload(add(p, 256)), mload(add(p, 384))))
                mstore(p, mod(add(mload(p), sm), 2130706433))
                mstore(add(p, 128), mod(add(mload(add(p, 128)), sm), 2130706433))
                mstore(add(p, 256), mod(add(mload(add(p, 256)), sm), 2130706433))
                mstore(add(p, 384), mod(add(mload(add(p, 384)), sm), 2130706433))
            }
        }
    }

    // Full round r: add the round constants, cube every element, external layer.
    function fullRound(uint256[16] memory s, uint256[64] memory rc, uint256 r) private pure {
        assembly {
            let q := 2130706433
            let rp := add(rc, shl(9, r))
            for { let i := 0 } lt(i, 512) { i := add(i, 32) } {
                let x := addmod(mload(add(s, i)), mload(add(rp, i)), q)
                mstore(add(s, i), mulmod(mulmod(x, x, q), x, q))
            }
        }
        externalLayer(s);
    }

    // Partial rounds: element 0 gets its constant and the S-box, then sum + V_i s_i for every element.
    function partialRounds(uint256[16] memory s, uint256[20] memory rc, uint256[16] memory dg) private pure {
        assembly {
            let q := 2130706433
            for { let r := 0 } lt(r, 20) { r := add(r, 1) } {
                let x := addmod(mload(s), mload(add(rc, shl(5, r))), q)
                mstore(s, mulmod(mulmod(x, x, q), x, q))
                let sum := 0
                for { let i := 0 } lt(i, 512) { i := add(i, 32) } {
                    sum := add(sum, mload(add(s, i)))
                }
                for { let i := 0 } lt(i, 512) { i := add(i, 32) } {
                    mstore(add(s, i), addmod(sum, mulmod(mload(add(s, i)), mload(add(dg, i)), q), q))
                }
            }
        }
    }

    function permute(uint256[16] memory s) internal pure {
        externalLayer(s);
        uint256[64] memory rc = SpendConstants.rcInitial();
        for (uint256 r = 0; r < 4; r++) {
            fullRound(s, rc, r);
        }
        partialRounds(s, SpendConstants.rcPartial(), SpendConstants.internalDiag());
        rc = SpendConstants.rcFinal();
        for (uint256 r = 0; r < 4; r++) {
            fullRound(s, rc, r);
        }
    }

    // P(l || r)[0..8], Plonky3's TruncatedPermutation.
    function compress(bytes32 l, bytes32 r) internal pure returns (bytes32) {
        uint256[16] memory s;
        for (uint256 i = 0; i < 8; i++) {
            s[i] = (uint256(l) >> (32 * i)) & 0xffffffff;
            s[8 + i] = (uint256(r) >> (32 * i)) & 0xffffffff;
        }
        permute(s);
        return pack(s);
    }

    function pack(uint256[16] memory s) internal pure returns (bytes32 d) {
        uint256 v;
        for (uint256 i = 0; i < 8; i++) {
            v |= s[i] << (32 * i);
        }
        d = bytes32(v);
    }

    // True when every element of a packed digest is canonical (below P).
    function isCanonical(bytes32 d) internal pure returns (bool) {
        for (uint256 i = 0; i < 8; i++) {
            if ((uint256(d) >> (32 * i)) & 0xffffffff >= P) return false;
        }
        return true;
    }
}

library Notes {
    uint256 internal constant P = 2130706433;
    uint256 internal constant AMOUNT_BITS = 26;
    uint256 internal constant ASSET_BITS = 27;

    // An amount below 2^128 as five 26-bit limbs, limb 0 lowest.
    function amountLimbs(uint256 a) internal pure returns (uint256[5] memory l) {
        require(a >> 128 == 0, "amount too large");
        for (uint256 i = 0; i < 5; i++) {
            l[i] = (a >> (AMOUNT_BITS * i)) & ((1 << AMOUNT_BITS) - 1);
        }
    }

    // An address as six 27-bit limbs, limb 0 lowest.
    function assetLimbs(address asset) internal pure returns (uint256[6] memory l) {
        uint256 a = uint256(uint160(asset));
        for (uint256 i = 0; i < 6; i++) {
            l[i] = (a >> (ASSET_BITS * i)) & ((1 << ASSET_BITS) - 1);
        }
    }

    // P(asset || amount || 0)[0..8].
    function value(address asset, uint256 amount) internal pure returns (bytes32) {
        uint256[16] memory s;
        uint256[6] memory a = assetLimbs(asset);
        uint256[5] memory m = amountLimbs(amount);
        for (uint256 i = 0; i < 6; i++) s[i] = a[i];
        for (uint256 i = 0; i < 5; i++) s[6 + i] = m[i];
        Poseidon2.permute(s);
        return Poseidon2.pack(s);
    }

    // The commitment of a note of amount of asset owned by tag (tag = P(rho || sk)[0..8]).
    function commitment(address asset, uint256 amount, bytes32 tag) internal pure returns (bytes32) {
        require(Poseidon2.isCanonical(tag), "tag not canonical");
        return Poseidon2.compress(value(asset, amount), tag);
    }

    // The 8 binding values of a spend from a keccak-256 hash of its call: element i is bits
    // [32 i, 32 i + 30) of the hash read as a big-endian integer (each below 2^30 < P).
    function bindOf(bytes32 h) internal pure returns (uint256[8] memory b) {
        for (uint256 i = 0; i < 8; i++) {
            b[i] = (uint256(h) >> (32 * i)) & 0x3fffffff;
        }
    }

    // The 48 public values of a spend, in the circuit's order: asset (6), v (5), fee (5),
    // nullifier (8), root (8), change commitment (8), bind (8).
    function publicValues(
        address asset,
        uint256 v,
        uint256 fee,
        bytes32 nullifier,
        bytes32 root,
        bytes32 changeCommitment,
        bytes32 bindHash
    ) internal pure returns (uint256[48] memory pv) {
        uint256[6] memory a = assetLimbs(asset);
        for (uint256 i = 0; i < 6; i++) pv[i] = a[i];
        uint256[5] memory l = amountLimbs(v);
        for (uint256 i = 0; i < 5; i++) pv[6 + i] = l[i];
        l = amountLimbs(fee);
        for (uint256 i = 0; i < 5; i++) pv[11 + i] = l[i];
        for (uint256 i = 0; i < 8; i++) {
            pv[16 + i] = (uint256(nullifier) >> (32 * i)) & 0xffffffff;
            pv[24 + i] = (uint256(root) >> (32 * i)) & 0xffffffff;
            pv[32 + i] = (uint256(changeCommitment) >> (32 * i)) & 0xffffffff;
        }
        uint256[8] memory b = bindOf(bindHash);
        for (uint256 i = 0; i < 8; i++) pv[40 + i] = b[i];
    }
}

// The append-only commitment tree of the pool: depth 20, empty leaves zero, nodes P(left || right).
// A commitment enters at most once: the nullifier is P(rho || commitment), so two identical notes would
// share one nullifier and one of them could never be spent.
library CommitmentTree {
    uint256 internal constant DEPTH = 20;

    struct Tree {
        uint256 count;
        bytes32[20] filled;
        mapping(bytes32 => bool) known;
    }

    // Roots of empty subtrees: zeros(0) is the empty leaf, zeros(k + 1) = P(zeros(k) || zeros(k)).
    function zeros(uint256 k) internal pure returns (bytes32) {
        return SpendConstants.emptyRoots()[k];
    }

    // Appends a leaf and returns its index and the new root.
    function insert(Tree storage t, bytes32 leaf) internal returns (uint256 index, bytes32 root) {
        index = t.count;
        require(index < (1 << DEPTH), "tree full");
        require(Poseidon2.isCanonical(leaf), "leaf not canonical");
        require(!t.known[leaf], "commitment exists");
        t.known[leaf] = true;
        bytes32[21] memory z = SpendConstants.emptyRoots();
        bytes32 node = leaf;
        uint256 i = index;
        for (uint256 k = 0; k < DEPTH; k++) {
            if (i & 1 == 0) {
                t.filled[k] = node;
                node = Poseidon2.compress(node, z[k]);
            } else {
                node = Poseidon2.compress(t.filled[k], node);
            }
            i >>= 1;
        }
        t.count = index + 1;
        root = node;
    }
}
