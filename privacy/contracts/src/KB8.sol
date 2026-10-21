// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Arithmetic in the degree-8 binomial extension of KoalaBear (x^8 = 3, P = 2^31 - 2^24 + 1) on packed
// elements: one uint256 holds the 8 coefficients, coefficient i in bits [32 i, 32 i + 32). Every
// coefficient is canonical (below P) on input and on output; the verifier range-checks every element
// it reads from a proof (isCanonical).
//
// add, sub and isCanonical work on all lanes at once: the even and the odd lanes are split into
// 64-bit fields, so a lane sum (below 2^32) and the test "lane >= P" (bit 32 of lane + 2^32 - P) have
// room. mulBase puts two coefficients in one word, 128 bits apart, so one MUL forms two products
// (each below 2^62) without the halves overlapping; mul uses Kronecker substitution (see mul). The mul, frob1,
// frob2 and frob4 bodies are generated; Ext8.mul is the reference for mul, and the Frobenius constants
// zeta8^(i k), zeta8 = 3^((P - 1) / 8), come from StarkConstants.frobenius().
library KB8 {
    uint256 internal constant P = 2130706433;

    function isCanonical(uint256 a) internal pure returns (bool ok) {
        assembly {
            let E := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            let C := 0x0000000080ffffff0000000080ffffff0000000080ffffff0000000080ffffff
            ok := iszero(and(or(add(and(a, E), C), add(and(shr(32, a), E), C)), 0x0000000100000000000000010000000000000001000000000000000100000000))
        }
    }

    function add(uint256 a, uint256 b) internal pure returns (uint256 r) {
        assembly {
            let E := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            let C := 0x0000000080ffffff0000000080ffffff0000000080ffffff0000000080ffffff
            let se := add(and(a, E), and(b, E))
            let so := add(and(shr(32, a), E), and(shr(32, b), E))
            se := sub(se, mul(and(shr(32, add(se, C)), 0x0000000000000001000000000000000100000000000000010000000000000001), 2130706433))
            so := sub(so, mul(and(shr(32, add(so, C)), 0x0000000000000001000000000000000100000000000000010000000000000001), 2130706433))
            r := or(se, shl(32, so))
        }
    }

    // a + (P - b) lane-wise: P - b_i lies in [1, P], so the lane sums stay below 2P and one
    // conditional subtraction makes them canonical.
    function sub(uint256 a, uint256 b) internal pure returns (uint256 r) {
        assembly {
            let E := 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff
            let C := 0x0000000080ffffff0000000080ffffff0000000080ffffff0000000080ffffff
            let nb := sub(0x7f0000017f0000017f0000017f0000017f0000017f0000017f0000017f000001, b)
            let se := add(and(a, E), and(nb, E))
            let so := add(and(shr(32, a), E), and(shr(32, nb), E))
            se := sub(se, mul(and(shr(32, add(se, C)), 0x0000000000000001000000000000000100000000000000010000000000000001), 2130706433))
            so := sub(so, mul(and(shr(32, add(so, C)), 0x0000000000000001000000000000000100000000000000010000000000000001), 2130706433))
            r := or(se, shl(32, so))
        }
    }

    // a + c for a base element c.
    function addBase(uint256 a, uint256 c) internal pure returns (uint256 r) {
        assembly {
            r := or(and(a, not(0xffffffff)), addmod(and(a, 0xffffffff), c, 2130706433))
        }
    }

    // a - c for a base element c.
    function subBase(uint256 a, uint256 c) internal pure returns (uint256 r) {
        assembly {
            let q := 2130706433
            r := or(and(a, not(0xffffffff)), addmod(and(a, 0xffffffff), sub(q, c), q))
        }
    }

    function mulBase(uint256 a, uint256 c) internal pure returns (uint256 r) {
        assembly {
            let pr := 0
            pr := mul(or(and(a, 0xffffffff), shl(128, and(shr(128, a), 0xffffffff))), c)
            r := or(r, or(mod(and(pr, 0xffffffffffffffffffffffffffffffff), 2130706433), shl(128, mod(shr(128, pr), 2130706433))))
            pr := mul(or(and(shr(32, a), 0xffffffff), shl(128, and(shr(160, a), 0xffffffff))), c)
            r := or(r, or(shl(32, mod(and(pr, 0xffffffffffffffffffffffffffffffff), 2130706433)), shl(160, mod(shr(128, pr), 2130706433))))
            pr := mul(or(and(shr(64, a), 0xffffffff), shl(128, and(shr(192, a), 0xffffffff))), c)
            r := or(r, or(shl(64, mod(and(pr, 0xffffffffffffffffffffffffffffffff), 2130706433)), shl(192, mod(shr(128, pr), 2130706433))))
            pr := mul(or(and(shr(96, a), 0xffffffff), shl(128, shr(224, a))), c)
            r := or(r, or(shl(96, mod(and(pr, 0xffffffffffffffffffffffffffffffff), 2130706433)), shl(224, mod(shr(128, pr), 2130706433))))
        }
    }

    // Kronecker substitution, two coefficients per number: A_p = a_(2p) + a_(2p+1) X and B_q likewise
    // with X = 2^68, so A_p B_q = a b + (a b' + a' b) X + a' b' X^2 carries three coefficients of the
    // product in fields of 68 bits. S_s = sum over p + q = s holds coefficients 2s, 2s + 1, 2s + 2;
    // with x^8 = 3, T_s = S_s + 3 S_(s+4) for s < 3, and every field stays below 2^67.
    //   r0 = T0.f0 + 3 S3.f2   r1 = T0.f1   r2 = T1.f0 + T0.f2   r3 = T1.f1
    //   r4 = T2.f0 + T1.f2     r5 = T2.f1   r6 = S3.f0 + T2.f2   r7 = S3.f1
    function mul(uint256 a, uint256 b) internal pure returns (uint256 r) {
        assembly {
            let A0 := or(and(a, 0xffffffff), shl(68, and(shr(32, a), 0xffffffff)))
            let A1 := or(and(shr(64, a), 0xffffffff), shl(68, and(shr(96, a), 0xffffffff)))
            let A2 := or(and(shr(128, a), 0xffffffff), shl(68, and(shr(160, a), 0xffffffff)))
            let A3 := or(and(shr(192, a), 0xffffffff), shl(68, and(shr(224, a), 0xffffffff)))
            let B0 := or(and(b, 0xffffffff), shl(68, and(shr(32, b), 0xffffffff)))
            let B1 := or(and(shr(64, b), 0xffffffff), shl(68, and(shr(96, b), 0xffffffff)))
            let B2 := or(and(shr(128, b), 0xffffffff), shl(68, and(shr(160, b), 0xffffffff)))
            let B3 := or(and(shr(192, b), 0xffffffff), shl(68, and(shr(224, b), 0xffffffff)))
            let s3 := add(add(add(mul(A0, B3), mul(A1, B2)), mul(A2, B1)), mul(A3, B0))
            let t := add(mul(A0, B0), mul(3, add(add(mul(A1, B3), mul(A2, B2)), mul(A3, B1))))
            r := or(mod(add(and(t, 0xfffffffffffffffff), mul(3, shr(136, s3))), 2130706433), shl(32, mod(and(shr(68, t), 0xfffffffffffffffff), 2130706433)))
            let carry := shr(136, t)
            t := add(add(mul(A0, B1), mul(A1, B0)), mul(3, add(mul(A2, B3), mul(A3, B2))))
            r := or(r, or(shl(64, mod(add(and(t, 0xfffffffffffffffff), carry), 2130706433)), shl(96, mod(and(shr(68, t), 0xfffffffffffffffff), 2130706433))))
            carry := shr(136, t)
            t := add(add(add(mul(A0, B2), mul(A1, B1)), mul(A2, B0)), mul(3, mul(A3, B3)))
            r := or(r, or(shl(128, mod(add(and(t, 0xfffffffffffffffff), carry), 2130706433)), shl(160, mod(and(shr(68, t), 0xfffffffffffffffff), 2130706433))))
            carry := shr(136, t)
            r := or(r, or(shl(192, mod(add(and(s3, 0xfffffffffffffffff), carry), 2130706433)), shl(224, mod(and(shr(68, s3), 0xfffffffffffffffff), 2130706433))))
        }
    }

    // a^(2^k).
    function pow2k(uint256 a, uint256 k) internal pure returns (uint256 r) {
        r = a;
        for (uint256 i = 0; i < k; i++) {
            r = mul(r, r);
        }
    }

    function frob1(uint256 a) internal pure returns (uint256 r) {
        assembly {
            let q := 2130706433
            let M := 0xffffffff
            r := and(a, M)
            r := or(r, shl(32, mulmod(and(shr(32, a), M), 1748172362, q)))
            r := or(r, shl(64, mulmod(and(shr(64, a), M), 2113994754, q)))
            r := or(r, shl(96, mulmod(and(shr(96, a), M), 391001680, q)))
            r := or(r, shl(128, mulmod(and(shr(128, a), M), 2130706432, q)))
            r := or(r, shl(160, mulmod(and(shr(160, a), M), 382534071, q)))
            r := or(r, shl(192, mulmod(and(shr(192, a), M), 16711679, q)))
            r := or(r, shl(224, mulmod(and(shr(224, a), M), 1739704753, q)))
        }
    }

    function frob2(uint256 a) internal pure returns (uint256 r) {
        assembly {
            let q := 2130706433
            let M := 0xffffffff
            r := and(a, M)
            r := or(r, shl(32, mulmod(and(shr(32, a), M), 2113994754, q)))
            r := or(r, shl(64, mulmod(and(shr(64, a), M), 2130706432, q)))
            r := or(r, shl(96, mulmod(and(shr(96, a), M), 16711679, q)))
            r := or(r, shl(128, and(shr(128, a), M)))
            r := or(r, shl(160, mulmod(and(shr(160, a), M), 2113994754, q)))
            r := or(r, shl(192, mulmod(and(shr(192, a), M), 2130706432, q)))
            r := or(r, shl(224, mulmod(and(shr(224, a), M), 16711679, q)))
        }
    }

    function frob4(uint256 a) internal pure returns (uint256 r) {
        assembly {
            let q := 2130706433
            let M := 0xffffffff
            r := and(a, M)
            r := or(r, shl(32, mulmod(and(shr(32, a), M), 2130706432, q)))
            r := or(r, shl(64, and(shr(64, a), M)))
            r := or(r, shl(96, mulmod(and(shr(96, a), M), 2130706432, q)))
            r := or(r, shl(128, and(shr(128, a), M)))
            r := or(r, shl(160, mulmod(and(shr(160, a), M), 2130706432, q)))
            r := or(r, shl(192, and(shr(192, a), M)))
            r := or(r, shl(224, mulmod(and(shr(224, a), M), 2130706432, q)))
        }
    }

    // Base-field inverse by Fermat (c^(P - 2)) through the modexp precompile; c must be non-zero.
    function invBase(uint256 c) internal view returns (uint256 r) {
        require(c != 0 && c < P, "invert zero");
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 32)
            mstore(add(ptr, 32), 32)
            mstore(add(ptr, 64), 32)
            mstore(add(ptr, 96), c)
            mstore(add(ptr, 128), 2130706431)
            mstore(add(ptr, 160), 2130706433)
            if iszero(staticcall(gas(), 0x05, ptr, 192, ptr, 32)) { revert(0, 0) }
            r := mload(ptr)
        }
    }

    // a^-1 = r / N(a) with r = phi(a) phi^2(a) ... phi^7(a) and N(a) = a r in the base field, phi the
    // Frobenius map. a must be non-zero.
    function inv(uint256 a) internal view returns (uint256) {
        uint256 x1 = frob1(a);
        uint256 y = mul(a, x1);
        uint256 y2 = frob2(y);
        uint256 z = mul(x1, y2);
        uint256 w = mul(y, y2);
        uint256 r = mul(z, frob4(w));
        uint256 n = mul(a, r);
        require(n >> 32 == 0, "norm outside the base field");
        return mulBase(r, invBase(n));
    }
}
