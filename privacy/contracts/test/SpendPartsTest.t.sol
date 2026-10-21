// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SpendVerifier, Poseidon2Fold} from "../src/SpendVerifier.sol";
import {KB8} from "../src/KB8.sol";
import {SpendPartsVectors as V} from "./SpendPartsVectors.sol";

// Exposes the verifier's constraint parts to compare them with Plonky3's own code
// (tools/src/bin/spend.rs): periodic selectors and row selectors at zeta, the folded constraints on
// random openings, and the quotient recomposition.
contract SpendHarness is SpendVerifier {
    function selectorsAt(uint256 zeta) public view returns (uint256[8] memory per, uint256 first, uint256 trans) {
        Ctx memory c;
        c.zeta = zeta;
        c.zp = KB8.pow2k(zeta, LOG_ROWS);
        Fold memory f;
        selectors(c, f);
        return (f.per, f.first, f.trans);
    }

    function foldAt(uint256[192] calldata local, uint256[192] calldata next, uint256[48] calldata pv, uint256 zeta, uint256 alpha)
        external
        view
        returns (uint256)
    {
        Ctx memory c;
        c.zeta = zeta;
        c.zp = KB8.pow2k(zeta, LOG_ROWS);
        Fold memory f;
        selectors(c, f);
        uint256 a;
        uint256 b;
        assembly {
            a := local
            b := next
        }
        f.tl = a;
        f.tn = b;
        f.alpha = alpha;
        f.pv = new uint256[](48);
        for (uint256 i = 0; i < 48; i++) f.pv[i] = pv[i];
        f.acc = Poseidon2Fold.fold(f.tl, alpha);
        extras(f);
        return f.acc;
    }

    // blob holds the 64 quotient-chunk coefficients at the proof offset O_QC.
    function quotientOf(bytes calldata blob, uint256 zeta) external pure returns (uint256) {
        Ctx memory c;
        uint256 a;
        assembly {
            a := blob.offset
        }
        c.base = a;
        c.zp = KB8.pow2k(zeta, LOG_ROWS);
        return quotientAtZeta(c);
    }

    function chunkOffset() external pure returns (uint256) {
        return O_QC;
    }
}

contract SpendPartsTest {
    SpendHarness h = new SpendHarness();

    function selectorsMatch(uint256 zeta, uint256[8] memory per, uint256 first, uint256 trans) internal view {
        (uint256[8] memory p, uint256 f, uint256 t) = h.selectorsAt(zeta);
        for (uint256 i = 0; i < 8; i++) require(p[i] == per[i], "periodic selector differs");
        require(f == first, "is_first_row differs");
        require(t == trans, "is_transition differs");
    }

    function testSelectors() public view {
        selectorsMatch(V.ZETA_0, V.periodic0(), V.FIRST_0, V.TRANSITION_0);
        selectorsMatch(V.ZETA_1, V.periodic1(), V.FIRST_1, V.TRANSITION_1);
        selectorsMatch(V.ZETA_2, V.periodic2(), V.FIRST_2, V.TRANSITION_2);
    }

    function testFold0() public view {
        require(h.foldAt(V.local0(), V.next0(), V.publics0(), V.ZETA_0, V.ALPHA_0) == V.FOLD_0, "fold differs");
    }

    function testFold1() public view {
        require(h.foldAt(V.local1(), V.next1(), V.publics1(), V.ZETA_1, V.ALPHA_1) == V.FOLD_1, "fold differs");
    }

    function testFold2() public view {
        require(h.foldAt(V.local2(), V.next2(), V.publics2(), V.ZETA_2, V.ALPHA_2) == V.FOLD_2, "fold differs");
    }

    function testQuotient() public view {
        uint256[64] memory ch = V.chunks();
        uint256 o = h.chunkOffset();
        bytes memory blob = new bytes(o + 64 * 32);
        for (uint256 i = 0; i < 64; i++) {
            uint256 v = ch[i];
            assembly {
                mstore(add(add(blob, 32), add(o, mul(32, i))), v)
            }
        }
        require(h.quotientOf(blob, V.QZETA) == V.QUOTIENT, "quotient differs");
    }

    // Halving and quartering constants used by the FRI folds.
    function testHalves() public pure {
        uint256 p = 2130706433;
        require(mulmod(2, (p + 1) / 2, p) == 1 && mulmod(4, (3 * p + 1) / 4, p) == 1, "inverse constants");
    }
}
