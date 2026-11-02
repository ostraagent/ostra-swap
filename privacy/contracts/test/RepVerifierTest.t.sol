// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {RepVerifier} from "../src/RepVerifier.sol";

interface Vm {
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

// End-to-end: the Solidity verifier accepts real Plonky3 reputation proofs, written in the flat layout by
// tools/src/bin/rep.rs (which also verified them natively), and rejects every tampered variant exactly
// where Plonky3 does.
contract RepVerifierTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 constant P = 2130706433;

    event VerifyGas(uint256 statement, uint256 proofBytes, uint256 gasUsed);

    RepVerifier verifier = new RepVerifier();

    function publics(uint256 n) internal view returns (uint256[43] memory pv) {
        bytes memory b = vm.readFileBinary(string.concat("test/data/rep_pub_", toString(n), ".bin"));
        require(b.length == 172, "43 values");
        for (uint256 i = 0; i < 43; i++) pv[i] = u(b, 4 * i, 4);
    }

    function proofOf(uint256 n) internal view returns (bytes memory) {
        return vm.readFileBinary(string.concat("test/data/rep_", toString(n), ".bin"));
    }

    function toString(uint256 n) internal pure returns (string memory) {
        bytes memory s = new bytes(1);
        s[0] = bytes1(uint8(48 + n));
        return string(s);
    }

    function check(uint256 n) internal {
        bytes memory p = proofOf(n);
        uint256[43] memory pv = publics(n);
        uint256 g0 = gasleft();
        bool ok = verifier.verify(p, pv);
        uint256 used = g0 - gasleft();
        emit VerifyGas(n, p.length, used);
        require(ok, "real proof rejected");
    }

    function testAcceptsStatement0() public {
        check(0);
    }

    function testAcceptsStatement1() public {
        check(1);
    }

    function testAcceptsStatement2() public {
        check(2);
    }

    function testAcceptsStatement3() public {
        check(3);
    }

    // Two of its queries open the same input leaf (tools/src/bin/rep.rs searched prover seeds).
    function testAcceptsDuplicateQueries() public view {
        bytes memory p = vm.readFileBinary("test/data/rep_dup.bin");
        require(verifier.verify(p, publics(0)), "duplicate-query proof rejected");
    }

    // The duplicate opening's row or salt changed in each input batch: rejected, as by Plonky3.
    function testTamperedDuplicate() public view {
        bytes memory base = vm.readFileBinary("test/data/rep_dup.bin");
        bytes memory cases = vm.readFileBinary("test/data/rep_tamper_dup.bin");
        uint256 at = 0;
        uint256 n = 0;
        while (at < cases.length) {
            Case memory k;
            (k, at) = readCase(cases, at);
            bytes memory p = copy(base, base.length, base.length);
            for (uint256 j = 0; j < k.len; j++) p[k.off + j] = cases[k.bytesAt + j];
            require(!verdict(p, publics(0)), "changed duplicate opening accepted");
            n++;
        }
        require(n == 6, "case count changed");
    }

    function verdict(bytes memory p, uint256[43] memory pv) internal view returns (bool) {
        try verifier.verify(p, pv) returns (bool ok) {
            return ok;
        } catch {
            return false;
        }
    }

    // A proof is bound to its own public values: another statement's values, or a value raised by P (the
    // same residue, non-canonical), are rejected; so are another bind, another scope and another epoch.
    function testPublicValuesBind() public view {
        bytes memory p = proofOf(0);
        require(!verdict(p, publics(1)), "other statement's public values accepted");
        uint256[43] memory pv = publics(0);
        pv[20] += P;
        require(!verdict(p, pv), "non-canonical public value accepted");
        pv = publics(0);
        pv[31] = P - 1 - pv[31];
        require(!verdict(p, pv), "changed bind accepted");
        pv = publics(0);
        pv[17] ^= 1;
        require(!verdict(p, pv), "changed scope accepted");
        pv = publics(0);
        pv[32] += 1;
        require(!verdict(p, pv), "changed epoch accepted");
    }

    function u(bytes memory d, uint256 p, uint256 n) internal pure returns (uint256 v) {
        for (uint256 k = 0; k < n; k++) v = (v << 8) | uint8(d[p + k]);
    }

    function copy(bytes memory src, uint256 n, uint256 len) internal pure returns (bytes memory dst) {
        dst = new bytes(len);
        assembly {
            let s := add(src, 32)
            let d := add(dst, 32)
            for { let i := 0 } lt(i, n) { i := add(i, 32) } {
                mstore(add(d, i), mload(add(s, i)))
            }
            mstore(add(d, n), 0)
        }
    }

    // Tampered variants (tools/src/bin/rep.rs): each carries Plonky3's verdict, or is marked by design
    // when the encoding has no Plonky3 counterpart. Op 3 raises one public value by one.
    struct Case {
        uint256 op;
        uint256 off;
        uint256 len;
        uint256 bytesAt;
        bool fromOracle;
        bool expected;
    }

    function readCase(bytes memory cases, uint256 at) internal pure returns (Case memory k, uint256 next) {
        k.op = uint8(cases[at]);
        k.off = u(cases, at + 1, 4);
        k.len = u(cases, at + 5, 2);
        k.bytesAt = at + 7;
        next = k.bytesAt + k.len + 2;
        k.fromOracle = uint8(cases[next - 2]) == 1;
        k.expected = uint8(cases[next - 1]) == 1;
    }

    function runCase(uint256 n, bytes memory base, bytes memory cases, Case memory k) internal view {
        uint256[43] memory pv = publics(n);
        bytes memory p;
        if (k.op == 1) {
            p = copy(base, k.off, k.off);
        } else if (k.op == 3) {
            p = base;
            pv[k.off] = (pv[k.off] + 1) % P;
        } else {
            p = copy(base, base.length, k.op == 2 ? base.length + k.len : base.length);
            for (uint256 j = 0; j < k.len; j++) p[k.off + j] = cases[k.bytesAt + j];
        }
        require(verdict(p, pv) == k.expected, "verdict differs from Plonky3");
    }

    // Cases [from, to) run here, so no single test exceeds the gas limit.
    function tampered(uint256 n, uint256 from, uint256 to) internal view returns (uint256 oracle, uint256 byDesign, uint256 total) {
        bytes memory base = proofOf(n);
        bytes memory cases = vm.readFileBinary(string.concat("test/data/rep_tamper_", toString(n), ".bin"));
        uint256 at = 0;
        while (at < cases.length) {
            Case memory k;
            (k, at) = readCase(cases, at);
            uint256 i = total++;
            if (i < from || i >= to) continue;
            runCase(n, base, cases, k);
            if (k.fromOracle) oracle++;
            else byDesign++;
        }
    }

    function testTampered0a() public view {
        tampered(0, 0, 19);
    }

    function testTampered0b() public view {
        tampered(0, 19, 38);
    }

    function testTampered0c() public view {
        tampered(0, 38, 57);
    }

    function testTampered0d() public view {
        (uint256 oracle, uint256 byDesign, uint256 total) = tampered(0, 57, 1000);
        require(total == 75 && oracle + byDesign == 18, "case count changed");
    }

    function testTampered1a() public view {
        tampered(1, 0, 19);
    }

    function testTampered1b() public view {
        tampered(1, 19, 38);
    }

    function testTampered1c() public view {
        tampered(1, 38, 57);
    }

    function testTampered1d() public view {
        (uint256 oracle, uint256 byDesign, uint256 total) = tampered(1, 57, 1000);
        require(total == 75 && oracle + byDesign == 18, "case count changed");
    }
}
