// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Reputation} from "../src/Reputation.sol";
import {RepConstants} from "../src/RepConstants.sol";
import {RepVectors as V} from "./RepVectors.sol";

// The on-chain record hashing, scope elements, binding values and public values against the circuit's own functions
// (tools/src/bin/rep.rs).
contract RepTest {
    event Gas(string what, uint256 gasUsed);

    function rec(uint256[8] memory f) internal pure returns (Reputation.Record memory) {
        return Reputation.Record(f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]);
    }

    function testRecordAndLeaf() public {
        require(Reputation.recordHash(rec(V.record0())) == V.RECORD_0, "record 0");
        require(Reputation.recordHash(rec(V.record1())) == V.RECORD_1, "record 1");
        uint256 g0 = gasleft();
        bytes32 r2 = Reputation.recordHash(rec(V.record2()));
        emit Gas("record hash", g0 - gasleft());
        require(r2 == V.RECORD_2, "record 2");
        require(Reputation.leaf(V.RECORD_0, V.IDC_0) == V.LEAF_0, "leaf 0");
        require(Reputation.leaf(V.RECORD_1, V.IDC_1) == V.LEAF_1, "leaf 1");
        require(Reputation.leaf(V.RECORD_2, V.IDC_2) == V.LEAF_2, "leaf 2");
    }

    function scopeMatches(bytes32 scope, uint256[8] memory want) internal pure {
        uint256[8] memory e = Reputation.scopeElements(scope);
        for (uint256 i = 0; i < 8; i++) require(e[i] == want[i], "scope element differs");
        require(e[0] == RepConstants.D_SCOPE, "scope domain");
    }

    function testScopeElements() public pure {
        scopeMatches(V.SCOPE_0, V.scopeElements0());
        scopeMatches(V.SCOPE_1, V.scopeElements1());
        scopeMatches(V.SCOPE_2, V.scopeElements2());
    }

    function thresholds() internal pure returns (Reputation.Thresholds memory t) {
        uint256[6] memory x = V.thresholds();
        t = Reputation.Thresholds(x[0], x[1], x[2], x[3], x[4], x[5]);
    }

    function testPublicValues() public pure {
        bytes32 bh = Reputation.bindHash(V.SCOPE, V.RECIPIENT, V.CHALLENGE);
        require(bh == V.BIND_HASH, "bind hash");
        uint256[43] memory pv = Reputation.publicValues(V.ROOT, V.PSEUDONYM, V.SCOPE, bh, V.EPOCH, thresholds());
        uint256[43] memory want = V.publics();
        for (uint256 i = 0; i < 43; i++) require(pv[i] == want[i], "public value differs");
    }

    // A field beyond the width the circuit range checks is refused, at each width's first value out.
    function testRecordRanges() public {
        uint256[8] memory limits = [uint256(1 << 19), 1 << 19, 1 << 128, 1 << 16, 1 << 16, 4, 1 << 29, 1 << 30];
        for (uint256 k = 0; k < 8; k++) {
            uint256[8] memory f = V.record2();
            f[k] = limits[k] - 1;
            Reputation.recordHash(rec(f));
            f[k] = limits[k];
            (bool ok,) = address(this).call(abi.encodeCall(this.hashOf, (f)));
            require(!ok, "out-of-range field accepted");
        }
    }

    function hashOf(uint256[8] memory f) external pure returns (bytes32) {
        return Reputation.recordHash(rec(f));
    }

    function testThresholdRanges() public pure {
        Reputation.Thresholds memory t = Reputation.Thresholds(0, 0, 0, 0, 0, 0);
        require(Reputation.thresholdsInRange(t), "zero thresholds");
        t = Reputation.Thresholds((1 << 29) - 1, (1 << 29) - 1, (1 << 128) - 1, 1000, 3, (1 << 29) - 1);
        require(Reputation.thresholdsInRange(t), "widest thresholds");
        t.minCompleted = 1 << 29;
        require(!Reputation.thresholdsInRange(t), "minCompleted");
        t.minCompleted = 0;
        t.minClients = 1 << 29;
        require(!Reputation.thresholdsInRange(t), "minClients");
        t.minClients = 0;
        t.minVolume = 1 << 128;
        require(!Reputation.thresholdsInRange(t), "minVolume");
        t.minVolume = 0;
        t.maxFailPermille = 1001;
        require(!Reputation.thresholdsInRange(t), "maxFailPermille");
        t.maxFailPermille = 0;
        t.minTier = 4;
        require(!Reputation.thresholdsInRange(t), "minTier");
        t.minTier = 0;
        t.maxFirstDay = 1 << 29;
        require(!Reputation.thresholdsInRange(t), "maxFirstDay");
    }
}
