// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Poseidon2, Notes} from "./Notes.sol";
import {RepConstants} from "./RepConstants.sol";

// The record hashing and the public values of the reputation circuit (circuit/src/rep.rs), as a contract computes
// them: every function matches the circuit's (tested against vectors from it: test/RepTest.t.sol).
//
//     record    = P([D_REC, completed, clients, vol0..vol4, rejected, expired, tier, firstDay, epoch, 0, 0, 0])[0..8]
//     leaf      = P(record || idc)[0..8]
//     scope     = [D_SCOPE, s1..s7], s_i = bits [30 (i - 1), 30 i) of keccak256(abi.encode(scope bytes32))
//     bind      = Notes.bindOf(keccak256(abi.encode(scope, recipient, challenge)))
//
// A digest is 8 field elements packed in a bytes32, element i in bits [32 i, 32 i + 32).
library Reputation {
    uint256 internal constant P = 2130706433;
    /// @notice The widths the circuit range checks the record's fields to.
    uint256 internal constant COUNT_LIMIT = 1 << 19; // completed, clients
    uint256 internal constant FAIL_LIMIT = 1 << 16; // rejected, expired
    uint256 internal constant TIER_LIMIT = 4;
    uint256 internal constant DAY_LIMIT = 1 << 29; // firstDay
    uint256 internal constant EPOCH_LIMIT = 1 << 30;
    /// @notice minCompleted, minClients and maxFirstDay below 2^29 keep every comparison exact (a difference that
    ///         goes negative wraps to at least P - 2^29 > 2^30, outside its 30-bit range check).
    uint256 internal constant THRESHOLD_LIMIT = 1 << 29;
    uint256 internal constant PERMILLE = 1000;
    uint256 internal constant MAX_TIER = 3;

    /// @notice A record as OstraReputation writes it (already clamped).
    struct Record {
        uint256 completed;
        uint256 clients;
        uint256 volume;
        uint256 rejected;
        uint256 expired;
        uint256 tier;
        uint256 firstDay;
        uint256 epoch;
    }

    /// @notice What a verifier asks of a record: completed >= minCompleted, clients >= minClients,
    ///         volume >= minVolume, 1000 (rejected + expired) < maxFailPermille (completed + rejected + expired),
    ///         tier >= minTier, firstDay <= maxFirstDay.
    struct Thresholds {
        uint256 minCompleted;
        uint256 minClients;
        uint256 minVolume;
        uint256 maxFailPermille;
        uint256 minTier;
        uint256 maxFirstDay;
    }

    /// @notice The record digest. Reverts on a field beyond the width the circuit range checks.
    function recordHash(Record memory r) internal pure returns (bytes32) {
        require(
            r.completed < COUNT_LIMIT && r.clients < COUNT_LIMIT && r.rejected < FAIL_LIMIT && r.expired < FAIL_LIMIT
                && r.tier < TIER_LIMIT && r.firstDay < DAY_LIMIT && r.epoch < EPOCH_LIMIT,
            "record out of range"
        );
        uint256[16] memory s;
        s[0] = RepConstants.D_REC;
        s[1] = r.completed;
        s[2] = r.clients;
        uint256[5] memory v = Notes.amountLimbs(r.volume);
        for (uint256 i = 0; i < 5; i++) s[3 + i] = v[i];
        s[8] = r.rejected;
        s[9] = r.expired;
        s[10] = r.tier;
        s[11] = r.firstDay;
        s[12] = r.epoch;
        Poseidon2.permute(s);
        return Poseidon2.pack(s);
    }

    /// @notice The leaf of a record and an identity commitment: P(record || idc)[0..8].
    function leaf(bytes32 record, bytes32 idc) internal pure returns (bytes32) {
        require(Poseidon2.isCanonical(idc), "idc not canonical");
        return Poseidon2.compress(record, idc);
    }

    /// @notice The 8 scope elements of a verifier's scope.
    function scopeElements(bytes32 scope) internal pure returns (uint256[8] memory e) {
        uint256 h = uint256(keccak256(abi.encode(scope)));
        e[0] = RepConstants.D_SCOPE;
        for (uint256 i = 1; i < 8; i++) {
            e[i] = (h >> (30 * (i - 1))) & 0x3fffffff;
        }
    }

    /// @notice What a proof is bound to besides its public values: the verifier's scope, who the proof is for and the
    ///         verifier's challenge.
    function bindHash(bytes32 scope, address recipient, bytes32 challenge) internal pure returns (bytes32) {
        return keccak256(abi.encode(scope, recipient, challenge));
    }

    /// @notice Whether the thresholds are in the ranges where the circuit's comparisons are exact.
    function thresholdsInRange(Thresholds memory t) internal pure returns (bool) {
        return t.minCompleted < THRESHOLD_LIMIT && t.minClients < THRESHOLD_LIMIT && t.maxFirstDay < THRESHOLD_LIMIT
            && t.maxFailPermille <= PERMILLE && t.minTier <= MAX_TIER && t.minVolume >> 128 == 0;
    }

    /// @notice The 43 public values of a reputation proof, in the circuit's order: root (8), pseudonym (8), scope (8),
    ///         bind (8), epoch, minCompleted, minClients, minVolume (5), maxFailPermille, minTier, maxFirstDay.
    function publicValues(bytes32 root, bytes32 pseudonym, bytes32 scope, bytes32 bindHash_, uint256 epoch, Thresholds memory t)
        internal
        pure
        returns (uint256[43] memory pv)
    {
        require(thresholdsInRange(t), "thresholds out of range");
        require(epoch < EPOCH_LIMIT, "epoch out of range");
        for (uint256 i = 0; i < 8; i++) {
            pv[i] = (uint256(root) >> (32 * i)) & 0xffffffff;
            pv[8 + i] = (uint256(pseudonym) >> (32 * i)) & 0xffffffff;
        }
        uint256[8] memory e = scopeElements(scope);
        uint256[8] memory b = Notes.bindOf(bindHash_);
        for (uint256 i = 0; i < 8; i++) {
            pv[16 + i] = e[i];
            pv[24 + i] = b[i];
        }
        pv[32] = epoch;
        pv[33] = t.minCompleted;
        pv[34] = t.minClients;
        uint256[5] memory m = Notes.amountLimbs(t.minVolume);
        for (uint256 i = 0; i < 5; i++) pv[35 + i] = m[i];
        pv[40] = t.maxFailPermille;
        pv[41] = t.minTier;
        pv[42] = t.maxFirstDay;
    }
}
