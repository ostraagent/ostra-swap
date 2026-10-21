// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Poseidon2, Notes, CommitmentTree} from "../src/Notes.sol";
import {NotesVectors as V} from "./NotesVectors.sol";

// The on-chain note hashing against the circuit's own functions (tools/src/bin/spend.rs).
contract NotesTest {
    using CommitmentTree for CommitmentTree.Tree;

    CommitmentTree.Tree tree;

    event Gas(string what, uint256 gasUsed);

    function perm(uint256[16] memory input, uint256[16] memory output) internal pure {
        Poseidon2.permute(input);
        for (uint256 i = 0; i < 16; i++) require(input[i] == output[i], "permutation differs");
    }

    function testPermutation() public {
        perm(V.permIn0(), V.permOut0());
        perm(V.permIn1(), V.permOut1());
        uint256[16] memory s = V.permIn2();
        uint256 g0 = gasleft();
        Poseidon2.permute(s);
        emit Gas("permutation", g0 - gasleft());
        uint256[16] memory o = V.permOut2();
        for (uint256 i = 0; i < 16; i++) require(s[i] == o[i], "permutation differs");
    }

    function testNoteHashes() public pure {
        require(Notes.value(V.ASSET_0, V.AMOUNT_0) == V.VALUE_0, "value 0");
        require(Notes.value(V.ASSET_1, V.AMOUNT_1) == V.VALUE_1, "value 1");
        require(Notes.value(V.ASSET_2, V.AMOUNT_2) == V.VALUE_2, "value 2");
        require(Notes.commitment(V.ASSET_0, V.AMOUNT_0, V.TAG_0) == V.COMMITMENT_0, "commitment 0");
        require(Notes.commitment(V.ASSET_1, V.AMOUNT_1, V.TAG_1) == V.COMMITMENT_1, "commitment 1");
        require(Notes.commitment(V.ASSET_2, V.AMOUNT_2, V.TAG_2) == V.COMMITMENT_2, "commitment 2");
    }

    function testTree() public {
        bytes32[5] memory leaves = V.leaves();
        bytes32[5] memory roots = V.roots();
        for (uint256 i = 0; i < 5; i++) {
            uint256 g0 = gasleft();
            (uint256 index, bytes32 root) = tree.insert(leaves[i]);
            emit Gas("tree insert", g0 - gasleft());
            require(index == i, "index");
            require(root == roots[i], "root differs");
        }
    }

    function testPublicValues() public pure {
        uint256[48] memory pv = Notes.publicValues(
            V.SPEND_ASSET, V.SPEND_V, V.SPEND_FEE, V.SPEND_NULLIFIER, V.SPEND_ROOT, V.SPEND_CHANGE, V.SPEND_BIND_HASH
        );
        uint256[48] memory want = V.spendPublics();
        for (uint256 i = 0; i < 48; i++) require(pv[i] == want[i], "public value differs");
    }

    function testRejectsNonCanonicalTag() public view {
        bytes32 bad = bytes32(uint256(2130706433));
        (bool ok,) = address(this).staticcall(abi.encodeWithSelector(this.commit.selector, bad));
        require(!ok, "non-canonical tag accepted");
    }

    function commit(bytes32 tag) external pure returns (bytes32) {
        return Notes.commitment(address(1), 1, tag);
    }

    function limbsOf(uint256 a) external pure returns (uint256[5] memory) {
        return Notes.amountLimbs(a);
    }

    function insertLeaf(bytes32 leaf) external returns (uint256, bytes32) {
        return tree.insert(leaf);
    }

    // Amounts of 2^128 or more do not fit the five 26-bit limbs the circuit balances.
    function testAmountBound() public view {
        (bool ok,) = address(this).staticcall(abi.encodeWithSelector(this.limbsOf.selector, uint256(1) << 128));
        require(!ok, "amount of 2^128 accepted");
        uint256[5] memory l = this.limbsOf((uint256(1) << 128) - 1);
        require(l[4] == (1 << 24) - 1 && l[0] == (1 << 26) - 1, "largest amount");
    }

    function testRejectsNonCanonicalLeaf() public {
        (bool ok,) = address(this).call(abi.encodeWithSelector(this.insertLeaf.selector, bytes32(uint256(2130706433) << 224)));
        require(!ok, "non-canonical leaf accepted");
    }

    function testRejectsDuplicateCommitment() public {
        bytes32 leaf = V.leaves()[0];
        this.insertLeaf(leaf);
        (bool ok,) = address(this).call(abi.encodeWithSelector(this.insertLeaf.selector, leaf));
        require(!ok, "duplicate commitment accepted");
    }
}
