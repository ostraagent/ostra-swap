// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, Vm, console} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {OstraReputation, IOstraPadRecord} from "../src/OstraReputation.sol";
import {RepVerifier} from "../privacy/contracts/src/RepVerifier.sol";
import {Reputation} from "../privacy/contracts/src/Reputation.sol";
import {WotsSigner} from "./utils/WotsSigner.sol";

/// @dev The live Ostra vault (version 3, ostra-robinhood src/OstraVault.sol): WOTS spends, action 23 approves a hash for
///      EIP-1271; keyRoot is its current WOTS key root.
interface ILiveVault {
    function nonce() external view returns (uint64);
    function keyRoot() external view returns (bytes32);
    function spendMessage(uint8 action, bytes32 nextKeyRoot, bytes calldata params) external view returns (bytes memory);
    function spend(uint8 action, bytes32 nextKeyRoot, bytes calldata params, bytes calldata signature) external;
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

interface ILiveVaultFactory {
    function createVault(address token, bytes32 initialKeyRoot, address initialCrank) external returns (address);
}

/// @dev The live OstraPad (ostrapad-pub src/OstraPad.sol) as these tests drive it.
interface ILivePad {
    struct Terms {
        address client;
        address provider;
        address evaluator;
        uint256 budget;
        bytes32 description;
        bytes32 clientCommit;
        bytes32 salt;
    }

    event EvaluatorDrawn(bytes32 indexed jobId, address indexed evaluator, uint8 round);

    function provider(address a) external view returns (IOstraPadRecord.Provider memory);
    function limitOf(address p) external view returns (uint256);
    function actionDigest(bytes32 action) external view returns (bytes32);
    function jobId(Terms calldata t) external pure returns (bytes32);
    function evaluatorFeeFor(uint256 budget) external pure returns (uint256);
    function create(Terms calldata t) external returns (bytes32);
    function accept(bytes32 id, bytes32 providerCommit) external;
    function reveal(bytes32 id, bytes32 secret) external;
    function draw(bytes32 id) external;
    function submit(bytes32 id, bytes32 deliverable) external;
    function decide(bytes32 id, bool approve, bytes32 reason) external;
    function settle(bytes32 id) external;
    function joinPool(address e, uint256 amount) external;
}

/// @notice OstraReputation on a Robinhood Chain mainnet fork, against the live OstraPad and the live OstraVaultFactory and
///         its vaults: every snapshot is authorized by a vault's own ApproveHash spend (EIP-1271), every record is read
///         from OstraPad's state, and every proof is made during the test by `ostra-prove` (privacy/target/release,
///         operating-system randomness) from this contract's tree and checked by RepVerifier on chain.
///         Needs FFI: forge test --ffi --match-contract ReputationFork.
///
///         Test vaults are made by the live factory with this run's WOTS keys. Two kinds of state are written with
///         cheatcodes, both documented where they are: the live vault's key root (its owner's WOTS secret is not ours;
///         everything else about the vault is its live state and code) and, for the records no live job history can
///         reach (2^16 rejections, 2^19 completions, a bond), OstraPad's provider record of a test vault. The live
///         record of the live vault is never edited: its new job is a real pool job on the live OstraPad.
contract ReputationForkTest is Test {
    uint256 internal constant ROBINHOOD_CHAIN_ID = 4663;
    uint256 internal constant P = 2130706433;
    address internal constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    ILivePad internal constant PAD = ILivePad(0x1BE28c4F08a548598fE0AA9b16DFD564C82E8055);
    /// @dev The live OstraVaultFactory (ostra-robinhood deployments/robinhood-mainnet.json, vaultFactory).
    address internal constant FACTORY = 0x043a15c514CFE2c797d33520bFF91a5DCdbf2979;
    /// @dev A live Ostra vault with an OstraPad provider record (found from OstraPad's JobCreated and JobAccepted events:
    ///      one of the six providers it has had).
    address internal constant LIVE_VAULT = 0xb63673010Ab32eCd07A06ED5B7634d2306b7e069;
    /// @dev OstraPad's `_providers` mapping slot (read off the live state: keccak256(abi.encode(LIVE_VAULT, 4)) holds
    ///      its lastEnd; checked in _setRecord by reading provider() back) and the vault's keyRoot slot (slot 5 holds
    ///      keyRoot(), checked in _adopt).
    uint256 internal constant PROVIDERS_SLOT = 4;
    uint256 internal constant KEY_ROOT_SLOT = 5;
    string internal constant PROVER = "privacy/target/release/ostra-prove";
    address internal constant SUBMITTER = address(0x5EB);
    bytes32 internal constant LIVE_KEYS = keccak256("OSTRA/EVM/TEST/rep-live");

    RepVerifier internal verifier;
    OstraReputation internal rep;
    bytes32 internal master;
    address internal relayer;
    /// @dev Each epoch's tree as an agent rebuilds it from Snapshot events, in index order.
    mapping(uint256 epoch => bytes32[]) internal leavesOf;

    struct Statement {
        bytes32 sk;
        Reputation.Record record;
        uint256 index;
        bytes32 scope;
        address recipient;
        bytes32 challenge;
        Reputation.Thresholds t;
    }

    struct Proved {
        bytes proof;
        bytes32 root;
        bytes32 pseudonym;
    }

    function setUp() public {
        vm.createSelectFork("robinhood");
        assertEq(block.chainid, ROBINHOOD_CHAIN_ID);
        bytes32 runSalt = keccak256(abi.encode(block.number, block.timestamp, vm.unixTime()));
        master = keccak256(abi.encode("OSTRA/EVM/TEST/rep-master", runSalt));
        relayer = makeAddr("relayer");
        verifier = new RepVerifier();
        rep = new OstraReputation(address(PAD), FACTORY, address(verifier));
        assertEq(rep.currentEpoch(), 0);
    }

    // ---------------------------------------------------------------------------------------------
    // The live vault, end to end
    // ---------------------------------------------------------------------------------------------

    /// @dev The live vault approves its snapshot through its own ApproveHash spend, the live record is snapshotted (all
    ///      its counted fields are zero: its one job had a fixed evaluator, which OstraPad does not count, so no
    ///      threshold can be proven: the fail ratio is strict), then the vault does a real pool job on the live OstraPad,
    ///      and in the next epoch its new record is snapshotted, proven by ostra-prove and verified on chain.
    function test_liveVault_snapshotProveVerify() public {
        IOstraPadRecord.Provider memory live = PAD.provider(LIVE_VAULT);
        assertTrue(live.lastEnd != 0 && live.fixedCompleted != 0, "a live provider record");
        console.log("live record: completed %s, clients %s, fixedCompleted %s", live.completed, live.clients, live.fixedCompleted);
        console.log("live record: rejected %s, expired %s, volume %s", live.rejected, live.expired, live.volume);
        _adopt(LIVE_VAULT);
        bytes32 sk = _digest(71, 72, 73, 74, 75, 76, 77, 78);
        bytes32 idc = _idc(sk);
        _liveEpoch0(live, sk, idc);

        // A pool job on the live OstraPad with the live vault as its provider, judged by a drawn evaluator.
        _poolJob(ILiveVault(LIVE_VAULT), LIVE_KEYS, 5e6);
        IOstraPadRecord.Provider memory now_ = PAD.provider(LIVE_VAULT);
        assertEq(now_.completed, live.completed + 1);
        assertEq(now_.clients, live.clients + 1);
        assertEq(now_.volume, live.volume + 5e6);

        // Epoch 1: another vault snapshots first, then the live vault.
        vm.warp(rep.BASE() + 7 days);
        assertEq(rep.currentEpoch(), 1);
        (ILiveVault other, bytes32 otherKeys) = _vault("other");
        _snapshot(other, otherKeys, _idc(_digest(1, 2, 3, 4, 5, 6, 7, 8)));
        (bytes32 leaf1, uint256 index1, bytes32 root1) = _snapshotGas(ILiveVault(LIVE_VAULT), LIVE_KEYS, idc, "snapshot gas (second, live vault)");
        assertEq(index1, 1);
        Reputation.Record memory r1 = _expected(now_, 0, 1);
        assertEq(leaf1, _leafCli(r1, idc));

        Statement memory s = Statement(sk, r1, index1, keccak256("ostra.reputation.test.scope"), address(0xBEEF), keccak256("challenge"), _open(0));
        s.t = Reputation.Thresholds(r1.completed, r1.clients, r1.volume, 1000, r1.tier, r1.firstDay);
        Proved memory pr = _prove(s, 1);
        assertEq(pr.root, root1);
        _verifyGas(s, pr);

        // One step beyond any threshold, and the prover refuses.
        s.t.minVolume = r1.volume + 1;
        (uint256 code,) = _tryCli("rep-prove", _proveRequest(s, 1));
        assertTrue(code != 0, "a threshold the record misses cannot be proven");
    }

    /// @dev Epoch 0: the live record as it is, snapshotted through the vault's approval; the prover's leaf is the
    ///      contract's, and no threshold holds for a record without a counted job.
    function _liveEpoch0(IOstraPadRecord.Provider memory live, bytes32 sk, bytes32 idc) internal {
        (bytes32 leaf0, uint256 index0,) = _snapshotGas(ILiveVault(LIVE_VAULT), LIVE_KEYS, idc, "snapshot gas (first, live vault)");
        Reputation.Record memory r0 = _expected(live, 0, 0);
        assertEq(r0.completed + r0.clients + r0.volume + r0.rejected + r0.expired + r0.tier, 0, "nothing counted yet");
        assertEq(leaf0, _leafCli(r0, idc), "the prover's leaf is the contract's");
        Statement memory s0 = Statement(sk, r0, index0, keccak256("scope"), address(0xBEEF), keccak256("c0"), _open(0));
        (uint256 code,) = _tryCli("rep-prove", _proveRequest(s0, 0));
        assertTrue(code != 0, "no threshold holds for a record without a counted job");
    }

    /// @dev Verifies on chain and logs the gas.
    function _verifyGas(Statement memory s, Proved memory pr) internal view {
        bytes memory call_ = abi.encodeCall(rep.verify, (pr.root, pr.pseudonym, s.scope, s.recipient, s.challenge, s.t, pr.proof));
        uint256 g = gasleft();
        bool ok = rep.verify(pr.root, pr.pseudonym, s.scope, s.recipient, s.challenge, s.t, pr.proof);
        uint256 used = g - gasleft();
        assertTrue(ok, "the live vault's proof verifies on chain");
        console.log("verify gas (execution)", used);
        console.log("verify calldata bytes", call_.length);
        console.log("verify calldata gas (16 per nonzero, 4 per zero byte)", _calldataGas(call_));
        console.log("proof bytes", pr.proof.length);
    }

    // ---------------------------------------------------------------------------------------------
    // Snapshot authorization
    // ---------------------------------------------------------------------------------------------

    /// @dev No approval, an approval of another idc, of another nonce, of another epoch or for another OstraReputation:
    ///      refused. The approval is used once, and only in its epoch.
    function test_snapshot_needsTheVaultsOwnApprovalOnce() public {
        (ILiveVault v, bytes32 keys) = _vault("a");
        bytes32 idc = _idc(_digest(11, 12, 13, 14, 15, 16, 17, 18));
        vm.expectRevert(OstraReputation.NotApproved.selector);
        rep.snapshot(address(v), idc);

        _spend(v, keys, 23, abi.encode(rep.snapshotDigest(address(v), _idc(_digest(9, 9, 9, 9, 9, 9, 9, 9)), 0, 0), true));
        vm.expectRevert(OstraReputation.NotApproved.selector);
        rep.snapshot(address(v), idc);

        _spend(v, keys, 23, abi.encode(rep.snapshotDigest(address(v), idc, 5, 0), true));
        vm.expectRevert(OstraReputation.NotApproved.selector);
        rep.snapshot(address(v), idc);

        _spend(v, keys, 23, abi.encode(rep.snapshotDigest(address(v), idc, 0, 1), true));
        vm.expectRevert(OstraReputation.NotApproved.selector);
        rep.snapshot(address(v), idc);

        OstraReputation other = new OstraReputation(address(PAD), FACTORY, address(verifier));
        _spend(v, keys, 23, abi.encode(other.snapshotDigest(address(v), idc, 0, 0), true));
        vm.expectRevert(OstraReputation.NotApproved.selector);
        rep.snapshot(address(v), idc);
        other.snapshot(address(v), idc);

        _approveSnapshot(v, keys, idc);
        vm.prank(relayer);
        rep.snapshot(address(v), idc);
        assertEq(rep.nonces(address(v)), 1);

        // An approval of nonce 1 given in epoch 0 (a snapshot approved ahead) does not hold in epoch 2.
        _approveSnapshot(v, keys, idc);
        vm.warp(rep.BASE() + 14 days);
        vm.expectRevert(OstraReputation.NotApproved.selector);
        rep.snapshot(address(v), idc);
        // Nor does the approval of nonce 0 given for epoch 1 earlier: its nonce is spent.
        vm.warp(rep.BASE() + 7 days);
        vm.expectRevert(OstraReputation.NotApproved.selector);
        rep.snapshot(address(v), idc);
        // A new approval, of nonce 1 in epoch 1.
        _approveSnapshot(v, keys, idc);
        rep.snapshot(address(v), idc);
        assertEq(rep.nonces(address(v)), 2);
    }

    /// @dev Contracts that are not Ostra vaults (OstraPad, USDG, the verifier) and accounts are refused.
    function test_snapshot_refusesWhatIsNotAnOstraVault() public {
        bytes32 idc = _idc(_digest(11, 12, 13, 14, 15, 16, 17, 18));
        address[4] memory notVaults = [address(PAD), USDG, address(verifier), makeAddr("account")];
        for (uint256 i; i < 4; i++) {
            vm.expectRevert(OstraReputation.NotOstraVault.selector);
            rep.snapshot(notVaults[i], idc);
        }
    }

    function test_snapshot_oncePerEpoch() public {
        (ILiveVault v, bytes32 keys) = _vault("a");
        bytes32 idc = _idc(_digest(11, 12, 13, 14, 15, 16, 17, 18));
        _snapshot(v, keys, idc);
        _approveSnapshot(v, keys, idc);
        vm.expectRevert(OstraReputation.AlreadySnapshotted.selector);
        rep.snapshot(address(v), idc);
        vm.warp(rep.BASE() + 7 days - 1);
        vm.expectRevert(OstraReputation.AlreadySnapshotted.selector);
        rep.snapshot(address(v), idc);
        vm.warp(rep.BASE() + 7 days);
        vm.expectRevert(OstraReputation.NotApproved.selector);
        rep.snapshot(address(v), idc);
        _approveSnapshot(v, keys, idc);
        rep.snapshot(address(v), idc);
        assertEq(rep.treeSize(0), 1);
        assertEq(rep.treeSize(1), 1);
        assertEq(rep.account(address(v)).firstDay, 0);
    }

    // ---------------------------------------------------------------------------------------------
    // Identity commitments
    // ---------------------------------------------------------------------------------------------

    function test_idc_oneVaultsAndCanonical() public {
        (ILiveVault a, bytes32 ka) = _vault("a");
        (ILiveVault b, bytes32 kb) = _vault("b");
        bytes32 idc = _idc(_digest(11, 12, 13, 14, 15, 16, 17, 18));
        _snapshot(a, ka, idc);
        assertEq(rep.vaultOfIdc(idc), address(a));
        _approveSnapshot(b, kb, idc);
        vm.expectRevert(OstraReputation.IdcTaken.selector);
        rep.snapshot(address(b), idc);
        bytes32 bad = bytes32(uint256(P));
        _approveSnapshot(b, kb, bad);
        vm.expectRevert(OstraReputation.BadIdc.selector);
        rep.snapshot(address(b), bad);
        _approveSnapshot(b, kb, bytes32(0));
        vm.expectRevert(OstraReputation.BadIdc.selector);
        rep.snapshot(address(b), bytes32(0));
    }

    /// @dev A new idc takes effect from the next epoch: the epoch's leaf keeps the one in force, the new one is taken at
    ///      once (no other vault can take it while it waits). An idc stays in force at least ROTATION_COOLDOWN (4)
    ///      epochs: an earlier rotation is refused.
    function test_idc_rotationTakesEffectNextEpochAfterTheCooldown() public {
        (ILiveVault a, bytes32 ka) = _vault("a");
        (ILiveVault b, bytes32 kb) = _vault("b");
        bytes32 x = _idc(_digest(11, 12, 13, 14, 15, 16, 17, 18));
        bytes32 y = _idc(_digest(21, 22, 23, 24, 25, 26, 27, 28));
        _snapshot(a, ka, x);
        assertEq(rep.account(address(a)).idcFrom, 0);
        // Epochs 1 and 2: y would take effect in 2 or 3, before x has been in force 4 epochs.
        for (uint256 e = 1; e < 3; e++) {
            vm.warp(rep.BASE() + e * 7 days);
            _approveSnapshot(a, ka, y);
            vm.expectRevert(abi.encodeWithSelector(OstraReputation.RotationTooSoon.selector, 4));
            rep.snapshot(address(a), y);
            _snapshot(a, ka, x);
        }
        // Epoch 3: y takes effect in 4.
        vm.warp(rep.BASE() + 21 days);
        (bytes32 leaf3,,) = _snapshot(a, ka, y);
        Reputation.Record memory r3 = _expected(PAD.provider(address(a)), 0, 3);
        assertEq(leaf3, Reputation.leaf(Reputation.recordHash(r3), x), "this epoch keeps the idc in force");
        OstraReputation.Account memory acc = rep.account(address(a));
        assertEq(acc.idc, x);
        assertEq(acc.pendingIdc, y);
        assertEq(acc.pendingFrom, 4);
        assertEq(rep.vaultOfIdc(y), address(a));
        _approveSnapshot(b, kb, y);
        vm.expectRevert(OstraReputation.IdcTaken.selector);
        rep.snapshot(address(b), y);
        vm.warp(rep.BASE() + 28 days);
        (bytes32 leaf4,,) = _snapshot(a, ka, y);
        Reputation.Record memory r4 = _expected(PAD.provider(address(a)), 0, 4);
        assertEq(leaf4, Reputation.leaf(Reputation.recordHash(r4), y), "the new idc from the next epoch");
        acc = rep.account(address(a));
        assertEq(acc.idc, y);
        assertEq(acc.idcFrom, 4);
        assertEq(acc.pendingIdc, bytes32(0));
        // Back to its own earlier idc: this vault's, but again only after the cooldown (in force from 8 on).
        vm.warp(rep.BASE() + 35 days);
        _approveSnapshot(a, ka, x);
        vm.expectRevert(abi.encodeWithSelector(OstraReputation.RotationTooSoon.selector, 8));
        rep.snapshot(address(a), x);
        vm.warp(rep.BASE() + 49 days);
        _snapshot(a, ka, x);
        assertEq(rep.account(address(a)).pendingIdc, x);
        assertEq(rep.account(address(a)).pendingFrom, 8);
    }

    /// @dev The review's sequence (one vault, one scope, a second pseudonym after a rotation): a rotation one epoch
    ///      after the first idc is refused; the second pseudonym in that scope comes only in epoch 4. With the epoch in
    ///      the scope, the vault has one pseudonym per scope.
    function test_idc_rotationNeedsFourEpochsForASecondPseudonym() public {
        (ILiveVault a, bytes32 ka) = _vault("sybil");
        _setRecord(address(a), 3, 0, 0, 2, 9e6, 0);
        bytes32 scope = keccak256("airdrop: one claim per vault");
        bytes32 sk1 = _digest(51, 52, 53, 54, 55, 56, 57, 58);
        bytes32 sk2 = _digest(61, 62, 63, 64, 65, 66, 67, 68);
        (, uint256 i0,) = _snapshot(a, ka, _idc(sk1));
        bytes32 p1 = _claim(a, sk1, i0, 0, scope);
        vm.warp(rep.BASE() + 7 days);
        bytes32 idc2 = _idc(sk2);
        _approveSnapshot(a, ka, idc2);
        vm.expectRevert(abi.encodeWithSelector(OstraReputation.RotationTooSoon.selector, 4));
        rep.snapshot(address(a), idc2);
        (, uint256 i1,) = _snapshot(a, ka, _idc(sk1));
        assertEq(_claim(a, sk1, i1, 1, scope), p1, "the same pseudonym while the idc stays");
        vm.warp(rep.BASE() + 21 days);
        _snapshot(a, ka, idc2);
        vm.warp(rep.BASE() + 28 days);
        (, uint256 i4,) = _snapshot(a, ka, idc2);
        bytes32 p2 = _claim(a, sk2, i4, 4, scope);
        assertTrue(p1 != p2, "a second pseudonym in the scope, four epochs on");
        // A verifier wanting one claim per vault and epoch puts the epoch into its scope.
        bytes32 scope4 = keccak256(abi.encode(scope, uint256(4)));
        assertTrue(_claim(a, sk2, i4, 4, scope4) != p2);
    }

    /// @dev The ~3.28M an estimate used to settle at, and up to the minimum: a revert (InsufficientGas), never false.
    function _lowGasReverts(bytes memory call_) internal view {
        bytes memory tooLittle = abi.encodeWithSelector(OstraReputation.InsufficientGas.selector, rep.VERIFY_GAS());
        uint256[3] memory low = [uint256(3_280_000), 9_000_000, rep.VERIFY_GAS()];
        for (uint256 i; i < 3; i++) {
            (bool ok, bytes memory ret) = address(rep).staticcall{gas: low[i]}(call_);
            assertFalse(ok, "too little gas must revert");
            assertEq(ret, tooLittle);
        }
    }

    /// @dev The least gas a valid call needs (what eth_estimateGas finds), to 1,000 gas: every call below it reverts.
    function _leastGas(bytes memory call_) internal view returns (uint256 hi) {
        uint256 lo = rep.VERIFY_GAS();
        hi = 13_000_000;
        while (hi - lo > 1_000) {
            uint256 mid = (lo + hi) / 2;
            (bool ok, bytes memory ret) = address(rep).staticcall{gas: mid}(call_);
            if (ok && abi.decode(ret, (bool))) {
                hi = mid;
            } else {
                assertFalse(ok, "never false for a valid proof");
                lo = mid;
            }
        }
    }

    function _claim(ILiveVault a, bytes32 sk, uint256 index, uint256 epoch, bytes32 scope) internal returns (bytes32) {
        Reputation.Thresholds memory t = _open(0);
        Statement memory s = Statement(sk, _expected(PAD.provider(address(a)), 0, epoch), index, scope, address(0xBEEF), keccak256(abi.encode(epoch)), t);
        Proved memory p = _prove(s, epoch);
        assertTrue(rep.verify(p.root, p.pseudonym, scope, s.recipient, s.challenge, t, p.proof), "accepted");
        return p.pseudonym;
    }

    // ---------------------------------------------------------------------------------------------
    // Records
    // ---------------------------------------------------------------------------------------------

    /// @dev 2^16 - 1 rejected or expired jobs are written, 2^16 refuse the snapshot (OstraPad's record of a test vault
    ///      written by vm.store: no job history reaches these counts).
    function test_record_refusedAt2to16() public {
        (ILiveVault v, bytes32 keys) = _vault("a");
        bytes32 idc = _idc(_digest(11, 12, 13, 14, 15, 16, 17, 18));
        _setRecord(address(v), 5, (1 << 16) - 1, (1 << 16) - 1, 3, 7e6, 0);
        (bytes32 leaf,,) = _snapshot(v, keys, idc);
        assertEq(leaf, _leafCli(_expected(PAD.provider(address(v)), 0, 0), idc));
        vm.warp(rep.BASE() + 7 days);
        _setRecord(address(v), 5, 1 << 16, 0, 3, 7e6, 0);
        _approveSnapshot(v, keys, idc);
        vm.expectRevert(OstraReputation.RecordTooLarge.selector);
        rep.snapshot(address(v), idc);
        _setRecord(address(v), 5, 0, 1 << 16, 3, 7e6, 0);
        vm.expectRevert(OstraReputation.RecordTooLarge.selector);
        rep.snapshot(address(v), idc);
    }

    /// @dev completed and clients beyond 2^19 - 1 are written as 2^19 - 1; the largest volume as its five limbs.
    function test_record_clampsCounts() public {
        (ILiveVault v, bytes32 keys) = _vault("a");
        bytes32 idc = _idc(_digest(11, 12, 13, 14, 15, 16, 17, 18));
        _setRecord(address(v), type(uint32).max, 0, 0, (1 << 19) + 5, type(uint128).max, 0);
        vm.recordLogs();
        (bytes32 leaf,,) = _snapshot(v, keys, idc);
        Reputation.Record memory r = _recorded();
        assertEq(r.completed, (1 << 19) - 1);
        assertEq(r.clients, (1 << 19) - 1);
        assertEq(r.volume, type(uint128).max);
        assertEq(r.tier, 3, "4 billion completed, all of them clients' and none rejected: the top tier");
        assertEq(leaf, _leafCli(r, idc));
    }

    /// @dev tierOf is OstraPad's limitOf tier without the bond: equal to limitOf's tier where the bond is zero, and
    ///      unchanged by a bond that lifts limitOf.
    function test_record_tierIsLimitOfWithoutTheBond() public {
        (ILiveVault v,) = _vault("a");
        uint256[4] memory limits = [uint256(5e6), 25e6, 100e6, 500e6];
        // (completed, rejected, clients, volume): below and at each tier's edges.
        uint256[5][12] memory cases = [
            [uint256(9), 0, 5, 100e6, 0],
            [uint256(10), 0, 5, 100e6, 1],
            [uint256(10), 3, 5, 100e6, 0],
            [uint256(10), 2, 5, 100e6, 1],
            [uint256(10), 0, 4, 1e12, 0],
            [uint256(50), 0, 20, 1e9 - 1, 1],
            [uint256(50), 0, 20, 1e9, 2],
            [uint256(50), 6, 20, 1e9, 1],
            [uint256(50), 5, 20, 1e9, 2],
            [uint256(199), 0, 50, 1e10, 2],
            [uint256(200), 0, 50, 1e10, 3],
            [uint256(200), 11, 50, 1e10, 2]
        ];
        for (uint256 i; i < cases.length; i++) {
            _setRecord(address(v), cases[i][0], cases[i][1], 0, cases[i][2], cases[i][3], 0);
            uint256 tier = rep.tierOf(PAD.provider(address(v)));
            assertEq(tier, cases[i][4], "tier");
            assertEq(PAD.limitOf(address(v)), limits[tier], "the same tier as OstraPad's limitOf");
            _setRecord(address(v), cases[i][0], cases[i][1], 0, cases[i][2], cases[i][3], 500e6);
            assertEq(PAD.limitOf(address(v)), 500e6, "the bond lifts limitOf");
            assertEq(rep.tierOf(PAD.provider(address(v))), tier, "but not the tier");
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Verify
    // ---------------------------------------------------------------------------------------------

    /// @dev A proof against an earlier root of this epoch's tree verifies; in the next epoch the root is stale. Every
    ///      term is bound: recipient, challenge, scope, thresholds, pseudonym.
    function test_verify_rootHistoryEpochAndBinding() public {
        (ILiveVault a, bytes32 ka) = _vault("a");
        (ILiveVault b, bytes32 kb) = _vault("b");
        bytes32 sk = _digest(31, 32, 33, 34, 35, 36, 37, 38);
        _setRecord(address(a), 12, 1, 0, 6, 150e6, 0);
        vm.warp(block.timestamp + 3 days);
        (, uint256 index,) = _snapshot(a, ka, _idc(sk));
        _snapshot(b, kb, _idc(_digest(1, 2, 3, 4, 5, 6, 7, 8)));
        Reputation.Record memory r = _expected(PAD.provider(address(a)), 3, 0);
        assertEq(r.tier, 1);
        Statement memory s = Statement(sk, r, index, keccak256("scope"), address(0xBEEF), keccak256("c"), _open(0));
        s.t = Reputation.Thresholds(10, 5, 100e6, 100, 1, 3);
        // Proved against the root after a's snapshot only (an agent's view before b's), verified after b's.
        Proved memory pr = _proveAt(s, 0, 1);
        assertTrue(rep.verify(pr.root, pr.pseudonym, s.scope, s.recipient, s.challenge, s.t, pr.proof));
        // Its anonymity set is the one leaf under that root; the latest root has two.
        assertEq(rep.rootSize(pr.root), 1);
        assertEq(rep.rootSize(rep.latestRoot(0)), 2);
        assertTrue(rep.latestRoot(0) != pr.root);

        assertFalse(rep.verify(pr.root, pr.pseudonym, s.scope, address(0xBEEE), s.challenge, s.t, pr.proof), "recipient");
        assertFalse(rep.verify(pr.root, pr.pseudonym, s.scope, s.recipient, keccak256("d"), s.t, pr.proof), "challenge");
        assertFalse(rep.verify(pr.root, pr.pseudonym, keccak256("other"), s.recipient, s.challenge, s.t, pr.proof), "scope");
        assertFalse(rep.verify(pr.root, bytes32(uint256(pr.pseudonym) ^ 1), s.scope, s.recipient, s.challenge, s.t, pr.proof), "pseudonym");
        Reputation.Thresholds memory t = s.t;
        t.minCompleted = 11;
        assertFalse(rep.verify(pr.root, pr.pseudonym, s.scope, s.recipient, s.challenge, t, pr.proof), "thresholds");
        bytes memory cut = new bytes(pr.proof.length - 1);
        for (uint256 i; i < cut.length; i++) cut[i] = pr.proof[i];
        assertFalse(rep.verify(pr.root, pr.pseudonym, s.scope, s.recipient, s.challenge, s.t, cut), "a malformed proof");

        // Inputs outside the circuit's exact ranges revert.
        t = s.t;
        t.maxFailPermille = 1001;
        vm.expectRevert(OstraReputation.BadThresholds.selector);
        rep.verify(pr.root, pr.pseudonym, s.scope, s.recipient, s.challenge, t, pr.proof);
        t = s.t;
        t.minCompleted = 1 << 29;
        vm.expectRevert(OstraReputation.BadThresholds.selector);
        rep.verify(pr.root, pr.pseudonym, s.scope, s.recipient, s.challenge, t, pr.proof);
        vm.expectRevert(OstraReputation.NotCanonical.selector);
        rep.verify(pr.root, bytes32(type(uint256).max), s.scope, s.recipient, s.challenge, s.t, pr.proof);
        vm.expectRevert(OstraReputation.UnknownRoot.selector);
        rep.verify(keccak256("root"), pr.pseudonym, s.scope, s.recipient, s.challenge, s.t, pr.proof);

        // The next epoch: the root and the proof's epoch are stale.
        vm.warp(rep.BASE() + 7 days);
        vm.expectRevert(OstraReputation.UnknownRoot.selector);
        rep.verify(pr.root, pr.pseudonym, s.scope, s.recipient, s.challenge, s.t, pr.proof);
    }

    /// @dev One pseudonym per vault, scope and idc: the same vault in another scope shows another pseudonym, and the
    ///      pseudonym is never the public idc.
    function test_verify_pseudonymPerScope() public {
        (ILiveVault a, bytes32 ka) = _vault("a");
        bytes32 sk = _digest(41, 42, 43, 44, 45, 46, 47, 48);
        bytes32 idc = _idc(sk);
        _setRecord(address(a), 3, 0, 0, 2, 9e6, 0);
        (, uint256 index,) = _snapshot(a, ka, idc);
        Reputation.Record memory r = _expected(PAD.provider(address(a)), 0, 0);
        Statement memory s = Statement(sk, r, index, keccak256("scope one"), address(0xBEEF), keccak256("c"), _open(0));
        s.t = Reputation.Thresholds(3, 2, 9e6, 1000, 0, 0);
        Proved memory p1 = _prove(s, 0);
        assertTrue(rep.verify(p1.root, p1.pseudonym, s.scope, s.recipient, s.challenge, s.t, p1.proof));
        s.challenge = keccak256("c2");
        Proved memory p1b = _prove(s, 0);
        assertEq(p1b.pseudonym, p1.pseudonym, "the same pseudonym in one scope");
        s.scope = keccak256("scope two");
        Proved memory p2 = _prove(s, 0);
        assertTrue(rep.verify(p2.root, p2.pseudonym, s.scope, s.recipient, s.challenge, s.t, p2.proof));
        assertTrue(p2.pseudonym != p1.pseudonym, "another pseudonym in another scope");
        assertTrue(p1.pseudonym != idc && p2.pseudonym != idc, "never the idc");
    }

    /// @dev Limiting the gas never turns a valid proof into "invalid": too little gas reverts (InsufficientGas), enough
    ///      returns true, and a tampered proof with enough gas returns false. Logs the least gas a valid call needs.
    function test_verify_gasLimitCannotRejectAValidProof() public {
        (ILiveVault a, bytes32 ka) = _vault("a");
        bytes32 sk = _digest(81, 82, 83, 84, 85, 86, 87, 88);
        _setRecord(address(a), 3, 0, 0, 2, 9e6, 0);
        (, uint256 index,) = _snapshot(a, ka, _idc(sk));
        Statement memory s = Statement(sk, _expected(PAD.provider(address(a)), 0, 0), index, keccak256("scope"), address(0xBEEF), keccak256("c"), _open(0));
        Proved memory pr = _prove(s, 0);
        bytes memory call_ = abi.encodeCall(rep.verify, (pr.root, pr.pseudonym, s.scope, s.recipient, s.challenge, s.t, pr.proof));
        _lowGasReverts(call_);
        (bool ok, bytes memory ret) = address(rep).staticcall{gas: 13_000_000}(call_);
        assertTrue(ok);
        assertTrue(abi.decode(ret, (bool)), "enough gas: valid");
        console.log("least gas for a valid verify call", _leastGas(call_));

        // A tampered proof (one trace value raised by one) with enough gas: false.
        bytes memory bad = pr.proof;
        bad[96 + 31] = bytes1(uint8(bad[96 + 31]) ^ 1);
        assertFalse(rep.verify{gas: 13_000_000}(pr.root, pr.pseudonym, s.scope, s.recipient, s.challenge, s.t, bad), "tampered: false");
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers: vaults and OstraPad
    // ---------------------------------------------------------------------------------------------

    function _vault(string memory name) internal returns (ILiveVault v, bytes32 keys) {
        keys = keccak256(abi.encode("OSTRA/EVM/TEST/rep-vault", name));
        v = ILiveVault(ILiveVaultFactory(FACTORY).createVault(USDG, WotsSigner.keyRoot(WotsSigner.deriveSeed(master, keys, 0)), address(0)));
    }

    function _spend(ILiveVault v, bytes32 keys, uint8 action, bytes memory params) internal {
        uint64 n = v.nonce();
        bytes32 next = WotsSigner.keyRoot(WotsSigner.deriveSeed(master, keys, n + 1));
        bytes memory sig = WotsSigner.sign(WotsSigner.deriveSeed(master, keys, n), v.spendMessage(action, next, params));
        vm.prank(SUBMITTER, SUBMITTER);
        v.spend(action, next, params, sig);
    }

    /// @dev The live vault's WOTS key is its owner's: this run's test key takes its place as the key root of the vault's
    ///      current nonce (one storage word, slot 5); the vault's code, nonce, approvals and every other state stay live.
    function _adopt(address v) internal {
        uint64 n = ILiveVault(v).nonce();
        assertEq(vm.load(v, bytes32(KEY_ROOT_SLOT)), ILiveVault(v).keyRoot(), "slot 5 is keyRoot");
        bytes32 root = WotsSigner.keyRoot(WotsSigner.deriveSeed(master, LIVE_KEYS, n));
        vm.store(v, bytes32(KEY_ROOT_SLOT), root);
        assertEq(ILiveVault(v).keyRoot(), root);
        assertEq(ILiveVault(v).nonce(), n);
    }

    function _approveSnapshot(ILiveVault v, bytes32 keys, bytes32 idc) internal {
        _spend(v, keys, 23, abi.encode(rep.snapshotDigest(address(v), idc, rep.nonces(address(v)), rep.currentEpoch()), true));
    }

    /// @dev The vault approves its snapshot with `idc` (ApproveHash) and the relayer sends it.
    function _snapshot(ILiveVault v, bytes32 keys, bytes32 idc) internal returns (bytes32 leaf, uint256 index, bytes32 root) {
        _approveSnapshot(v, keys, idc);
        vm.prank(relayer);
        (leaf, index, root) = rep.snapshot(address(v), idc);
        uint256 epoch = rep.currentEpoch();
        assertEq(index, leavesOf[epoch].length);
        leavesOf[epoch].push(leaf);
        assertEq(rep.rootEpochPlusOne(root), epoch + 1);
        assertEq(rep.rootSize(root), index + 1);
        assertEq(rep.latestRoot(epoch), root);
    }

    function _snapshotGas(ILiveVault v, bytes32 keys, bytes32 idc, string memory what)
        internal
        returns (bytes32 leaf, uint256 index, bytes32 root)
    {
        _approveSnapshot(v, keys, idc);
        bytes memory call_ = abi.encodeCall(rep.snapshot, (address(v), idc));
        vm.prank(relayer);
        uint256 g = gasleft();
        (leaf, index, root) = rep.snapshot(address(v), idc);
        console.log(what, g - gasleft());
        console.log("snapshot calldata gas", _calldataGas(call_));
        uint256 epoch = rep.currentEpoch();
        assertEq(index, leavesOf[epoch].length);
        leavesOf[epoch].push(leaf);
    }

    /// @dev OstraPad's provider record of a test vault, written in OstraPad's storage (records no job history reaches);
    ///      lastEnd, active and fixedCompleted are kept. Read back through provider() to check the layout.
    function _setRecord(address v, uint256 completed, uint256 rejected, uint256 expired, uint256 clients, uint256 volume, uint256 bond)
        internal
    {
        bytes32 base = keccak256(abi.encode(v, PROVIDERS_SLOT));
        IOstraPadRecord.Provider memory old = PAD.provider(v);
        uint256 w0 = bond | (uint256(old.lastEnd) << 128) | (uint256(old.active) << 192) | (completed << 224);
        uint256 w1 = rejected | (expired << 32) | (clients << 64) | (uint256(old.fixedCompleted) << 96) | (volume << 128);
        vm.store(address(PAD), base, bytes32(w0));
        vm.store(address(PAD), bytes32(uint256(base) + 1), bytes32(w1));
        IOstraPadRecord.Provider memory r = PAD.provider(v);
        assertEq(r.bond, bond);
        assertEq(r.completed, completed);
        assertEq(r.rejected, rejected);
        assertEq(r.expired, expired);
        assertEq(r.clients, clients);
        assertEq(r.volume, volume);
        assertEq(r.lastEnd, old.lastEnd);
    }

    /// @dev A pool job of `budget` on the live OstraPad: a new client account creates it, `v` accepts and submits through
    ///      ApproveHash spends, five new evaluators join the pool (the live members stay in it), the drawn evaluator
    ///      approves, and it settles after the appeal window.
    function _poolJob(ILiveVault v, bytes32 keys, uint256 budget) internal {
        for (uint256 i; i < 5; i++) {
            address e = makeAddr(string.concat("evaluator", vm.toString(i)));
            deal(USDG, e, 100e6);
            vm.startPrank(e);
            IERC20(USDG).approve(address(PAD), 100e6);
            PAD.joinPool(e, 100e6);
            vm.stopPrank();
        }
        vm.warp(block.timestamp + 2 days + 1);
        address client = makeAddr("client");
        bytes32 cs = keccak256("client secret");
        bytes32 ps = keccak256("provider secret");
        ILivePad.Terms memory t = ILivePad.Terms(client, address(v), address(0), budget, keccak256("write a haiku"), keccak256(abi.encode(cs)), keccak256("salt"));
        uint256 need = budget + PAD.evaluatorFeeFor(budget);
        deal(USDG, client, need);
        vm.startPrank(client);
        IERC20(USDG).approve(address(PAD), need);
        bytes32 id = PAD.create(t);
        vm.stopPrank();
        bytes32 commit = keccak256(abi.encode(ps));
        _spend(v, keys, 23, abi.encode(PAD.actionDigest(keccak256(abi.encode("accept", id, commit))), true));
        vm.prank(relayer);
        PAD.accept(id, commit);
        PAD.reveal(id, cs);
        PAD.reveal(id, ps);
        vm.roll(block.number + 1);
        vm.recordLogs();
        PAD.draw(id);
        address evaluator = _drawn(id);
        _spend(v, keys, 23, abi.encode(PAD.actionDigest(keccak256(abi.encode("submit", id, bytes32("haiku")))), true));
        vm.prank(relayer);
        PAD.submit(id, bytes32("haiku"));
        vm.prank(evaluator);
        PAD.decide(id, true, bytes32("ok"));
        vm.warp(block.timestamp + 48 hours);
        PAD.settle(id);
    }

    function _drawn(bytes32 id) internal view returns (address) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].emitter == address(PAD) && logs[i].topics[0] == ILivePad.EvaluatorDrawn.selector && logs[i].topics[1] == id) {
                return address(uint160(uint256(logs[i].topics[2])));
            }
        }
        revert("no evaluator drawn");
    }

    /// @dev The record OstraReputation must write for `p` (the circuit's clamps and OstraPad's tier).
    function _expected(IOstraPadRecord.Provider memory p, uint256 firstDay, uint256 epoch) internal view returns (Reputation.Record memory r) {
        r.completed = p.completed > (1 << 19) - 1 ? (1 << 19) - 1 : p.completed;
        r.clients = p.clients > (1 << 19) - 1 ? (1 << 19) - 1 : p.clients;
        r.volume = p.volume;
        r.rejected = p.rejected;
        r.expired = p.expired;
        r.tier = rep.tierOf(p);
        r.firstDay = firstDay;
        r.epoch = epoch;
    }

    function _recorded() internal view returns (Reputation.Record memory r) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].emitter == address(rep) && logs[i].topics[0] == OstraReputation.Recorded.selector) {
                (r.completed, r.clients, r.volume, r.rejected, r.expired, r.tier, r.firstDay) =
                    abi.decode(logs[i].data, (uint256, uint256, uint256, uint256, uint256, uint256, uint256));
                r.epoch = uint256(logs[i].topics[2]);
                return r;
            }
        }
        revert("no record");
    }

    function _open(uint256) internal pure returns (Reputation.Thresholds memory t) {
        t = Reputation.Thresholds(0, 0, 0, 1000, 0, (1 << 29) - 1);
    }

    function _calldataGas(bytes memory d) internal pure returns (uint256 g) {
        for (uint256 i; i < d.length; i++) g += d[i] == 0 ? 4 : 16;
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers: the agent's side, ostra-prove through FFI
    // ---------------------------------------------------------------------------------------------

    function _idc(bytes32 sk) internal returns (bytes32) {
        return _digestFrom(vm.parseJsonStringArray(_cli("rep-id", string.concat('{"sk":', _digestJson(sk), "}")), ".idc"));
    }

    function _recordJson(Reputation.Record memory r) internal pure returns (string memory) {
        return string.concat(
            '{"completed":', vm.toString(r.completed), ',"clients":', vm.toString(r.clients), ',"volume":"', vm.toString(r.volume),
            '","rejected":', vm.toString(r.rejected), ',"expired":', vm.toString(r.expired), ',"tier":', vm.toString(r.tier),
            string.concat(',"first_day":', vm.toString(r.firstDay), ',"epoch":', vm.toString(r.epoch), "}")
        );
    }

    function _leafCli(Reputation.Record memory r, bytes32 idc) internal returns (bytes32) {
        string memory out = _cli("rep-record", string.concat('{"record":', _recordJson(r), ',"idc":', _digestJson(idc), "}"));
        assertEq(_digestFrom(vm.parseJsonStringArray(out, ".record")), Reputation.recordHash(r), "the prover's record digest");
        return _digestFrom(vm.parseJsonStringArray(out, ".leaf"));
    }

    function _thresholdsJson(Reputation.Thresholds memory t) internal pure returns (string memory) {
        return string.concat(
            '{"min_completed":', vm.toString(t.minCompleted), ',"min_clients":', vm.toString(t.minClients), ',"min_volume":"',
            vm.toString(t.minVolume), '","max_fail_permille":', vm.toString(t.maxFailPermille), ',"min_tier":',
            string.concat(vm.toString(t.minTier), ',"max_first_day":', vm.toString(t.maxFirstDay), "}")
        );
    }

    /// @dev The prove request for statement `s` against the tree of `epoch` with its first `count` leaves.
    function _proveRequestAt(Statement memory s, uint256 epoch, uint256 count) internal returns (string memory q, bytes32 root) {
        string memory pathJson;
        (root, pathJson) = _path(epoch, s.index, count);
        q = string.concat('{"sk":', _digestJson(s.sk), ',"record":', _recordJson(s.record), ',"epoch":', vm.toString(epoch));
        q = string.concat(q, ',"index":', vm.toString(s.index), ',"path":', pathJson, ',"root":', _digestJson(root));
        q = string.concat(
            q, ',"scope":"', vm.toString(s.scope), '","thresholds":', _thresholdsJson(s.t), ',"bind_hash":"',
            vm.toString(rep.bindHash(s.scope, s.recipient, s.challenge)), '"}'
        );
    }

    function _proveRequest(Statement memory s, uint256 epoch) internal returns (string memory q) {
        (q,) = _proveRequestAt(s, epoch, leavesOf[epoch].length);
    }

    function _prove(Statement memory s, uint256 epoch) internal returns (Proved memory pr) {
        return _proveAt(s, epoch, leavesOf[epoch].length);
    }

    /// @dev Proves `s` against the root of the first `count` leaves of the tree of `epoch`; checks the prover's public
    ///      values are the ones OstraReputation hands the verifier.
    function _proveAt(Statement memory s, uint256 epoch, uint256 count) internal returns (Proved memory pr) {
        string memory q;
        (q, pr.root) = _proveRequestAt(s, epoch, count);
        assertEq(rep.rootEpochPlusOne(pr.root), epoch + 1, "a root this epoch's tree has had");
        string memory out = _cli("rep-prove", q);
        pr.proof = vm.parseJsonBytes(out, ".proof");
        pr.pseudonym = _digestFrom(vm.parseJsonStringArray(out, ".pseudonym"));
        string[] memory pvs = vm.parseJsonStringArray(out, ".public_values");
        assertEq(pvs.length, 43);
        uint256[43] memory pv =
            Reputation.publicValues(pr.root, pr.pseudonym, s.scope, rep.bindHash(s.scope, s.recipient, s.challenge), epoch, s.t);
        for (uint256 i; i < 43; i++) assertEq(vm.parseUint(pvs[i]), pv[i]);
    }

    /// @dev The root of the first `count` leaves of the tree of `epoch` and leaf `index`'s Merkle path, as JSON.
    function _path(uint256 epoch, uint256 index, uint256 count) internal returns (bytes32 root, string memory pathJson) {
        string memory l = "[";
        for (uint256 i; i < count; i++) l = string.concat(l, i == 0 ? "" : ",", _digestJson(leavesOf[epoch][i]));
        string memory out = _cli("path", string.concat('{"leaves":', l, '],"index":', vm.toString(index), "}"));
        root = _digestFrom(vm.parseJsonStringArray(out, ".root"));
        pathJson = "[";
        for (uint256 k; k < 20; k++) {
            bytes32 sib = _digestFrom(vm.parseJsonStringArray(out, string.concat(".path[", vm.toString(k), "]")));
            pathJson = string.concat(pathJson, k == 0 ? "" : ",", _digestJson(sib));
        }
        pathJson = string.concat(pathJson, "]");
    }

    function _tryCli(string memory cmd, string memory json) internal returns (uint256 code, string memory out) {
        string[] memory a = new string[](3);
        a[0] = "bash";
        a[1] = "-c";
        a[2] = string.concat("printf '%s' '", json, "' | ", PROVER, " ", cmd);
        Vm.FfiResult memory r = vm.tryFfi(a);
        return (uint256(int256(r.exitCode)), string(r.stdout));
    }

    function _cli(string memory cmd, string memory json) internal returns (string memory) {
        string[] memory a = new string[](3);
        a[0] = "bash";
        a[1] = "-c";
        a[2] = string.concat("printf '%s' '", json, "' | ", PROVER, " ", cmd);
        Vm.FfiResult memory r = vm.tryFfi(a);
        assertEq(int256(r.exitCode), int256(0), string(r.stderr));
        return string(r.stdout);
    }

    function _digestJson(bytes32 d) internal pure returns (string memory s) {
        s = "[";
        for (uint256 i; i < 8; i++) {
            s = string.concat(s, i == 0 ? '"' : ',"', vm.toString((uint256(d) >> (32 * i)) & 0xffffffff), '"');
        }
        s = string.concat(s, "]");
    }

    function _digestFrom(string[] memory a) internal pure returns (bytes32) {
        assertEq(a.length, 8);
        uint256 v;
        for (uint256 i; i < 8; i++) {
            uint256 x = vm.parseUint(a[i]);
            assertLt(x, P);
            v |= x << (32 * i);
        }
        return bytes32(v);
    }

    function _digest(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 f, uint256 g, uint256 h)
        internal
        pure
        returns (bytes32)
    {
        return bytes32(a | (b << 32) | (c << 64) | (d << 96) | (e << 128) | (f << 160) | (g << 192) | (h << 224));
    }
}
