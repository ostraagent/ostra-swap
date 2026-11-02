// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {RepVerifier} from "../privacy/contracts/src/RepVerifier.sol";
import {Poseidon2, CommitmentTree} from "../privacy/contracts/src/Notes.sol";
import {Reputation} from "../privacy/contracts/src/Reputation.sol";
import {RepConstants} from "../privacy/contracts/src/RepConstants.sol";

/// @notice OstraPad's provider record (ostrapad-pub/src/OstraPad.sol, Provider), as provider(address) returns it.
interface IOstraPadRecord {
    struct Provider {
        uint128 bond;
        uint64 lastEnd;
        uint32 active;
        uint32 completed;
        uint32 rejected;
        uint32 expired;
        uint32 clients;
        uint32 fixedCompleted;
        uint128 volume;
    }

    function provider(address a) external view returns (Provider memory);
}

/// @notice The live OstraVaultFactory's address derivation (ostra-robinhood src/OstraVaultV3.sol, IOstraVaultFactory).
interface IOstraVaultFactoryAddress {
    function vaultAddress(address token, bytes32 initialKeyRoot, address initialCrank) external view returns (address);
}

/// @notice What an Ostra vault answers about its creation (ostra-robinhood src/OstraVaultV3.sol, IOstraVaultView).
interface IOstraVaultCreation {
    function token() external view returns (address);
    function initialKeyRoot() external view returns (bytes32);
    function initialCrank() external view returns (address);
}

interface IERC1271Signer {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

/// @title OstraReputation
/// @notice Anonymous proofs of an Ostra vault's OstraPad record. An agent proves that the provider record of one of
///         the Ostra vaults it controls meets a verifier's public thresholds, without showing which vault: no issuer,
///         the record is read from OstraPad's own state, and the vault authorizes it through EIP-1271 (an approved
///         hash), so no vault upgrade is needed.
///
///         * snapshot(vault, idc): the vault approved snapshotDigest(vault, idc, nonces[vault], currentEpoch()) (an
///           ApproveHash spend; the approval holds for that epoch only); anyone sends it. This contract reads
///           PAD.provider(vault) and appends the leaf P(record || idc)[0..8] to the tree of the current epoch, once per
///           vault and epoch. idc = P(sk || D_IDC..) is the vault's identity commitment (`ostra-prove rep-id` of a
///           reputation-only secret sk); it is the vault's alone. A new one (rotation: the way to revoke a leaked sk)
///           takes effect from the next epoch, and a vault may schedule one at most once every ROTATION_COOLDOWN epochs,
///           counted from the epoch its idc in force took effect.
///         * verify(...): a reputation proof (`ostra-prove rep-prove`, checked by RepVerifier) that a leaf under a root
///           of the current epoch's tree holds a record of this epoch meeting the thresholds and the idc of the sk the
///           pseudonym P(sk || scope)[0..8] comes from: one pseudonym per vault, scope and idc, unlinkable across
///           scopes. A vault has one leaf, so one idc and one pseudonym per scope, in an epoch; across epochs a rotation
///           gives it a new pseudonym in the same scope (at most one rotation per ROTATION_COOLDOWN epochs). A verifier
///           that wants one claim per vault for a period puts the epoch (or a period id) into its scope: with the epoch
///           in the scope, exactly one pseudonym per vault and scope. The verifier supplies the scope, the thresholds,
///           the recipient and the challenge (the bind) itself; the epoch is the current one.
///
///         The anonymity set of a proof is the leaves of the tree under its root: rootSize(root) tells how many, and a
///         prover should use the latest root of the epoch (latestRoot) when it proves, a verifier may require a minimum
///         rootSize. An idc is public once a snapshot carrying it is sent: anyone may take it first for a vault of its
///         own (front-running the first snapshot), which only refuses that snapshot (IdcTaken); the agent picks a new
///         sk. Taking someone's idc gains nothing: proofs need the sk behind it.
///
///         Record values (all clamped in the safe direction): completed and clients at most 2^19 - 1; volume in five
///         26-bit limbs; a record with 2^16 or more rejected or expired jobs is refused; tier 0..3 is OstraPad's
///         limitOf tier without the bond (0: the 5 USDG base, 1: 25, 2: 100, 3: 500 USDG); firstDay is the day
///         (since BASE) of the vault's first snapshot; epoch the week since BASE. No owner, no upgrade.
contract OstraReputation {
    /// @notice The domain of a snapshot approval, so that no other approval of the vault can be sent as one.
    bytes32 public constant SNAPSHOT_DOMAIN = keccak256("OstraReputation.snapshot.v1");
    bytes4 internal constant EIP1271_MAGIC = 0x1626ba7e;
    uint256 public constant EPOCH_LENGTH = 7 days;
    uint256 public constant DAY = 1 days;
    /// @notice Clamp of completed and clients, and the refusal bound of rejected and expired (the circuit's widths).
    uint256 public constant COUNT_MAX = (1 << 19) - 1;
    uint256 public constant FAIL_LIMIT = 1 << 16;
    /// @notice An idc stays in force at least this many epochs before a vault may have the next one take effect.
    uint256 public constant ROTATION_COOLDOWN = 4;
    /// @notice The gas verify must have left when it calls RepVerifier: 63/64 of it (what the call forwards, EIP-150) is
    ///         about 11.8M, against the 9.85M to 9.91M RepVerifier used on the real proofs measured (test/data/rep_*.bin
    ///         and the fork tests' proofs): a margin of about 19% for the proof-dependent part (Merkle sibling counts).
    uint256 public constant VERIFY_GAS = 12_000_000;

    IOstraPadRecord public immutable PAD;
    IOstraVaultFactoryAddress public immutable FACTORY;
    RepVerifier public immutable VERIFIER;
    /// @notice Deployment time: day and epoch 0 start here.
    uint256 public immutable BASE;

    /// @notice A vault's reputation state.
    struct Account {
        /// @notice The identity commitment in force (zero before the first snapshot).
        bytes32 idc;
        /// @notice A new identity commitment waiting for its epoch (zero: none).
        bytes32 pendingIdc;
        /// @notice The epoch pendingIdc takes effect in.
        uint32 pendingFrom;
        /// @notice The last epoch snapshotted, plus one (zero: never).
        uint32 lastEpochPlusOne;
        /// @notice The day of the first snapshot.
        uint32 firstDay;
        /// @notice The epoch the idc in force took effect in.
        uint32 idcFrom;
    }

    /// @notice A root a tree has had: its epoch plus one (zero: unknown) and how many leaves the tree held then.
    struct RootInfo {
        uint32 epochPlusOne;
        uint32 leaves;
    }

    mapping(address vault => Account) internal _accounts;
    /// @notice The vault each identity commitment belongs to (for ever, once taken).
    mapping(bytes32 idc => address vault) public vaultOfIdc;
    /// @notice The next snapshot nonce of each vault (each approval is used once).
    mapping(address vault => uint256) public nonces;
    /// @dev One tree per epoch.
    mapping(uint256 epoch => CommitmentTree.Tree) internal _trees;
    /// @dev Every root any tree has had.
    mapping(bytes32 root => RootInfo) internal _roots;
    /// @notice The root of each epoch's tree after its last leaf (zero before the first).
    mapping(uint256 epoch => bytes32) public latestRoot;

    /// @notice A leaf entered the tree of `epoch` at `index`; `root` is that tree's root after it. Agents rebuild each
    ///         epoch's tree (and their Merkle paths) from these events, in index order.
    event Snapshot(address indexed vault, uint256 indexed epoch, bytes32 leaf, uint256 index, bytes32 root);
    /// @notice The record that leaf holds, as written (the prover needs it).
    event Recorded(
        address indexed vault,
        uint256 indexed epoch,
        uint256 completed,
        uint256 clients,
        uint256 volume,
        uint256 rejected,
        uint256 expired,
        uint256 tier,
        uint256 firstDay
    );
    /// @notice `vault`'s identity commitment becomes `idc` from `epoch` on.
    event IdcScheduled(address indexed vault, bytes32 idc, uint256 epoch);

    error NotOstraVault();
    error NotApproved();
    error BadIdc();
    error IdcTaken();
    error AlreadySnapshotted();
    error RecordTooLarge();
    error UnknownRoot();
    error NotCanonical();
    error BadThresholds();
    /// @notice A new idc may take effect from epoch `from` on.
    error RotationTooSoon(uint256 from);
    /// @notice verify needs at least `needed` gas left when it calls the verifier.
    error InsufficientGas(uint256 needed);
    /// @notice RepVerifier stopped without a verdict (no revert reason).
    error VerifierHalted();

    constructor(address pad, address factory, address verifier) {
        PAD = IOstraPadRecord(pad);
        FACTORY = IOstraVaultFactoryAddress(factory);
        VERIFIER = RepVerifier(verifier);
        BASE = block.timestamp;
    }

    // ---------------------------------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------------------------------

    function currentEpoch() public view returns (uint256) {
        return (block.timestamp - BASE) / EPOCH_LENGTH;
    }

    function account(address vault) external view returns (Account memory) {
        return _accounts[vault];
    }

    /// @notice The epoch of `root` plus one (zero: not a root this contract's trees have had).
    function rootEpochPlusOne(bytes32 root) external view returns (uint256) {
        return _roots[root].epochPlusOne;
    }

    /// @notice How many leaves the tree held when its root was `root` (the anonymity set of a proof against it).
    function rootSize(bytes32 root) external view returns (uint256) {
        return _roots[root].leaves;
    }

    /// @notice How many leaves the tree of `epoch` holds.
    function treeSize(uint256 epoch) external view returns (uint256) {
        return _trees[epoch].count;
    }

    /// @notice The hash `vault` approves (ApproveHash) for its snapshot with `idc` at nonce `nonce` in epoch `epoch`.
    function snapshotDigest(address vault, bytes32 idc, uint256 nonce, uint256 epoch) public view returns (bytes32) {
        return keccak256(abi.encode(SNAPSHOT_DOMAIN, block.chainid, address(this), vault, idc, nonce, epoch));
    }

    /// @notice The tier of OstraPad's limitOf for this record, without the bond: 3 (500 USDG), 2 (100), 1 (25), 0 (5).
    function tierOf(IOstraPadRecord.Provider memory r) public pure returns (uint256) {
        uint256 done = uint256(r.completed) + r.rejected;
        uint256 v = r.volume;
        if (r.completed >= 200 && r.clients >= 50 && v >= 10_000_000_000 && uint256(r.rejected) * 100 < done * 5) return 3;
        if (r.completed >= 50 && r.clients >= 20 && v >= 1_000_000_000 && uint256(r.rejected) * 100 < done * 10) return 2;
        if (r.completed >= 10 && r.clients >= 5 && v >= 100_000_000 && uint256(r.rejected) * 100 < done * 20) return 1;
        return 0;
    }

    /// @notice The bind_hash of a proof for `recipient` under a verifier's `scope` and `challenge`.
    function bindHash(bytes32 scope, address recipient, bytes32 challenge) public pure returns (bytes32) {
        return Reputation.bindHash(scope, recipient, challenge);
    }

    // ---------------------------------------------------------------------------------------------
    // Snapshot
    // ---------------------------------------------------------------------------------------------

    /// @notice Appends `vault`'s OstraPad record of now to the current epoch's tree, as the vault approved it
    ///         (snapshotDigest at its next nonce and this epoch). The first snapshot takes `idc`; a later `idc` other than
    ///         the one in force (or waiting) takes effect from the next epoch (this snapshot's leaf keeps the one in
    ///         force), and only if by then the one in force will have been in force ROTATION_COOLDOWN epochs
    ///         (RotationTooSoon). Anyone may send it. Returns the leaf, its index and the new root.
    function snapshot(address vault, bytes32 idc) external returns (bytes32 leaf, uint256 index, bytes32 root) {
        if (!_isOstraVault(vault)) revert NotOstraVault();
        if (idc == bytes32(0) || !Poseidon2.isCanonical(idc)) revert BadIdc();
        uint256 nonce = nonces[vault];
        uint256 epoch = currentEpoch();
        if (IERC1271Signer(vault).isValidSignature(snapshotDigest(vault, idc, nonce, epoch), "") != EIP1271_MAGIC) {
            revert NotApproved();
        }
        nonces[vault] = nonce + 1;

        Account storage a = _accounts[vault];
        if (a.lastEpochPlusOne == epoch + 1) revert AlreadySnapshotted();
        a.lastEpochPlusOne = uint32(epoch + 1);
        if (a.pendingIdc != bytes32(0) && epoch >= a.pendingFrom) {
            a.idc = a.pendingIdc;
            a.idcFrom = a.pendingFrom;
            a.pendingIdc = bytes32(0);
            a.pendingFrom = 0;
        }
        if (a.idc == bytes32(0)) {
            _take(vault, idc);
            a.idc = idc;
            a.idcFrom = uint32(epoch);
            a.firstDay = uint32((block.timestamp - BASE) / DAY);
        } else if (idc != a.idc && idc != a.pendingIdc) {
            uint256 from = uint256(a.idcFrom) + ROTATION_COOLDOWN;
            if (epoch + 1 < from) revert RotationTooSoon(from);
            _take(vault, idc);
            a.pendingIdc = idc;
            a.pendingFrom = uint32(epoch + 1);
            emit IdcScheduled(vault, idc, epoch + 1);
        }

        Reputation.Record memory r = _record(vault, a.firstDay, epoch);
        leaf = Reputation.leaf(Reputation.recordHash(r), a.idc);
        (index, root) = CommitmentTree.insert(_trees[epoch], leaf);
        _roots[root] = RootInfo(uint32(epoch + 1), uint32(index + 1));
        latestRoot[epoch] = root;
        emit Snapshot(vault, epoch, leaf, index, root);
        emit Recorded(vault, epoch, r.completed, r.clients, r.volume, r.rejected, r.expired, r.tier, r.firstDay);
    }

    /// @dev An identity commitment is one vault's: taken at its first use, never by another vault.
    function _take(address vault, bytes32 idc) private {
        address owner = vaultOfIdc[idc];
        if (owner == address(0)) vaultOfIdc[idc] = vault;
        else if (owner != vault) revert IdcTaken();
    }

    /// @dev OstraPad's record of `vault`, as the circuit takes it.
    function _record(address vault, uint256 firstDay, uint256 epoch) private view returns (Reputation.Record memory r) {
        IOstraPadRecord.Provider memory p = PAD.provider(vault);
        if (p.rejected >= FAIL_LIMIT || p.expired >= FAIL_LIMIT) revert RecordTooLarge();
        r.completed = p.completed > COUNT_MAX ? COUNT_MAX : p.completed;
        r.clients = p.clients > COUNT_MAX ? COUNT_MAX : p.clients;
        r.volume = p.volume;
        r.rejected = p.rejected;
        r.expired = p.expired;
        r.tier = tierOf(p);
        r.firstDay = firstDay;
        r.epoch = epoch;
    }

    /// @dev Whether FACTORY made `v`: the vault address of `v`'s own creation parameters is `v` (no other contract can
    ///      sit at that CREATE2 address). False for anything that does not answer like a vault. As OstraVaultV3.isOstraVault.
    function _isOstraVault(address v) private view returns (bool) {
        if (v.code.length == 0) return false;
        (bool ok1, bytes memory t) = v.staticcall(abi.encodeCall(IOstraVaultCreation.token, ()));
        (bool ok2, bytes memory k) = v.staticcall(abi.encodeCall(IOstraVaultCreation.initialKeyRoot, ()));
        (bool ok3, bytes memory c) = v.staticcall(abi.encodeCall(IOstraVaultCreation.initialCrank, ()));
        if (!ok1 || !ok2 || !ok3 || t.length != 32 || k.length != 32 || c.length != 32) return false;
        uint256 tw = uint256(bytes32(t));
        uint256 cw = uint256(bytes32(c));
        if (tw >> 160 != 0 || cw >> 160 != 0) return false;
        return FACTORY.vaultAddress(address(uint160(tw)), bytes32(k), address(uint160(cw))) == v;
    }

    // ---------------------------------------------------------------------------------------------
    // Verify
    // ---------------------------------------------------------------------------------------------

    /// @notice Whether `proof` shows that a vault whose record of this epoch meets `t` has the pseudonym `pseudonym`
    ///         in `scope`, for `recipient` and `challenge` (bindHash), against `root` (a root of this epoch's tree).
    ///         Reverts on an unknown or stale root, a non-canonical pseudonym or thresholds outside the ranges where
    ///         the circuit's comparisons are exact (Reputation.thresholdsInRange), on too little gas (InsufficientGas:
    ///         give the call about 12.1M gas) and when the verifier halts without a verdict; false only for a proof
    ///         RepVerifier rejects.
    ///         A verifier keeps the pseudonyms it has seen per scope (one per vault, scope and idc; with the epoch or a
    ///         period id in the scope, one per vault for that epoch or period up to a rotation, see above), picks a
    ///         fresh challenge, and may require a minimum rootSize(root).
    function verify(
        bytes32 root,
        bytes32 pseudonym,
        bytes32 scope,
        address recipient,
        bytes32 challenge,
        Reputation.Thresholds calldata t,
        bytes calldata proof
    ) external view returns (bool) {
        uint256 epoch = currentEpoch();
        if (_roots[root].epochPlusOne != epoch + 1) revert UnknownRoot();
        if (!Poseidon2.isCanonical(pseudonym)) revert NotCanonical();
        if (!Reputation.thresholdsInRange(t)) revert BadThresholds();
        uint256[43] memory pv = Reputation.publicValues(root, pseudonym, scope, bindHash(scope, recipient, challenge), epoch, t);
        // publicValues sets scope[0] = D_SCOPE (Reputation.scopeElements) and checks maxFailPermille <= 1000.
        assert(pv[16] == RepConstants.D_SCOPE);
        // Enough gas that the verifier cannot run out on a proof of this shape: a call with less reverts, so that
        // limiting the gas can never turn a valid proof into "invalid".
        if (gasleft() < VERIFY_GAS) revert InsufficientGas(VERIFY_GAS);
        try VERIFIER.verify(proof, pv) returns (bool ok) {
            return ok;
        } catch (bytes memory reason) {
            // RepVerifier rejects with a reason (a require message or a panic code); a failure without one is not
            // a verdict on the proof (out of gas, or any other halt), so it is passed on as a revert.
            if (reason.length == 0) revert VerifierHalted();
            return false;
        }
    }
}
