// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {OstraRouter} from "./OstraRouter.sol";
import {SpendVerifier} from "../privacy/contracts/src/SpendVerifier.sol";
import {Poseidon2, Notes, CommitmentTree} from "../privacy/contracts/src/Notes.sol";

/// @title OstraPrivatePool
/// @notice Private balances for Ostra Swap: an agent keeps ERC-20 tokens as notes in this pool and swaps or
///         withdraws them without showing which of its notes it spends, or whose they are. What stays public:
///         the token, the amount, the pair and the time; what is hidden is the owner (privacy/README.md).
///
///         A note is a commitment P(value || tag) in a depth-20 commitment tree (privacy/contracts/src/Notes.sol):
///         value binds the token and the amount, tag = P(rho || sk) binds the owner's secret key sk and the note's
///         nonce rho. Spending a note takes a STARK (privacy/circuit, checked by SpendVerifier) that the note is a
///         leaf under a root this pool has had, that its nullifier is the one given (each note spends once), and
///         that its amount is v + fee + change: v leaves the note (to a swap or a withdrawal), fee pays the relayer
///         that sends the transaction (the agent pays its gas from its private balance, no wallet of its own shows),
///         and the change becomes a new note of the same token for the same owner. The proof is bound to the exact
///         call: its public values hold the token, v, fee, nullifier, root and change commitment, and its bind_hash
///         (unshieldHash, swapHash) the chain, this pool, the relayer, the deadline and where v goes, so nobody who
///         sees it can change where the funds go: a relayer or a front-runner can only send the call as it is.
///
///         * shield: anyone deposits a token for a tag; the pool counts what arrived and adds the note.
///         * unshield: spends a note; v goes to the recipient the proof names.
///         * privateSwap: spends a note; v is swapped through OstraRouter along the route the proof names, for at
///           least minOut, and what the swap pays becomes a new note for the tag the proof names. The swap pays
///           the router's base fee (OstraRouter.swapAtBaseFee): no holder discount on the private path, not even
///           from OSTRA locked for this pool, which would lower every note owner's fee at once (decided 21 Oct 2026).
///
///         Notes go into trees of 2^20 leaves, numbered from 0; when one is full the next starts (independent review,
///         21 Oct 2026: one tree for ever would freeze every note once full, and anyone can fill it with shields of a
///         token of its own). A spend proves against any root any tree has had, so notes in a full tree stay
///         spendable, and a commitment enters the pool at most once, whatever the tree.
///
///         A swap's outTag is public before the swap lands: anyone may shield exactly the note the swap would add,
///         which makes that swap revert ("commitment exists") at the cost of giving the owner at least minOut. Agents
///         watch Shielded for their own tags. Tokens whose balances change by themselves (rebasing, fees on transfer
///         when the pool pays) are not supported: the notes of such a token may hold more than the pool. Tokens sent
///         to the pool other than through shield belong to no note. No owner, no upgrade.
contract OstraPrivatePool is ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    /// @notice Domain tags of the two spends, so that a proof made for one can never be sent as the other.
    bytes32 public constant UNSHIELD_DOMAIN = keccak256("OstraPrivatePool.unshield.v1");
    bytes32 public constant SWAP_DOMAIN = keccak256("OstraPrivatePool.privateSwap.v1");

    SpendVerifier public immutable VERIFIER;
    OstraRouter public immutable ROUTER;

    /// @notice The public terms of a spend. asset, v, fee, nullifier, root and changeCommitment are the proof's
    ///         public values; relayer and deadline enter it through its bind_hash.
    struct SpendTerms {
        /// @notice The token of the note spent.
        address asset;
        /// @notice What leaves the note: withdrawn, or swapped.
        uint256 v;
        /// @notice Paid to relayer in asset.
        uint256 fee;
        bytes32 nullifier;
        /// @notice A root of the commitment tree the note is a leaf under (any root this pool has had).
        bytes32 root;
        /// @notice The change note, added to the tree.
        bytes32 changeCommitment;
        /// @notice Gets the fee (may be zero only when the fee is zero).
        address relayer;
        /// @notice The spend is valid until this time (unix seconds), inclusive.
        uint64 deadline;
    }

    /// @notice What a private swap pays for. The route is OstraRouter's: hub and both legs.
    struct SwapTerms {
        address tokenOut;
        /// @notice The least tokenOut the new note gets, after the router's fee.
        uint256 minOut;
        /// @notice The tag of the note the swap's output becomes (a fresh rho of the owner).
        bytes32 outTag;
        address hub;
        OstraRouter.Leg legIn;
        OstraRouter.Leg legOut;
    }

    /// @notice Leaves per tree.
    uint256 public constant TREE_CAPACITY = 1 << 20;

    /// @dev The trees, by number.
    mapping(uint256 tree => CommitmentTree.Tree) internal _trees;
    /// @notice The tree notes go into now.
    uint256 public currentTree;
    /// @notice Every commitment in the pool, whatever its tree.
    mapping(bytes32 commitment => bool) public isNote;
    /// @notice Every root any tree has had: a spend may prove against any of them.
    mapping(bytes32 root => bool) public isKnownRoot;
    /// @notice The nullifiers of the notes spent.
    mapping(bytes32 nullifier => bool) public isSpent;
    /// @notice The current tree's root after the last note added (zero before the first).
    bytes32 public currentRoot;

    /// @notice A note entered tree `tree` at `index`; `root` is that tree's root after it. Agents rebuild each tree
    ///         (and their Merkle paths) from these events, in index order.
    event NoteAdded(bytes32 indexed commitment, uint256 indexed tree, uint256 index, bytes32 root);
    event Shielded(address indexed from, address indexed token, uint256 amount, bytes32 tag, bytes32 commitment);
    event Unshielded(
        bytes32 indexed nullifier, address indexed recipient, address indexed token, uint256 amount, uint256 fee, address relayer
    );
    event PrivateSwapped(
        bytes32 indexed nullifier,
        address indexed tokenIn,
        address indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut,
        uint256 fee,
        address relayer,
        bytes32 outTag,
        bytes32 outCommitment
    );

    error ZeroToken();
    error ZeroAmount();
    error ZeroRecipient();
    error Expired();
    error UnknownRoot();
    error AlreadySpent();
    error NotCanonical();
    error InvalidProof();
    error NoRelayer();
    error BadSwap();
    error TooLittleReceived(uint256 minOut, uint256 amountOut);
    error CommitmentExists();

    constructor(address verifier, address router) {
        VERIFIER = SpendVerifier(verifier);
        ROUTER = OstraRouter(payable(router));
    }

    // ---------------------------------------------------------------------------------------------
    // In
    // ---------------------------------------------------------------------------------------------

    /// @notice Takes `amount` of `token` from the caller (approved first) and adds a note of what arrived for `tag`
    ///         (P(rho || sk) of the owner: `ostra-prove note`). Returns the note's commitment, tree, index and
    ///         amount.
    function shield(address token, uint256 amount, bytes32 tag)
        external
        nonReentrant
        returns (bytes32 commitment, uint256 tree, uint256 index, uint256 received)
    {
        if (token == address(0)) revert ZeroToken();
        if (amount == 0) revert ZeroAmount();
        if (!Poseidon2.isCanonical(tag)) revert NotCanonical();
        uint256 before = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        received = IERC20(token).balanceOf(address(this)) - before;
        if (received == 0) revert ZeroAmount();
        commitment = Notes.commitment(token, received, tag);
        (tree, index) = _add(commitment);
        emit Shielded(msg.sender, token, received, tag, commitment);
    }

    // ---------------------------------------------------------------------------------------------
    // Out
    // ---------------------------------------------------------------------------------------------

    /// @notice The bind_hash of an unshield: what its proof is bound to besides its public values.
    function unshieldHash(address relayer, uint64 deadline, address recipient) public view returns (bytes32) {
        return keccak256(abi.encode(UNSHIELD_DOMAIN, block.chainid, address(this), relayer, deadline, recipient));
    }

    /// @notice The bind_hash of a private swap: what its proof is bound to besides its public values.
    function swapHash(address relayer, uint64 deadline, SwapTerms calldata t) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                SWAP_DOMAIN,
                block.chainid,
                address(this),
                relayer,
                deadline,
                t.tokenOut,
                t.minOut,
                t.outTag,
                keccak256(abi.encode(t.hub, t.legIn, t.legOut))
            )
        );
    }

    /// @notice Spends a note: s.v of s.asset to `recipient`, s.fee to s.relayer, the change to a new note.
    function unshield(SpendTerms calldata s, address recipient, bytes calldata proof) external nonReentrant {
        if (recipient == address(0)) revert ZeroRecipient();
        _spend(s, unshieldHash(s.relayer, s.deadline, recipient), proof);
        if (s.v != 0) IERC20(s.asset).safeTransfer(recipient, s.v);
        emit Unshielded(s.nullifier, recipient, s.asset, s.v, s.fee, s.relayer);
    }

    /// @notice Spends a note: s.v of s.asset is swapped through OstraRouter along t's route for at least t.minOut
    ///         of t.tokenOut, which becomes a new note for t.outTag; s.fee goes to s.relayer, the change to a new note.
    ///         Returns what the swap paid and the new note's commitment.
    function privateSwap(SpendTerms calldata s, SwapTerms calldata t, bytes calldata proof)
        external
        nonReentrant
        returns (uint256 amountOut, bytes32 outCommitment)
    {
        if (t.tokenOut == address(0) || t.tokenOut == s.asset || s.v == 0) revert BadSwap();
        if (!Poseidon2.isCanonical(t.outTag)) revert NotCanonical();
        _spend(s, swapHash(s.relayer, s.deadline, t), proof);

        uint256 before = IERC20(t.tokenOut).balanceOf(address(this));
        IERC20(s.asset).forceApprove(address(ROUTER), s.v);
        ROUTER.swapAtBaseFee(s.asset, t.tokenOut, s.v, t.minOut, address(this), t.hub, t.legIn, t.legOut);
        IERC20(s.asset).forceApprove(address(ROUTER), 0);
        // Counted here, not taken from the router: what the new note holds is what this pool received.
        amountOut = IERC20(t.tokenOut).balanceOf(address(this)) - before;
        if (amountOut < t.minOut) revert TooLittleReceived(t.minOut, amountOut);
        if (amountOut == 0) revert ZeroAmount();

        outCommitment = Notes.commitment(t.tokenOut, amountOut, t.outTag);
        _add(outCommitment);
        emit PrivateSwapped(s.nullifier, s.asset, t.tokenOut, s.v, amountOut, s.fee, s.relayer, t.outTag, outCommitment);
    }

    // ---------------------------------------------------------------------------------------------
    // The tree
    // ---------------------------------------------------------------------------------------------

    /// @notice How many notes tree `tree` holds.
    function treeSize(uint256 tree) external view returns (uint256) {
        return _trees[tree].count;
    }

    /// @dev Checks and records a spend, verifies its proof, adds its change note and pays its fee.
    function _spend(SpendTerms calldata s, bytes32 bindHash, bytes calldata proof) private {
        if (block.timestamp > s.deadline) revert Expired();
        if (s.fee != 0 && s.relayer == address(0)) revert NoRelayer();
        if (!Poseidon2.isCanonical(s.nullifier) || !Poseidon2.isCanonical(s.changeCommitment)) revert NotCanonical();
        if (!isKnownRoot[s.root]) revert UnknownRoot();
        if (isSpent[s.nullifier]) revert AlreadySpent();
        isSpent[s.nullifier] = true;
        uint256[48] memory pv =
            Notes.publicValues(s.asset, s.v, s.fee, s.nullifier, s.root, s.changeCommitment, bindHash);
        if (!VERIFIER.verify(proof, pv)) revert InvalidProof();
        _add(s.changeCommitment);
        if (s.fee != 0) IERC20(s.asset).safeTransfer(s.relayer, s.fee);
    }

    /// @dev Adds a note to the current tree (the next one when it is full) and records the new root.
    function _add(bytes32 commitment) internal returns (uint256 tree, uint256 index) {
        if (isNote[commitment]) revert CommitmentExists();
        isNote[commitment] = true;
        tree = currentTree;
        if (_trees[tree].count == TREE_CAPACITY) {
            tree += 1;
            currentTree = tree;
        }
        bytes32 root;
        (index, root) = CommitmentTree.insert(_trees[tree], commitment);
        isKnownRoot[root] = true;
        currentRoot = root;
        emit NoteAdded(commitment, tree, index, root);
    }
}
