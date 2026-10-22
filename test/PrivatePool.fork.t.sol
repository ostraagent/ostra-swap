// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, Vm, console} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {OstraBuyback} from "../src/OstraBuyback.sol";
import {OstraRouter} from "../src/OstraRouter.sol";
import {OstraStake} from "../src/OstraStake.sol";
import {OstraPrivatePool, OstraShieldEscrow} from "../src/OstraPrivatePool.sol";
import {SpendVerifier} from "../privacy/contracts/src/SpendVerifier.sol";
import {Notes} from "../privacy/contracts/src/Notes.sol";
import {Legs, PoolKey} from "./utils/Legs.sol";

interface IQuoterV2Pool {
    struct QuoteExactInputSingleParams {
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint24 fee;
        uint160 sqrtPriceLimitX96;
    }

    function quoteExactInputSingle(QuoteExactInputSingleParams memory params)
        external
        returns (uint256 amountOut, uint160 sqrtPriceX96After, uint32 initializedTicksCrossed, uint256 gasEstimate);
}

interface IV4QuoterPool {
    struct QuoteExactSingleParams {
        PoolKey poolKey;
        bool zeroForOne;
        uint128 exactAmount;
        bytes hookData;
    }

    function quoteExactInputSingle(QuoteExactSingleParams memory params)
        external
        returns (uint256 amountOut, uint256 gasEstimate);
}

interface IPonsCurveBuyPool {
    function buy(uint256 ethIn, uint256 minOut, address recipient) external payable;
}

/// @notice OstraPrivatePool on a Robinhood Chain mainnet fork, end to end through the agent's prover: every proof is
///         made during the test by `ostra-prove` (privacy/target/release/ostra-prove, operating-system randomness),
///         from the pool's own tree and bind hashes, and checked by SpendVerifier on chain. Swaps go through the
///         real Universal Router and Uniswap pools. Needs FFI: forge test --ffi --match-contract PrivatePool.
contract PrivatePoolForkTest is Test {
    uint256 internal constant ROBINHOOD_CHAIN_ID = 4663;
    uint256 internal constant P = 2130706433;

    address internal constant UNIVERSAL_ROUTER = 0x8876789976dEcBfCbBbe364623C63652db8C0904;
    address internal constant QUOTER_V2 = 0x33e885eD0Ec9bF04EcfB19341582aADCb4c8A9E7;
    address internal constant V4_QUOTER = 0x8Dc178eFB8111BB0973Dd9d722ebeFF267c98F94;
    address internal constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address internal constant WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    address internal constant NVDA = 0xd0601CE157Db5bdC3162BbaC2a2C8aF5320D9EEC;
    address internal constant OSTRA = 0x68Ff81dFFF6eccefb74706fE1e0a86320CB2Eb96;
    address internal constant OSTRA_CURVE = 0xef89C3a9832Ae6f8Dc5F785484b1B5cb1120F372;
    address internal constant TREASURY = 0x6569E27A95a6A3E92A311B4Cc6600fed56aA50A2;
    address internal constant PONS_HOOK = 0xE5e702641Ea86F4ae6cC3cDaeD2B886f976Be044;

    string internal constant PROVER = "privacy/target/release/ostra-prove";

    OstraStake internal stake;
    OstraBuyback internal buyback;
    OstraRouter internal router;
    SpendVerifier internal verifier;
    OstraPrivatePool internal pool;

    address internal user = makeAddr("user");
    address internal relayer = makeAddr("relayer");
    address internal recipient = makeAddr("recipient");
    address internal owner = makeAddr("owner");
    address internal keeper = makeAddr("keeper");

    /// @dev The agent's secret key (a fixed digest: tests only; an agent draws it with `ostra-prove secret`).
    bytes32 internal sk;
    /// @dev The tree as the agent rebuilds it from NoteAdded, in index order.
    bytes32[] internal leaves;

    /// @dev A note the agent holds.
    struct Note {
        bytes32 rho;
        address asset;
        uint256 amount;
        bytes32 commitment;
        uint256 index;
    }

    /// @dev A spend ready to send: its terms and proof, and the change note's nonce.
    struct Spend {
        OstraPrivatePool.SpendTerms s;
        bytes proof;
        bytes32 changeRho;
    }

    function setUp() public {
        vm.createSelectFork("robinhood");
        assertEq(block.chainid, ROBINHOOD_CHAIN_ID);
        stake = new OstraStake(OSTRA);
        buyback = new OstraBuyback(OSTRA, USDG, WETH, UNIVERSAL_ROUTER, OSTRA_CURVE, PONS_HOOK, owner, keeper);
        router = new OstraRouter(UNIVERSAL_ROUTER, USDG, WETH, address(stake), address(buyback), TREASURY);
        verifier = new SpendVerifier();
        pool = new OstraPrivatePool(address(verifier), address(router));
        sk = _digest(11, 12, 13, 14, 15, 16, 17, 18);
    }

    // ---------------------------------------------------------------------------------------------
    // Shield
    // ---------------------------------------------------------------------------------------------

    function test_shield_noteMatchesProver() public {
        Note memory n = _shield(USDG, 1_000e6, _rho(1));
        assertEq(n.index, 0);
        assertEq(pool.treeSize(0), 1);
        assertTrue(pool.isNote(n.commitment));
        assertEq(_bal(USDG, address(pool)), 1_000e6);
        (bytes32 root,) = _path(0);
        assertEq(pool.currentRoot(), root);
        assertTrue(pool.isKnownRoot(root));

        Note memory m = _shield(NVDA, 3e18, _rho(2));
        assertEq(m.index, 1);
        (root,) = _path(1);
        assertEq(pool.currentRoot(), root);
    }

    function test_shield_rejects() public {
        deal(USDG, user, 10e6);
        vm.startPrank(user);
        IERC20(USDG).approve(address(pool), type(uint256).max);
        vm.expectRevert(OstraPrivatePool.ZeroToken.selector);
        pool.shield(address(0), 1, bytes32(0));
        vm.expectRevert(OstraPrivatePool.ZeroAmount.selector);
        pool.shield(USDG, 0, bytes32(0));
        vm.expectRevert(OstraPrivatePool.NotCanonical.selector);
        pool.shield(USDG, 1e6, bytes32(uint256(P)));
        vm.stopPrank();
    }

    /// @dev The same note twice would share one nullifier: the pool refuses the second.
    function test_shield_duplicateCommitmentRejected() public {
        Note memory n = _shield(USDG, 5e6, _rho(1));
        (bytes32 tag,,) = _noteCli(n.rho, USDG, 5e6);
        deal(USDG, user, 5e6);
        vm.startPrank(user);
        IERC20(USDG).approve(address(pool), 5e6);
        vm.expectRevert(OstraPrivatePool.CommitmentExists.selector);
        pool.shield(USDG, 5e6, tag);
        vm.stopPrank();
    }

    // ---------------------------------------------------------------------------------------------
    // Shield from an escrow (a sender that can only transfer, such as an Ostra vault)
    // ---------------------------------------------------------------------------------------------

    /// @dev The vault transfers to the escrow; anyone (here the relayer) has the pool take it: the note is the tag's
    ///      owner's, and it spends like any other.
    function test_shieldFromEscrow_noteMatchesProverAndSpends() public {
        bytes32 rho = _rho(1);
        (bytes32 tag, bytes32 cm,) = _noteCli(rho, USDG, 40e6);
        address escrow = pool.shieldEscrowAddress(USDG, tag);
        assertEq(escrow.code.length, 0);
        deal(USDG, user, 40e6);
        vm.prank(user);
        IERC20(USDG).transfer(escrow, 40e6);

        vm.expectEmit(address(pool));
        emit OstraPrivatePool.Shielded(escrow, USDG, 40e6, tag, cm);
        vm.prank(relayer);
        uint256 g = gasleft();
        (bytes32 c, uint256 tree, uint256 index, uint256 received) = pool.shieldFromEscrow(USDG, tag);
        console.log("shieldFromEscrow gas (escrow deployed)", g - gasleft());
        assertEq(c, cm);
        assertEq(tree, 0);
        assertEq(index, 0);
        assertEq(received, 40e6);
        assertGt(escrow.code.length, 0);
        assertEq(OstraShieldEscrow(escrow).POOL(), address(pool));
        assertEq(_bal(USDG, escrow), 0);
        assertEq(_bal(USDG, address(pool)), 40e6);
        leaves.push(c);

        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(Note(rho, USDG, 40e6, c, 0), 15e6, 1e6, pool.unshieldHash(relayer, deadline, recipient), relayer, deadline);
        pool.unshield(sp.s, recipient, sp.proof);
        assertEq(_bal(USDG, recipient), 15e6);
        assertEq(_bal(USDG, relayer), 1e6);
    }

    /// @dev The escrow stays after its first note: more sent to it is another note of the same tag (another amount);
    ///      the same amount again would be the same note, refused, and the escrow keeps it.
    function test_shieldFromEscrow_againAndTheSameNoteRefused() public {
        (bytes32 tag,,) = _noteCli(_rho(1), USDG, 5e6);
        address escrow = pool.shieldEscrowAddress(USDG, tag);
        deal(USDG, user, 20e6);
        vm.startPrank(user);
        IERC20(USDG).transfer(escrow, 5e6);
        pool.shieldFromEscrow(USDG, tag);
        IERC20(USDG).transfer(escrow, 7e6);
        (bytes32 c,,, uint256 received) = pool.shieldFromEscrow(USDG, tag);
        assertEq(received, 7e6);
        assertEq(c, Notes.commitment(USDG, 7e6, tag));
        IERC20(USDG).transfer(escrow, 5e6);
        vm.expectRevert(OstraPrivatePool.CommitmentExists.selector);
        pool.shieldFromEscrow(USDG, tag);
        vm.stopPrank();
        assertEq(_bal(USDG, escrow), 5e6);
        assertEq(pool.treeSize(0), 2);
    }

    function test_shieldFromEscrow_rejects() public {
        (bytes32 tag,,) = _noteCli(_rho(1), USDG, 5e6);
        vm.expectRevert(OstraPrivatePool.ZeroToken.selector);
        pool.shieldFromEscrow(address(0), tag);
        vm.expectRevert(OstraPrivatePool.NotCanonical.selector);
        pool.shieldFromEscrow(USDG, bytes32(uint256(P)));
        vm.expectRevert(OstraPrivatePool.EscrowEmpty.selector);
        pool.shieldFromEscrow(USDG, tag);
        // Another token's escrow for the same tag is another address: tokens sent there are not this one's.
        assertTrue(pool.shieldEscrowAddress(USDG, tag) != pool.shieldEscrowAddress(NVDA, tag));
        address nvdaEscrow = pool.shieldEscrowAddress(NVDA, tag);
        deal(NVDA, user, 1e18);
        vm.prank(user);
        IERC20(NVDA).transfer(nvdaEscrow, 1e18);
        vm.expectRevert(OstraPrivatePool.EscrowEmpty.selector);
        pool.shieldFromEscrow(USDG, tag);
    }

    /// @dev Only the pool moves what an escrow holds.
    function test_shieldEscrow_onlyThePoolPays() public {
        (bytes32 tag,,) = _noteCli(_rho(1), USDG, 5e6);
        address escrow = pool.shieldEscrowAddress(USDG, tag);
        deal(USDG, user, 10e6 + 1);
        vm.startPrank(user);
        IERC20(USDG).transfer(escrow, 5e6);
        pool.shieldFromEscrow(USDG, tag);
        IERC20(USDG).transfer(escrow, 5e6 + 1);
        vm.expectRevert(OstraShieldEscrow.OnlyPool.selector);
        OstraShieldEscrow(escrow).pay(USDG, 1);
        vm.stopPrank();
        assertEq(_bal(USDG, escrow), 5e6 + 1);
    }

    // ---------------------------------------------------------------------------------------------
    // Unshield
    // ---------------------------------------------------------------------------------------------

    function test_unshield_paysRecipientRelayerAndChange() public {
        Note memory n = _shield(USDG, 1_000e6, _rho(1));
        _shield(USDG, 77e6, _rho(2)); // another note, so the spent one is not the only leaf
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, 600e6, 2e6, pool.unshieldHash(relayer, deadline, recipient), relayer, deadline);

        uint256 g = gasleft();
        pool.unshield(sp.s, recipient, sp.proof);
        console.log("unshield gas", g - gasleft());
        leaves.push(sp.s.changeCommitment);

        assertEq(_bal(USDG, recipient), 600e6);
        assertEq(_bal(USDG, relayer), 2e6);
        assertEq(_bal(USDG, address(pool)), 1_077e6 - 602e6);
        assertTrue(pool.isSpent(sp.s.nullifier));
        assertEq(pool.treeSize(0), 3);
        (bytes32 root,) = _path(2);
        assertEq(pool.currentRoot(), root);

        // The change note is the owner's: 398 USDG under the change nonce the prover drew. Spend all of it.
        (, bytes32 changeCm,) = _noteCli(sp.changeRho, USDG, 398e6);
        assertEq(changeCm, sp.s.changeCommitment);
        Note memory change = Note(sp.changeRho, USDG, 398e6, changeCm, 2);
        Spend memory sp2 = _prove(change, 398e6, 0, pool.unshieldHash(address(0), deadline, recipient), address(0), deadline);
        pool.unshield(sp2.s, recipient, sp2.proof);
        assertEq(_bal(USDG, recipient), 998e6);
        assertEq(_bal(USDG, address(pool)), 77e6);
    }

    function test_unshield_replayRejected() public {
        Note memory n = _shield(USDG, 100e6, _rho(1));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, 50e6, 0, pool.unshieldHash(address(0), deadline, recipient), address(0), deadline);
        pool.unshield(sp.s, recipient, sp.proof);
        vm.expectRevert(OstraPrivatePool.AlreadySpent.selector);
        pool.unshield(sp.s, recipient, sp.proof);
    }

    /// @dev One proof, every term changed in turn: each is refused, and the proof still works as made.
    function test_unshield_boundToEveryTerm() public {
        Note memory n = _shield(USDG, 100e6, _rho(1));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, 60e6, 1e6, pool.unshieldHash(relayer, deadline, recipient), relayer, deadline);
        OstraPrivatePool.SpendTerms memory s = sp.s; // the same memory: each change below is undone after
        bytes32 changeCm = s.changeCommitment;
        bytes32 nf = s.nullifier;

        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(s, user, sp.proof); // another recipient

        s.relayer = user;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(s, recipient, sp.proof);
        s.relayer = relayer;

        s.deadline = deadline + 1;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(s, recipient, sp.proof);
        s.deadline = deadline;

        s.v = 61e6;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(s, recipient, sp.proof);
        s.v = 60e6;

        s.fee = 2e6;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(s, recipient, sp.proof);
        s.fee = 1e6;

        s.changeCommitment = n.commitment;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(s, recipient, sp.proof);
        s.changeCommitment = changeCm;

        s.asset = NVDA;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(s, recipient, sp.proof);
        s.asset = USDG;

        // The nullifier of another note (canonical, unspent): refused.
        (,, bytes32 otherNf) = _noteCli(_rho(9), USDG, 100e6);
        s.nullifier = otherNf;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(s, recipient, sp.proof);
        s.nullifier = nf;

        // A proof byte flipped.
        bytes memory bad = bytes.concat(sp.proof);
        bad[bad.length - 1] ^= bytes1(0x01);
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(s, recipient, bad);

        assertFalse(pool.isSpent(s.nullifier));
        pool.unshield(s, recipient, sp.proof);
        assertEq(_bal(USDG, recipient), 60e6);
        assertEq(_bal(USDG, relayer), 1e6);
    }

    function test_unshield_checksBeforeTheProof() public {
        Note memory n = _shield(USDG, 100e6, _rho(1));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, 60e6, 1e6, pool.unshieldHash(relayer, deadline, recipient), relayer, deadline);
        OstraPrivatePool.SpendTerms memory s = sp.s; // the same memory: each change below is undone after
        bytes32 root = s.root;
        bytes32 nf = s.nullifier;

        vm.expectRevert(OstraPrivatePool.ZeroRecipient.selector);
        pool.unshield(s, address(0), sp.proof);

        s.relayer = address(0);
        vm.expectRevert(OstraPrivatePool.NoRelayer.selector);
        pool.unshield(s, recipient, sp.proof);
        s.relayer = relayer;

        s.root = keccak256("not a root") & bytes32(uint256(0x0fffffff0fffffff0fffffff0fffffff0fffffff0fffffff0fffffff0fffffff));
        vm.expectRevert(OstraPrivatePool.UnknownRoot.selector);
        pool.unshield(s, recipient, sp.proof);
        s.root = root;

        // A nullifier element at P or above: the same field value as a smaller one would be.
        s.nullifier = bytes32(uint256(nf) + P);
        vm.expectRevert(OstraPrivatePool.NotCanonical.selector);
        pool.unshield(s, recipient, sp.proof);
        s.nullifier = nf;

        vm.warp(uint256(deadline) + 1);
        vm.expectRevert(OstraPrivatePool.Expired.selector);
        pool.unshield(s, recipient, sp.proof);
    }

    /// @dev A proof made for this pool is refused by another pool holding the very same tree.
    function test_unshield_boundToThePool() public {
        Note memory n = _shield(USDG, 100e6, _rho(1));
        OstraPrivatePool other = new OstraPrivatePool(address(verifier), address(router));
        (bytes32 tag,,) = _noteCli(n.rho, USDG, 100e6);
        deal(USDG, user, 100e6);
        vm.startPrank(user);
        IERC20(USDG).approve(address(other), 100e6);
        other.shield(USDG, 100e6, tag);
        vm.stopPrank();
        assertEq(other.currentRoot(), pool.currentRoot());

        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, 100e6, 0, pool.unshieldHash(address(0), deadline, recipient), address(0), deadline);
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        other.unshield(sp.s, recipient, sp.proof);
        pool.unshield(sp.s, recipient, sp.proof);
        assertEq(_bal(USDG, recipient), 100e6);
    }

    // ---------------------------------------------------------------------------------------------
    // Private swap
    // ---------------------------------------------------------------------------------------------

    function test_privateSwap_usdgToNvda_thenUnshield() public {
        Note memory n = _shield(USDG, 1_000e6, _rho(1));
        uint256 v = 500e6;
        uint256 routerFee = (v * 20) / 10_000;
        uint256 expected = _quoteV3(USDG, 500, NVDA, v - routerFee);
        bytes32 outRho = _rho(3);
        (bytes32 outTag,,) = _noteCli(outRho, NVDA, expected);
        OstraPrivatePool.SwapTerms memory t = _terms(NVDA, expected, outTag, Legs.none(), Legs.v3(USDG, 500, NVDA));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, v, 1e6, pool.swapHash(relayer, deadline, t), relayer, deadline);
        uint256 treasuryBefore = _bal(USDG, TREASURY);

        uint256 g = gasleft();
        (uint256 out, bytes32 outCm) = pool.privateSwap(sp.s, t, sp.proof);
        console.log("privateSwap gas", g - gasleft());
        leaves.push(sp.s.changeCommitment);
        leaves.push(outCm);

        assertEq(out, expected);
        (, bytes32 cliCm,) = _noteCli(outRho, NVDA, out);
        assertEq(outCm, cliCm);
        assertEq(_bal(NVDA, address(pool)), out);
        assertEq(_bal(USDG, address(pool)), 1_000e6 - v - 1e6);
        assertEq(_bal(USDG, relayer), 1e6);
        // The router's fee at the base rate, as the pool's account: half to the buyback, the rest to the treasury.
        assertEq(_bal(USDG, address(buyback)), routerFee / 2);
        assertEq(_bal(USDG, TREASURY) - treasuryBefore, routerFee - routerFee / 2);
        assertEq(IERC20(USDG).allowance(address(pool), address(router)), 0);
        _assertRouterHoldsNothing();

        // The NVDA note is the owner's: unshield it.
        Note memory nv = Note(outRho, NVDA, out, outCm, 2);
        Spend memory sp2 = _prove(nv, out, 0, pool.unshieldHash(address(0), deadline, recipient), address(0), deadline);
        pool.unshield(sp2.s, recipient, sp2.proof);
        assertEq(_bal(NVDA, recipient), out);
        assertEq(_bal(NVDA, address(pool)), 0);
    }

    /// @dev USDG to ETH on the native-ETH v4 pool: the router wraps the ETH, the note holds WETH.
    function test_privateSwap_usdgToWeth_v4Native() public {
        Note memory n = _shield(USDG, 300e6, _rho(1));
        uint256 v = 300e6;
        uint256 routerFee = (v * 20) / 10_000;
        PoolKey memory key = PoolKey({currency0: address(0), currency1: USDG, fee: 500, tickSpacing: 10, hooks: address(0)});
        assertEq(keccak256(abi.encode(key)), 0x387bf619da4d3fb62bb276482693dba1b9b3520f573cabdfe033384a24125982);
        uint256 expected = _quoteV4(key, false, v - routerFee);
        bytes32 outRho = _rho(4);
        (bytes32 outTag,,) = _noteCli(outRho, WETH, expected);
        OstraPrivatePool.SwapTerms memory t = _terms(WETH, expected, outTag, Legs.none(), Legs.v4(key, false, false));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, v, 0, pool.swapHash(address(0), deadline, t), address(0), deadline);

        (uint256 out, bytes32 outCm) = pool.privateSwap(sp.s, t, sp.proof);
        assertEq(out, expected);
        (, bytes32 cliCm,) = _noteCli(outRho, WETH, out);
        assertEq(outCm, cliCm);
        assertEq(_bal(WETH, address(pool)), out);
        assertEq(_bal(USDG, address(pool)), 0);
        assertEq(address(pool).balance, 0);
        _assertRouterHoldsNothing();
    }

    function test_privateSwap_boundToEveryTerm() public {
        Note memory n = _shield(USDG, 1_000e6, _rho(1));
        uint256 v = 200e6;
        uint256 expected = _quoteV3(USDG, 500, NVDA, v - (v * 20) / 10_000);
        (bytes32 outTag,,) = _noteCli(_rho(3), NVDA, expected);
        OstraPrivatePool.SwapTerms memory t = _terms(NVDA, expected, outTag, Legs.none(), Legs.v3(USDG, 500, NVDA));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, v, 1e6, pool.swapHash(relayer, deadline, t), relayer, deadline);

        t.minOut = expected - 1;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.privateSwap(sp.s, t, sp.proof);
        t.minOut = expected;

        t.outTag = _digest(1, 2, 3, 4, 5, 6, 7, 8);
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.privateSwap(sp.s, t, sp.proof);
        t.outTag = outTag;

        t.legOut = Legs.v3(USDG, 3000, NVDA);
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.privateSwap(sp.s, t, sp.proof);
        t.legOut = Legs.v3(USDG, 500, NVDA);

        t.hub = WETH;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.privateSwap(sp.s, t, sp.proof);
        t.hub = USDG;

        t.tokenOut = WETH;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.privateSwap(sp.s, t, sp.proof);
        t.tokenOut = NVDA;

        sp.s.relayer = user;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.privateSwap(sp.s, t, sp.proof);
        sp.s.relayer = relayer;

        sp.s.deadline = deadline + 1;
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.privateSwap(sp.s, t, sp.proof);
        sp.s.deadline = deadline;

        // A swap's proof sent as an unshield: another domain, refused.
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(sp.s, relayer, sp.proof);

        assertFalse(pool.isSpent(sp.s.nullifier));
        (uint256 out,) = pool.privateSwap(sp.s, t, sp.proof);
        assertEq(out, expected);
    }

    /// @dev A swap that misses its minimum reverts as a whole: the note stays unspent and spends later.
    function test_privateSwap_minOutMissed_noteStaysUnspent() public {
        Note memory n = _shield(USDG, 100e6, _rho(1));
        uint256 v = 100e6;
        uint256 expected = _quoteV3(USDG, 500, NVDA, v - (v * 20) / 10_000);
        (bytes32 outTag,,) = _noteCli(_rho(3), NVDA, expected);
        OstraPrivatePool.SwapTerms memory t = _terms(NVDA, expected + 1, outTag, Legs.none(), Legs.v3(USDG, 500, NVDA));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, v, 0, pool.swapHash(address(0), deadline, t), address(0), deadline);
        vm.expectRevert(abi.encodeWithSelector(OstraRouter.TooLittleReceived.selector, expected + 1, expected));
        pool.privateSwap(sp.s, t, sp.proof);
        assertFalse(pool.isSpent(sp.s.nullifier));
        assertEq(pool.treeSize(0), 1);

        t.minOut = expected;
        Spend memory again = _prove(n, v, 0, pool.swapHash(address(0), deadline, t), address(0), deadline);
        (uint256 out,) = pool.privateSwap(again.s, t, again.proof);
        assertEq(out, expected);
    }

    function test_privateSwap_rejects() public {
        Note memory n = _shield(USDG, 100e6, _rho(1));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        OstraPrivatePool.SwapTerms memory t = _terms(NVDA, 1, _digest(1, 2, 3, 4, 5, 6, 7, 8), Legs.none(), Legs.v3(USDG, 500, NVDA));
        Spend memory sp = _prove(n, 50e6, 0, pool.swapHash(address(0), deadline, t), address(0), deadline);

        t.tokenOut = address(0);
        vm.expectRevert(OstraPrivatePool.BadSwap.selector);
        pool.privateSwap(sp.s, t, sp.proof);
        t.tokenOut = USDG;
        vm.expectRevert(OstraPrivatePool.BadSwap.selector);
        pool.privateSwap(sp.s, t, sp.proof);
        t.tokenOut = NVDA;
        t.outTag = bytes32(uint256(P));
        vm.expectRevert(OstraPrivatePool.NotCanonical.selector);
        pool.privateSwap(sp.s, t, sp.proof);
    }

    /// @dev Anyone may lock OSTRA for any account, the pool too: the private path still pays the base fee
    ///      (swapAtBaseFee), so such a lock cannot lower every note owner's fee at once (decided 21 Oct 2026).
    function test_privateSwap_baseFeeEvenWithALockNamingThePool() public {
        vm.deal(user, 0.05 ether);
        vm.prank(user);
        IPonsCurveBuyPool(OSTRA_CURVE).buy{value: 0.05 ether}(0.05 ether, 1, user);
        address[] memory list = new address[](1);
        list[0] = address(pool);
        vm.startPrank(user);
        IERC20(OSTRA).approve(address(stake), type(uint256).max);
        stake.lock(500_000e18, list);
        vm.stopPrank();
        assertEq(stake.feeBps(address(pool)), 0);

        Note memory n = _shield(USDG, 400e6, _rho(1));
        uint256 v = 400e6;
        uint256 routerFee = (v * 20) / 10_000;
        uint256 expected = _quoteV3(USDG, 500, NVDA, v - routerFee);
        (bytes32 outTag,,) = _noteCli(_rho(3), NVDA, expected);
        OstraPrivatePool.SwapTerms memory t = _terms(NVDA, expected, outTag, Legs.none(), Legs.v3(USDG, 500, NVDA));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, v, 0, pool.swapHash(address(0), deadline, t), address(0), deadline);
        uint256 treasuryBefore = _bal(USDG, TREASURY);

        vm.expectEmit(address(router));
        emit OstraRouter.Swapped(address(pool), USDG, NVDA, v, expected, USDG, routerFee, 20, address(pool));
        (uint256 out,) = pool.privateSwap(sp.s, t, sp.proof);
        assertEq(out, expected);
        assertEq(_bal(USDG, address(buyback)), routerFee / 2);
        assertEq(_bal(USDG, TREASURY) - treasuryBefore, routerFee - routerFee / 2);
        _assertRouterHoldsNothing();
    }

    /// @dev A proof against an older root still spends after more notes came in, up to its deadline inclusive.
    function test_unshield_oldRootAndDeadlineInclusive() public {
        Note memory n = _shield(USDG, 100e6, _rho(1));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, 100e6, 0, pool.unshieldHash(address(0), deadline, recipient), address(0), deadline);
        _shield(USDG, 5e6, _rho(2));
        _shield(NVDA, 1e18, _rho(3));
        assertTrue(pool.currentRoot() != sp.s.root);
        vm.warp(deadline);
        pool.unshield(sp.s, recipient, sp.proof);
        assertEq(_bal(USDG, recipient), 100e6);
    }

    /// @dev The proof binds the chain: the same call on another chain id is refused.
    function test_unshield_boundToTheChain() public {
        Note memory n = _shield(USDG, 100e6, _rho(1));
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, 100e6, 0, pool.unshieldHash(address(0), deadline, recipient), address(0), deadline);
        vm.chainId(1);
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.unshield(sp.s, recipient, sp.proof);
        vm.chainId(ROBINHOOD_CHAIN_ID);
        pool.unshield(sp.s, recipient, sp.proof);
        assertEq(_bal(USDG, recipient), 100e6);
    }

    /// @dev NVDA to the hub: a leg in only; the leg in is bound like the rest of the route.
    function test_privateSwap_nvdaToUsdg_legInBound() public {
        Note memory n = _shield(NVDA, 4e18, _rho(1));
        uint256 v = 3e18;
        uint256 hub = _quoteV3(NVDA, 500, USDG, v);
        uint256 expected = hub - (hub * 20) / 10_000;
        bytes32 outRho = _rho(3);
        (bytes32 outTag,,) = _noteCli(outRho, USDG, expected);
        OstraPrivatePool.SwapTerms memory t = _terms(USDG, expected, outTag, Legs.v3(NVDA, 500, USDG), Legs.none());
        uint64 deadline = uint64(block.timestamp + 1 hours);
        Spend memory sp = _prove(n, v, 1e16, pool.swapHash(relayer, deadline, t), relayer, deadline);

        t.legIn = Legs.v3(NVDA, 3000, USDG);
        vm.expectRevert(OstraPrivatePool.InvalidProof.selector);
        pool.privateSwap(sp.s, t, sp.proof);
        t.legIn = Legs.v3(NVDA, 500, USDG);

        (uint256 out, bytes32 outCm) = pool.privateSwap(sp.s, t, sp.proof);
        assertEq(out, expected);
        (, bytes32 cliCm,) = _noteCli(outRho, USDG, out);
        assertEq(outCm, cliCm);
        assertEq(_bal(USDG, address(pool)), out);
        assertEq(_bal(NVDA, address(pool)), 4e18 - v - 1e16);
        assertEq(_bal(NVDA, relayer), 1e16);
        _assertRouterHoldsNothing();
    }

    /// @dev A full tree: the next note starts tree 1, and notes of both trees spend. (The harness only marks tree 0
    ///      full; its leaves are the ones the test added.)
    function test_tree_rollsOverWhenFull() public {
        PoolHarness h = new PoolHarness(address(verifier), address(router));
        pool = h;
        Note memory first = _shield(USDG, 10e6, _rho(1));
        h.markFull(0);
        delete leaves;

        bytes32 rho = _rho(2);
        (bytes32 tag, bytes32 cm,) = _noteCli(rho, USDG, 20e6);
        deal(USDG, user, 20e6);
        vm.startPrank(user);
        IERC20(USDG).approve(address(pool), 20e6);
        (bytes32 c, uint256 tree, uint256 index,) = pool.shield(USDG, 20e6, tag);
        vm.stopPrank();
        assertEq(c, cm);
        assertEq(tree, 1);
        assertEq(index, 0);
        assertEq(pool.currentTree(), 1);
        assertEq(pool.treeSize(1), 1);
        leaves.push(c);

        // A commitment of tree 0 cannot enter tree 1.
        (bytes32 firstTag,,) = _noteCli(first.rho, USDG, 10e6);
        deal(USDG, user, 10e6);
        vm.startPrank(user);
        IERC20(USDG).approve(address(pool), 10e6);
        vm.expectRevert(OstraPrivatePool.CommitmentExists.selector);
        pool.shield(USDG, 10e6, firstTag);
        vm.stopPrank();

        uint64 deadline = uint64(block.timestamp + 1 hours);
        Note memory second = Note(rho, USDG, 20e6, c, 0);
        Spend memory sp = _prove(second, 20e6, 0, pool.unshieldHash(address(0), deadline, recipient), address(0), deadline);
        pool.unshield(sp.s, recipient, sp.proof);
        assertEq(_bal(USDG, recipient), 20e6);
        assertEq(pool.treeSize(1), 2);
    }

    // ---------------------------------------------------------------------------------------------
    // The agent's side: ostra-prove through FFI
    // ---------------------------------------------------------------------------------------------

    function _shield(address token, uint256 amount, bytes32 rho) internal returns (Note memory n) {
        (bytes32 tag, bytes32 cm,) = _noteCli(rho, token, amount);
        deal(token, user, amount);
        vm.startPrank(user);
        IERC20(token).approve(address(pool), amount);
        uint256 g = gasleft();
        (bytes32 c, uint256 tree, uint256 index, uint256 received) = pool.shield(token, amount, tag);
        console.log("shield gas", g - gasleft());
        vm.stopPrank();
        assertEq(c, cm);
        assertEq(tree, pool.currentTree());
        assertEq(index, leaves.length);
        assertEq(received, amount);
        leaves.push(c);
        n = Note(rho, token, amount, c, index);
    }

    /// @dev Proves spending `n`: v and fee out, the rest as change, bound to `bindHash`, against the current root.
    function _prove(Note memory n, uint256 v, uint256 fee, bytes32 bindHash, address relayer_, uint64 deadline)
        internal
        returns (Spend memory sp)
    {
        (bytes32 root, string memory pathJson) = _path(n.index);
        assertEq(root, pool.currentRoot());
        string memory out = _cli("prove", _proveRequest(n, v, fee, bindHash, root, pathJson));
        sp.proof = vm.parseJsonBytes(out, ".proof");
        sp.changeRho = _digestFrom(vm.parseJsonStringArray(out, ".change_rho"));
        string[] memory pvs = vm.parseJsonStringArray(out, ".public_values");
        assertEq(pvs.length, 48);
        (,, bytes32 nf) = _noteCli(n.rho, n.asset, n.amount);
        sp.s = OstraPrivatePool.SpendTerms({
            asset: n.asset,
            v: v,
            fee: fee,
            nullifier: nf,
            root: root,
            changeCommitment: _digestAt(pvs, 32),
            relayer: relayer_,
            deadline: deadline
        });
        _assertPublicValues(sp.s, bindHash, pvs);
    }

    function _proveRequest(Note memory n, uint256 v, uint256 fee, bytes32 bindHash, bytes32 root, string memory pathJson)
        internal
        view
        returns (string memory q)
    {
        q = string.concat(
            '{"sk":', _digestJson(sk), ',"rho":', _digestJson(n.rho), ',"asset":"', vm.toString(n.asset), '","amount":"',
            vm.toString(n.amount), '","index":', vm.toString(n.index), ',"path":', pathJson
        );
        q = string.concat(
            q, ',"v":"', vm.toString(v), '","fee":"', vm.toString(fee), '","bind_hash":"', vm.toString(bindHash),
            '","root":', _digestJson(root), "}"
        );
    }

    /// @dev The prover's public values are the ones the pool will hand the verifier.
    function _assertPublicValues(OstraPrivatePool.SpendTerms memory s, bytes32 bindHash, string[] memory pvs) internal pure {
        uint256[48] memory pv = Notes.publicValues(s.asset, s.v, s.fee, s.nullifier, s.root, s.changeCommitment, bindHash);
        for (uint256 i; i < 48; i++) assertEq(vm.parseUint(pvs[i]), pv[i]);
    }

    function _noteCli(bytes32 rho, address asset, uint256 amount) internal returns (bytes32 tag, bytes32 cm, bytes32 nf) {
        string memory out = _cli(
            "note",
            string.concat(
                '{"sk":', _digestJson(sk), ',"rho":', _digestJson(rho), ',"asset":"', vm.toString(asset), '","amount":"',
                vm.toString(amount), '"}'
            )
        );
        tag = _digestFrom(vm.parseJsonStringArray(out, ".tag"));
        cm = _digestFrom(vm.parseJsonStringArray(out, ".commitment"));
        nf = _digestFrom(vm.parseJsonStringArray(out, ".nullifier"));
    }

    /// @dev The root of the agent's tree and leaf `index`'s Merkle path, as JSON for `prove`.
    function _path(uint256 index) internal returns (bytes32 root, string memory pathJson) {
        string memory l = "[";
        for (uint256 i; i < leaves.length; i++) l = string.concat(l, i == 0 ? "" : ",", _digestJson(leaves[i]));
        string memory out = _cli("path", string.concat('{"leaves":', l, '],"index":', vm.toString(index), "}"));
        root = _digestFrom(vm.parseJsonStringArray(out, ".root"));
        pathJson = "[";
        for (uint256 k; k < 20; k++) {
            bytes32 sib = _digestFrom(vm.parseJsonStringArray(out, string.concat(".path[", vm.toString(k), "]")));
            pathJson = string.concat(pathJson, k == 0 ? "" : ",", _digestJson(sib));
        }
        pathJson = string.concat(pathJson, "]");
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
        return _digestAt(a, 0);
    }

    function _digestAt(string[] memory a, uint256 at) internal pure returns (bytes32) {
        uint256 v;
        for (uint256 i; i < 8; i++) {
            uint256 x = vm.parseUint(a[at + i]);
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

    /// @dev A note nonce (tests only; an agent draws each with `ostra-prove secret`).
    function _rho(uint256 k) internal pure returns (bytes32) {
        return _digest(100 * k + 1, 100 * k + 2, 100 * k + 3, 100 * k + 4, 100 * k + 5, 100 * k + 6, 100 * k + 7, 100 * k + 8);
    }

    // ---------------------------------------------------------------------------------------------
    // Swaps
    // ---------------------------------------------------------------------------------------------

    function _terms(address tokenOut, uint256 minOut, bytes32 outTag, OstraRouter.Leg memory legIn, OstraRouter.Leg memory legOut)
        internal
        pure
        returns (OstraPrivatePool.SwapTerms memory t)
    {
        t = OstraPrivatePool.SwapTerms({tokenOut: tokenOut, minOut: minOut, outTag: outTag, hub: USDG, legIn: legIn, legOut: legOut});
    }

    function _quoteV3(address tokenIn, uint24 fee, address tokenOut, uint256 amountIn) internal returns (uint256 out) {
        (out,,,) = IQuoterV2Pool(QUOTER_V2).quoteExactInputSingle(
            IQuoterV2Pool.QuoteExactInputSingleParams({
                tokenIn: tokenIn, tokenOut: tokenOut, amountIn: amountIn, fee: fee, sqrtPriceLimitX96: 0
            })
        );
        assertGt(out, 0);
    }

    function _quoteV4(PoolKey memory key, bool zeroForOne, uint256 amountIn) internal returns (uint256 out) {
        (out,) = IV4QuoterPool(V4_QUOTER).quoteExactInputSingle(
            IV4QuoterPool.QuoteExactSingleParams({
                poolKey: key, zeroForOne: zeroForOne, exactAmount: uint128(amountIn), hookData: ""
            })
        );
        assertGt(out, 0);
    }

    function _bal(address token, address who) internal view returns (uint256) {
        return IERC20(token).balanceOf(who);
    }

    function _assertRouterHoldsNothing() internal view {
        assertEq(_bal(USDG, address(router)), 0);
        assertEq(_bal(WETH, address(router)), 0);
        assertEq(_bal(NVDA, address(router)), 0);
        assertEq(address(router).balance, 0);
    }
}

/// @dev Marks a tree full, so that the next note starts the next tree (2^20 shields are out of a test's reach).
contract PoolHarness is OstraPrivatePool {
    constructor(address verifier, address router) OstraPrivatePool(verifier, router) {}

    function markFull(uint256 tree) external {
        _trees[tree].count = TREE_CAPACITY;
    }
}
