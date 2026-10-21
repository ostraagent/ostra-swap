// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Test, Vm, console} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {OstraBuyback} from "../src/OstraBuyback.sol";
import {OstraQuoteBatch} from "../src/OstraQuoteBatch.sol";
import {OstraRouter, OstraSwapEscrow} from "../src/OstraRouter.sol";
import {OstraStake} from "../src/OstraStake.sol";
import {Legs, PoolKey} from "./utils/Legs.sol";
import {WotsSigner} from "./utils/WotsSigner.sol";

interface IUniswapV3Factory {
    function getPool(address tokenA, address tokenB, uint24 fee) external view returns (address);
}

/// @dev Uniswap's QuoterV2 (v3) and V4Quoter on chain 4663.
interface IQuoterV2 {
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

interface IV4Quoter {
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

/// @dev The live Ostra vault factory and vaults (ostra-robinhood src/OstraVaultFactory.sol and src/OstraVault.sol).
interface IOstraVaultFactory {
    function createVault(address token, bytes32 initialKeyRoot, address initialCrank) external returns (address);
}

interface IOstraVault {
    function nonce() external view returns (uint64);
    function spendMessage(uint8 action, bytes32 nextKeyRoot, bytes calldata params) external view returns (bytes memory);
    function spend(uint8 action, bytes32 nextKeyRoot, bytes calldata params, bytes calldata signature) external;
}

/// @dev The live OstraHook (ostra-robinhood src/launchpad/OstraHook.sol): poolKey(PoolId).
interface IOstraHookKeys {
    function poolKey(bytes32 id) external view returns (PoolKey memory);
}

interface IPoolManagerInit {
    function initialize(PoolKey memory key, uint160 sqrtPriceX96) external returns (int24 tick);
}

interface IMulticall3 {
    struct Call3 {
        address target;
        bool allowFailure;
        bytes callData;
    }

    struct Result {
        bool success;
        bytes returnData;
    }

    function aggregate3(Call3[] calldata calls) external payable returns (Result[] memory returnData);
}

interface IPonsCurveBuy {
    function buy(uint256 ethIn, uint256 minOut, address recipient) external payable;
}

/// @notice Ostra Swap on a Robinhood Chain mainnet fork: the real Universal Router, Uniswap v3 and v4 pools, USDG,
///         WETH, stock tokens, OSTRA on its Pons bonding curve and the live Ostra vault factory. Balances are set
///         with deal() where a test needs a holder; OSTRA is bought on its curve.
contract SwapForkTest is Test {
    uint256 internal constant ROBINHOOD_CHAIN_ID = 4663;

    address internal constant UNIVERSAL_ROUTER = 0x8876789976dEcBfCbBbe364623C63652db8C0904;
    address internal constant V3_FACTORY = 0x1f7d7550B1b028f7571E69A784071F0205FD2EfA;
    address internal constant QUOTER_V2 = 0x33e885eD0Ec9bF04EcfB19341582aADCb4c8A9E7;
    address internal constant V4_QUOTER = 0x8Dc178eFB8111BB0973Dd9d722ebeFF267c98F94;
    address internal constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address internal constant WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    address internal constant NVDA = 0xd0601CE157Db5bdC3162BbaC2a2C8aF5320D9EEC;
    address internal constant TSLA = 0x322F0929c4625eD5bAd873c95208D54E1c003b2d;
    address internal constant OSTRA = 0x68Ff81dFFF6eccefb74706fE1e0a86320CB2Eb96;
    address internal constant OSTRA_CURVE = 0xef89C3a9832Ae6f8Dc5F785484b1B5cb1120F372;
    address internal constant TREASURY = 0x6569E27A95a6A3E92A311B4Cc6600fed56aA50A2;
    address internal constant VAULT_FACTORY = 0x043a15c514CFE2c797d33520bFF91a5DCdbf2979;
    address internal constant DEAD = 0x000000000000000000000000000000000000dEaD;
    address internal constant POOL_MANAGER = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    address internal constant MULTICALL3 = 0xcA11bde05977b3631167028862bE2a173976CA11;
    /// @dev The Pons V2 meme hook: Pons graduates a token to (ETH, token, fee 0, tick spacing 200, this hook).
    address internal constant PONS_HOOK = 0xE5e702641Ea86F4ae6cC3cDaeD2B886f976Be044;

    /// @dev OstraVault spend action 0 (Transfer): params abi.encode(address to, uint256 amount).
    uint8 internal constant ACTION_TRANSFER = 0;

    bytes32 internal constant MASTER = keccak256("OSTRA/SWAP/TEST/master");
    bytes32 internal constant VAULT_KEYCHAIN = keccak256("OSTRA/SWAP/TEST/vault");

    OstraStake internal stake;
    OstraBuyback internal buyback;
    OstraRouter internal router;

    address internal user = makeAddr("user");
    address internal keeper = makeAddr("keeper");
    address internal owner = makeAddr("owner");

    function setUp() public {
        vm.createSelectFork("robinhood");
        assertEq(block.chainid, ROBINHOOD_CHAIN_ID);
        for (uint256 i; i < 9; i++) {
            address a = [UNIVERSAL_ROUTER, V3_FACTORY, QUOTER_V2, V4_QUOTER, USDG, WETH, NVDA, TSLA, OSTRA][i];
            assertGt(a.code.length, 0);
        }
        assertGt(OSTRA_CURVE.code.length, 0);
        assertGt(VAULT_FACTORY.code.length, 0);
        stake = new OstraStake(OSTRA);
        assertGt(PONS_HOOK.code.length, 0);
        buyback = new OstraBuyback(OSTRA, USDG, WETH, UNIVERSAL_ROUTER, OSTRA_CURVE, PONS_HOOK, owner, keeper);
        router = new OstraRouter(UNIVERSAL_ROUTER, USDG, WETH, address(stake), address(buyback), TREASURY);
    }

    // ---------------------------------------------------------------------------------------------
    // Pools and quotes
    // ---------------------------------------------------------------------------------------------

    /// @dev TSLA/USDG on Uniswap v4, no hook, 0.3%: pool id 0x8517…d32e on chain 4663 (TSLA is currency0).
    function _tslaUsdgV4() internal pure returns (PoolKey memory key) {
        key = PoolKey({currency0: TSLA, currency1: USDG, fee: 3000, tickSpacing: 60, hooks: address(0)});
        assertEq(keccak256(abi.encode(key)), 0x8517f8071ae5b831b738052f12125e8e3d6c158b78728aa44ce3b25e5104d32e);
    }

    /// @dev ETH/USDG on Uniswap v4, no hook, 0.05%: pool id 0x387b…5982 (native ETH is currency0).
    function _ethUsdgV4() internal pure returns (PoolKey memory key) {
        key = PoolKey({currency0: address(0), currency1: USDG, fee: 500, tickSpacing: 10, hooks: address(0)});
        assertEq(keccak256(abi.encode(key)), 0x387bf619da4d3fb62bb276482693dba1b9b3520f573cabdfe033384a24125982);
    }

    function _quoteV3(address tokenIn, uint24 fee, address tokenOut, uint256 amountIn) internal returns (uint256 out) {
        assertTrue(IUniswapV3Factory(V3_FACTORY).getPool(tokenIn, tokenOut, fee) != address(0));
        (out,,,) = IQuoterV2(QUOTER_V2).quoteExactInputSingle(
            IQuoterV2.QuoteExactInputSingleParams({
                tokenIn: tokenIn, tokenOut: tokenOut, amountIn: amountIn, fee: fee, sqrtPriceLimitX96: 0
            })
        );
        assertGt(out, 0);
    }

    function _quoteV4(PoolKey memory key, bool zeroForOne, uint256 amountIn) internal returns (uint256 out) {
        (out,) = IV4Quoter(V4_QUOTER).quoteExactInputSingle(
            IV4Quoter.QuoteExactSingleParams({
                poolKey: key, zeroForOne: zeroForOne, exactAmount: uint128(amountIn), hookData: ""
            })
        );
        assertGt(out, 0);
    }

    function _bal(address token, address who) internal view returns (uint256) {
        return IERC20(token).balanceOf(who);
    }

    // ---------------------------------------------------------------------------------------------
    // Wallet swaps
    // ---------------------------------------------------------------------------------------------

    function test_walletSwap_usdgToNvda_v3_feeSplit() public {
        uint256 amountIn = 1_000e6;
        deal(USDG, user, amountIn);
        uint256 fee = (amountIn * 20) / 10_000;
        uint256 expected = _quoteV3(USDG, 500, NVDA, amountIn - fee);
        uint256 treasuryBefore = _bal(USDG, TREASURY);

        vm.startPrank(user);
        IERC20(USDG).approve(address(router), amountIn);
        vm.expectEmit(address(router));
        emit OstraRouter.Swapped(user, USDG, NVDA, amountIn, expected, USDG, fee, 20, user);
        uint256 out = router.swap(USDG, NVDA, amountIn, expected, user, USDG, Legs.none(), Legs.v3(USDG, 500, NVDA));
        vm.stopPrank();

        assertEq(out, expected);
        assertEq(_bal(NVDA, user), expected);
        assertEq(_bal(USDG, user), 0);
        assertEq(_bal(USDG, address(buyback)), fee / 2);
        assertEq(_bal(USDG, TREASURY) - treasuryBefore, fee - fee / 2);
        _assertRouterHoldsNothing();
    }

    function test_walletSwap_nvdaToTsla_v3ThenV4() public {
        uint256 amountIn = 5e18;
        deal(NVDA, user, amountIn);
        uint256 hub = _quoteV3(NVDA, 500, USDG, amountIn);
        uint256 fee = (hub * 20) / 10_000;
        uint256 expected = _quoteV4(_tslaUsdgV4(), false, hub - fee);

        vm.startPrank(user);
        IERC20(NVDA).approve(address(router), amountIn);
        uint256 out = router.swap(
            NVDA, TSLA, amountIn, expected, user, USDG, Legs.v3(NVDA, 500, USDG), Legs.v4(_tslaUsdgV4(), false, false)
        );
        vm.stopPrank();

        assertEq(out, expected);
        assertEq(_bal(TSLA, user), expected);
        assertEq(_bal(NVDA, user), 0);
        assertEq(_bal(USDG, address(buyback)), fee / 2);
        _assertRouterHoldsNothing();
    }

    function test_walletSwap_ethIn_v4NativePool() public {
        uint256 amountIn = 0.5 ether;
        vm.deal(user, amountIn);
        uint256 hub = _quoteV4(_ethUsdgV4(), true, amountIn);
        uint256 fee = (hub * 20) / 10_000;

        vm.prank(user);
        uint256 out = router.swap{value: amountIn}(
            address(0), USDG, amountIn, hub - fee, user, USDG, Legs.v4(_ethUsdgV4(), true, true), Legs.none()
        );

        assertEq(out, hub - fee);
        assertEq(_bal(USDG, user), hub - fee);
        assertEq(user.balance, 0);
        _assertRouterHoldsNothing();
    }

    function test_walletSwap_ethOut_v4NativePool() public {
        uint256 amountIn = 500e6;
        deal(USDG, user, amountIn);
        uint256 hubOut = _quoteV4(_ethUsdgV4(), false, amountIn);
        uint256 fee = (hubOut * 20) / 10_000;

        vm.startPrank(user);
        IERC20(USDG).approve(address(router), amountIn);
        // The hub is WETH: the leg pays native ETH, the router wraps it, takes the fee in WETH and pays ETH out.
        uint256 out = router.swap(USDG, address(0), amountIn, hubOut - fee, user, WETH, Legs.v4(_ethUsdgV4(), false, false), Legs.none());
        vm.stopPrank();

        assertEq(out, hubOut - fee);
        assertEq(user.balance, hubOut - fee);
        assertEq(_bal(WETH, address(buyback)), fee / 2);
        _assertRouterHoldsNothing();
    }

    /// @dev A token the Ostra launchpad launched (the first launch on chain 4663, block 92,738,855, paired with
    ///      USDG): bought and sold back through the router, so the Ostra hook runs with the Universal Router as its
    ///      swapper, as for any wallet.
    function test_walletSwap_ostraLaunchpadToken_buyAndSell() public {
        address hook = 0x63A784afb8905452aDceC471a45E555F5caE68cC;
        address token = 0x8f11Ce6A5c28c2064f69540C7C8471127683d3aA;
        PoolKey memory key = IOstraHookKeys(hook).poolKey(0x6863ce533fe2583ebbe633008679e03b84e043c330686df696500fc382c81219);
        assertEq(key.hooks, hook);
        bool usdgIs0 = key.currency0 == USDG;
        assertEq(usdgIs0 ? key.currency1 : key.currency0, token);

        uint256 amountIn = 20e6;
        deal(USDG, user, amountIn);
        uint256 net = amountIn - (amountIn * 20) / 10_000;
        uint256 quoted = _quoteV4(key, usdgIs0, net);
        vm.startPrank(user);
        IERC20(USDG).approve(address(router), amountIn);
        uint256 bought = router.swap(USDG, token, amountIn, (quoted * 99) / 100, user, USDG, Legs.none(), Legs.v4(key, usdgIs0, false));
        assertGe(bought, (quoted * 99) / 100);
        assertEq(_bal(token, user), bought);

        IERC20(token).approve(address(router), bought);
        uint256 back = router.swap(token, USDG, bought, 1, user, USDG, Legs.v4(key, !usdgIs0, false), Legs.none());
        vm.stopPrank();
        assertGt(back, 0);
        assertEq(_bal(USDG, user), back);
        assertEq(_bal(token, address(router)), 0);
        _assertRouterHoldsNothing();
    }

    function test_walletSwap_belowMinOut_reverts() public {
        uint256 amountIn = 1_000e6;
        deal(USDG, user, amountIn);
        uint256 expected = _quoteV3(USDG, 500, NVDA, amountIn - (amountIn * 20) / 10_000);
        vm.startPrank(user);
        IERC20(USDG).approve(address(router), amountIn);
        vm.expectRevert(abi.encodeWithSelector(OstraRouter.TooLittleReceived.selector, expected + 1, expected));
        router.swap(USDG, NVDA, amountIn, expected + 1, user, USDG, Legs.none(), Legs.v3(USDG, 500, NVDA));
        vm.stopPrank();
    }

    /// @dev Independent review, 20 Oct 2026: 1,000,000 USDG into the thin NVDA/USDG v3 pool at 1% runs it dry, so
    ///      the Universal Router swaps only part of the input and keeps the rest, which anyone could sweep. A leg
    ///      that leaves any of its input there is refused, and the sender keeps everything.
    function test_walletSwap_poolRunningDry_reverts() public {
        uint256 amountIn = 1_000_000e6;
        assertTrue(IUniswapV3Factory(V3_FACTORY).getPool(USDG, NVDA, 10_000) != address(0));
        deal(USDG, user, amountIn);
        vm.startPrank(user);
        IERC20(USDG).approve(address(router), amountIn);
        vm.expectRevert(OstraRouter.LegLeftInput.selector);
        router.swap(USDG, NVDA, amountIn, 1, user, USDG, Legs.none(), Legs.v3(USDG, 10_000, NVDA));
        vm.stopPrank();
        assertEq(_bal(USDG, user), amountIn);
    }

    function test_walletSwap_refusesBadHubAndLegs() public {
        deal(USDG, user, 100e6);
        vm.startPrank(user);
        IERC20(USDG).approve(address(router), 100e6);
        vm.expectRevert(OstraRouter.BadHub.selector);
        router.swap(USDG, NVDA, 100e6, 0, user, NVDA, Legs.none(), Legs.none());
        // tokenIn is the hub: a leg in makes no sense.
        vm.expectRevert(OstraRouter.BadLeg.selector);
        router.swap(USDG, NVDA, 100e6, 0, user, USDG, Legs.v3(USDG, 500, NVDA), Legs.v3(USDG, 500, NVDA));
        vm.expectRevert(OstraRouter.SameToken.selector);
        router.swap(USDG, USDG, 100e6, 0, user, USDG, Legs.none(), Legs.none());
        vm.stopPrank();
    }

    /// @dev A leg whose commands pay the output to someone else gives the router nothing: the swap misses minOut
    ///      and reverts, so the caller keeps its input.
    function test_walletSwap_legPayingElsewhere_reverts() public {
        address thief = makeAddr("thief");
        OstraRouter.Leg memory leg = Legs.v3(USDG, 500, NVDA);
        leg.inputs[0] = abi.encode(thief, Legs.CONTRACT_BALANCE, uint256(0), abi.encodePacked(USDG, uint24(500), NVDA), false, new uint256[](0));
        deal(USDG, user, 100e6);
        vm.startPrank(user);
        IERC20(USDG).approve(address(router), 100e6);
        vm.expectRevert(abi.encodeWithSelector(OstraRouter.TooLittleReceived.selector, 1, 0));
        router.swap(USDG, NVDA, 100e6, 1, user, USDG, Legs.none(), leg);
        vm.stopPrank();
        assertEq(_bal(USDG, user), 100e6);
        assertEq(_bal(NVDA, thief), 0);
    }

    function test_router_refusesStrayEth() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool ok,) = address(router).call{value: 1 ether}("");
        assertFalse(ok);
    }

    // ---------------------------------------------------------------------------------------------
    // OSTRA lock and fee tiers
    // ---------------------------------------------------------------------------------------------

    /// @dev Buys OSTRA on its Pons bonding curve with real ETH, for `to`.
    function _buyOstra(address to, uint256 ethIn) internal returns (uint256 got) {
        vm.deal(to, ethIn);
        uint256 before = _bal(OSTRA, to);
        vm.prank(to);
        IPonsCurveBuy(OSTRA_CURVE).buy{value: ethIn}(ethIn, 1, to);
        got = _bal(OSTRA, to) - before;
        assertGt(got, 0);
    }

    function _one(address a) internal pure returns (address[] memory list) {
        list = new address[](1);
        list[0] = a;
    }

    function _two(address a, address b) internal pure returns (address[] memory list) {
        list = new address[](2);
        list[0] = a;
        list[1] = b;
    }

    function test_stake_tiers_lockAndWithdraw() public {
        assertEq(stake.feeBps(user), 20);
        // A curve buy of 0.01 ETH got about 1.9 million OSTRA on 20 Oct 2026: 0.05 ETH covers every tier.
        uint256 have = _buyOstra(user, 0.05 ether);
        assertGe(have, 500_000e18);

        vm.startPrank(user);
        IERC20(OSTRA).approve(address(stake), type(uint256).max);
        stake.lock(100_000e18, _one(user));
        assertEq(stake.lockedFor(user), 100_000e18);
        assertEq(stake.feeBps(user), 15);
        stake.lock(150_000e18, _one(user));
        assertEq(stake.feeBps(user), 10);
        stake.lock(250_000e18, _one(user));
        assertEq(stake.lockedFor(user), 500_000e18);
        assertEq(stake.feeBps(user), 0);

        // Locked for 7 days from the last lock.
        (, uint40 unlockAt,) = stake.positionOf(user);
        assertEq(unlockAt, block.timestamp + 7 days);
        vm.expectRevert(abi.encodeWithSelector(OstraStake.StillLocked.selector, unlockAt));
        stake.withdraw();

        // While locked the list only grows (independent review: no lending the tier per transaction): two vaults
        // join the wallet, and changing the list locks it again; dropping one waits for the lock to run out.
        address vaultA = makeAddr("vaultA");
        address vaultB = makeAddr("vaultB");
        vm.warp(block.timestamp + 3 days);
        address[] memory three = new address[](3);
        three[0] = user;
        three[1] = vaultA;
        three[2] = vaultB;
        vm.expectRevert(abi.encodeWithSelector(OstraStake.BeneficiariesLocked.selector, unlockAt));
        stake.lock(0, _two(vaultA, vaultB));
        stake.lock(0, three);
        assertEq(stake.feeBps(user), 0);
        assertEq(stake.feeBps(vaultA), 0);
        assertEq(stake.feeBps(vaultB), 0);
        (, unlockAt,) = stake.positionOf(user);
        assertEq(unlockAt, block.timestamp + 7 days);
        vm.expectRevert(OstraStake.NothingToLock.selector);
        stake.lock(0, three);
        vm.expectRevert(abi.encodeWithSelector(OstraStake.BeneficiariesLocked.selector, unlockAt));
        stake.lock(0, _one(vaultA));
        vm.warp(unlockAt);
        stake.lock(0, _one(vaultA));
        assertEq(stake.lockedFor(user), 0);
        assertEq(stake.lockedFor(vaultB), 0);
        assertEq(stake.lockedFor(vaultA), 500_000e18);

        // Bad lists.
        vm.expectRevert(OstraStake.BadBeneficiaries.selector);
        stake.lock(0, new address[](0));
        vm.expectRevert(OstraStake.BadBeneficiaries.selector);
        stake.lock(0, _two(vaultA, vaultA));
        vm.expectRevert(OstraStake.BadBeneficiaries.selector);
        stake.lock(0, _one(address(0)));
        vm.expectRevert(OstraStake.BadBeneficiaries.selector);
        stake.lock(0, new address[](9));

        (, unlockAt,) = stake.positionOf(user);
        vm.warp(unlockAt);
        uint256 before = _bal(OSTRA, user);
        stake.withdraw();
        vm.stopPrank();
        assertEq(_bal(OSTRA, user) - before, 500_000e18);
        assertEq(stake.lockedFor(vaultA), 0);
        assertEq(stake.feeBps(vaultA), 20);
        vm.prank(user);
        vm.expectRevert(OstraStake.NothingToWithdraw.selector);
        stake.withdraw();
    }

    function test_walletSwap_feeFollowsLock() public {
        _buyOstra(user, 0.05 ether);
        vm.startPrank(user);
        IERC20(OSTRA).approve(address(stake), type(uint256).max);
        stake.lock(250_000e18, _one(user));
        vm.stopPrank();

        uint256 amountIn = 1_000e6;
        uint256 fee = (amountIn * 10) / 10_000;
        uint256 expected = _quoteV3(USDG, 500, NVDA, amountIn - fee);
        deal(USDG, user, amountIn);
        vm.startPrank(user);
        IERC20(USDG).approve(address(router), amountIn);
        router.swap(USDG, NVDA, amountIn, expected, user, USDG, Legs.none(), Legs.v3(USDG, 500, NVDA));
        vm.stopPrank();
        assertEq(_bal(NVDA, user), expected);
        assertEq(_bal(USDG, address(buyback)), fee / 2);

        // 500,000 locked: no fee at all.
        vm.startPrank(user);
        stake.lock(250_000e18, _one(user));
        vm.stopPrank();
        expected = _quoteV3(USDG, 500, NVDA, amountIn);
        deal(USDG, user, amountIn);
        uint256 buybackBefore = _bal(USDG, address(buyback));
        vm.startPrank(user);
        IERC20(USDG).approve(address(router), amountIn);
        router.swap(USDG, NVDA, amountIn, expected, user, USDG, Legs.none(), Legs.v3(USDG, 500, NVDA));
        vm.stopPrank();
        assertEq(_bal(USDG, address(buyback)), buybackBefore);
    }

    /// @dev swapAtBaseFee charges the base fee whatever is locked for the sender; swap from the same sender is free.
    function test_walletSwap_atBaseFee_ignoresTheLock() public {
        _buyOstra(user, 0.05 ether);
        vm.startPrank(user);
        IERC20(OSTRA).approve(address(stake), type(uint256).max);
        stake.lock(500_000e18, _one(user));
        vm.stopPrank();
        assertEq(stake.feeBps(user), 0);

        uint256 amountIn = 1_000e6;
        uint256 fee = (amountIn * 20) / 10_000;
        uint256 expected = _quoteV3(USDG, 500, NVDA, amountIn - fee);
        uint256 treasuryBefore = _bal(USDG, TREASURY);
        address to = makeAddr("to");
        deal(USDG, user, amountIn);
        vm.startPrank(user);
        IERC20(USDG).approve(address(router), amountIn);
        vm.expectEmit(address(router));
        emit OstraRouter.Swapped(user, USDG, NVDA, amountIn, expected, USDG, fee, 20, to);
        uint256 out = router.swapAtBaseFee(USDG, NVDA, amountIn, expected, to, USDG, Legs.none(), Legs.v3(USDG, 500, NVDA));
        vm.stopPrank();
        assertEq(out, expected);
        assertEq(_bal(NVDA, to), expected);
        assertEq(_bal(USDG, address(buyback)), fee / 2);
        assertEq(_bal(USDG, TREASURY) - treasuryBefore, fee - fee / 2);
        _assertRouterHoldsNothing();

        // The same sender through swap: its lock applies, no fee.
        expected = _quoteV3(USDG, 500, NVDA, amountIn);
        deal(USDG, user, amountIn);
        vm.startPrank(user);
        IERC20(USDG).approve(address(router), amountIn);
        vm.expectEmit(address(router));
        emit OstraRouter.Swapped(user, USDG, NVDA, amountIn, expected, USDG, 0, 0, user);
        router.swap(USDG, NVDA, amountIn, expected, user, USDG, Legs.none(), Legs.v3(USDG, 500, NVDA));
        vm.stopPrank();
        assertEq(_bal(USDG, address(buyback)), fee / 2);
    }

    // ---------------------------------------------------------------------------------------------
    // Vault swaps through an escrow
    // ---------------------------------------------------------------------------------------------

    function _seed(uint64 index) internal pure returns (bytes32) {
        return WotsSigner.deriveSeed(MASTER, VAULT_KEYCHAIN, index);
    }

    function _newVault(address token, uint256 amount) internal returns (IOstraVault vault) {
        vault = IOstraVault(IOstraVaultFactory(VAULT_FACTORY).createVault(token, WotsSigner.keyRoot(_seed(0)), address(0)));
        deal(token, address(vault), amount);
    }

    /// @dev The vault's WOTS key signs a Transfer of `amount` to `to`.
    function _spendCall(IOstraVault vault, address to, uint256 amount) internal view returns (bytes memory) {
        uint64 n = vault.nonce();
        bytes32 next = WotsSigner.keyRoot(_seed(n + 1));
        bytes memory params = abi.encode(to, amount);
        bytes memory signature = WotsSigner.sign(_seed(n), vault.spendMessage(ACTION_TRANSFER, next, params));
        return abi.encodeCall(IOstraVault.spend, (ACTION_TRANSFER, next, params, signature));
    }

    function _transfer(IOstraVault vault, address to, uint256 amount) internal {
        (bool ok,) = address(vault).call(_spendCall(vault, to, amount));
        assertTrue(ok);
    }

    /// @dev An order from a USDG vault to NVDA through the USDG hub along `legOut`.
    function _order(IOstraVault vault, uint256 amountIn, uint256 minOut, address recipient, OstraRouter.Leg memory legOut)
        internal
        view
        returns (OstraRouter.Order memory)
    {
        return OstraRouter.Order({
            tokenIn: USDG,
            tokenOut: NVDA,
            amountIn: amountIn,
            minOut: minOut,
            recipient: recipient,
            refundTo: address(vault),
            notBefore: 0,
            deadline: uint64(block.timestamp + 600),
            tranches: 0,
            interval: 0,
            executor: address(0),
            canceller: address(0),
            route: router.routeHash(USDG, Legs.none(), legOut),
            salt: keccak256(abi.encode("salt", address(vault), amountIn, minOut))
        });
    }

    /// @dev The relayer's transaction: Multicall3 [vault.spend(Transfer to escrow), router.executeEscrow], every
    ///      call required to succeed, with `gasLimit`. Returns whether the transaction succeeded.
    function _relay(IOstraVault vault, OstraRouter.Order memory o, OstraRouter.Leg memory legOut, uint256 gasLimit)
        internal
        returns (bool ok)
    {
        IMulticall3.Call3[] memory calls = new IMulticall3.Call3[](2);
        calls[0] = IMulticall3.Call3(address(vault), false, _spendCall(vault, router.escrowAddress(o), o.amountIn));
        calls[1] = IMulticall3.Call3(address(router), false, abi.encodeCall(OstraRouter.executeEscrow, (o, USDG, Legs.none(), legOut)));
        (ok,) = MULTICALL3.call{gas: gasLimit}(abi.encodeCall(IMulticall3.aggregate3, (calls)));
    }

    function test_escrow_vaultSwap_relayedInOneTransaction() public {
        uint256 amountIn = 250e6;
        IOstraVault vault = _newVault(USDG, amountIn);
        address nvdaVault = makeAddr("nvdaVault");
        uint256 fee = (amountIn * 20) / 10_000;
        uint256 expected = _quoteV3(USDG, 500, NVDA, amountIn - fee);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _order(vault, amountIn, expected, nvdaVault, legOut);
        address escrow = router.escrowAddress(o);
        assertEq(escrow.code.length, 0);

        vm.expectEmit(address(router));
        emit OstraRouter.EscrowExecuted(router.orderHash(o), escrow, amountIn, true);
        assertTrue(_relay(vault, o, legOut, 3_000_000));

        assertEq(vault.nonce(), 1);
        assertEq(_bal(NVDA, nvdaVault), expected);
        assertEq(_bal(USDG, address(vault)), 0);
        assertEq(_bal(USDG, escrow), 0);
        assertEq(_bal(USDG, address(buyback)), fee / 2);
        assertGt(escrow.code.length, 0);
        assertEq(OstraSwapEscrow(escrow).ROUTER(), address(router));
        _assertRouterHoldsNothing();

        // The same order again finds nothing in the escrow and moves nothing.
        (bool swapped, uint256 out) = router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertFalse(swapped);
        assertEq(out, 0);
    }

    /// @dev Gas of a vault swap's two calls (the relayer prices them from its own simulation; this is for the record).
    function test_gas_escrowSwap() public {
        uint256 amountIn = 250e6;
        IOstraVault vault = _newVault(USDG, amountIn);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _order(vault, amountIn, 1, user, legOut);
        bytes memory spend = _spendCall(vault, router.escrowAddress(o), amountIn);
        uint256 g = gasleft();
        (bool ok,) = address(vault).call(spend);
        uint256 spendGas = g - gasleft();
        assertTrue(ok);
        g = gasleft();
        (bool swapped,) = router.executeEscrow(o, USDG, Legs.none(), legOut);
        uint256 executeGas = g - gasleft();
        assertTrue(swapped);
        console.log("vault Transfer spend gas", spendGas);
        console.log("executeEscrow gas (escrow deploy + v3 swap)", executeGas);
    }

    /// @dev The fee of an escrow swap is the recipient's: a lock naming the vault that gets the output lowers it.
    function test_escrow_feeIsTheRecipients() public {
        uint256 amountIn = 250e6;
        IOstraVault vault = _newVault(USDG, amountIn);
        address nvdaVault = makeAddr("nvdaVault");
        _buyOstra(user, 0.05 ether);
        vm.startPrank(user);
        IERC20(OSTRA).approve(address(stake), type(uint256).max);
        stake.lock(100_000e18, _two(address(vault), nvdaVault));
        vm.stopPrank();
        assertEq(stake.feeBps(nvdaVault), 15);

        uint256 fee = (amountIn * 15) / 10_000;
        uint256 expected = _quoteV3(USDG, 500, NVDA, amountIn - fee);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _order(vault, amountIn, expected, nvdaVault, legOut);
        assertTrue(_relay(vault, o, legOut, 3_000_000));
        assertEq(_bal(NVDA, nvdaVault), expected);
        assertEq(_bal(USDG, address(buyback)), fee / 2);
    }

    /// @dev Independent review, finding 2: an order funded by anyone that names a big holder as refundTo pays the
    ///      full fee, because the fee is the recipient's.
    function test_escrow_namingAHoldersRefundToGainsNothing() public {
        address whale = makeAddr("whale");
        _buyOstra(whale, 0.05 ether);
        vm.startPrank(whale);
        IERC20(OSTRA).approve(address(stake), type(uint256).max);
        stake.lock(500_000e18, _one(whale));
        vm.stopPrank();

        uint256 amountIn = 1_000e6;
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        uint256 fee = (amountIn * 20) / 10_000;
        uint256 expected = _quoteV3(USDG, 500, NVDA, amountIn - fee);
        OstraRouter.Order memory o = OstraRouter.Order({
            tokenIn: USDG,
            tokenOut: NVDA,
            amountIn: amountIn,
            minOut: 1,
            recipient: user,
            refundTo: whale,
            notBefore: 0,
            deadline: uint64(block.timestamp + 600),
            tranches: 0,
            interval: 0,
            executor: address(0),
            canceller: address(0),
            route: router.routeHash(USDG, Legs.none(), legOut),
            salt: bytes32(uint256(7))
        });
        deal(USDG, user, amountIn);
        vm.startPrank(user);
        IERC20(USDG).transfer(router.escrowAddress(o), amountIn);
        (bool swapped, uint256 out) = router.executeEscrow(o, USDG, Legs.none(), legOut);
        vm.stopPrank();
        assertTrue(swapped);
        assertEq(out, expected);
        assertEq(_bal(USDG, address(buyback)), fee / 2);
    }

    function test_escrow_missedMinOut_refundsAndKeyMovedOn() public {
        uint256 amountIn = 250e6;
        IOstraVault vault = _newVault(USDG, amountIn);
        uint256 expected = _quoteV3(USDG, 500, NVDA, amountIn - (amountIn * 20) / 10_000);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _order(vault, amountIn, expected + 1, user, legOut);
        address escrow = router.escrowAddress(o);

        vm.expectEmit(address(router));
        emit OstraRouter.EscrowRefunded(
            router.orderHash(o),
            address(vault),
            USDG,
            amountIn,
            0,
            abi.encodeWithSelector(OstraRouter.TooLittleReceived.selector, expected + 1, expected)
        );
        assertTrue(_relay(vault, o, legOut, 3_000_000));
        assertEq(_bal(USDG, address(vault)), amountIn);
        assertEq(_bal(USDG, escrow), 0);
        assertEq(_bal(NVDA, user), 0);
        assertEq(_bal(USDG, address(buyback)), 0);
        // The spend landed: the vault's key moved on, and the next spend signs with the next key.
        assertEq(vault.nonce(), 1);
        _transfer(vault, user, 1e6);
        assertEq(vault.nonce(), 2);
        _assertRouterHoldsNothing();
    }

    function test_escrow_afterDeadline_refunds() public {
        uint256 amountIn = 100e6;
        IOstraVault vault = _newVault(USDG, amountIn);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _order(vault, amountIn, 0, user, legOut);
        _transfer(vault, router.escrowAddress(o), amountIn);
        vm.warp(uint256(o.deadline) + 1);
        vm.expectEmit(address(router));
        emit OstraRouter.EscrowRefunded(router.orderHash(o), address(vault), USDG, amountIn, 0, abi.encodeWithSelector(OstraRouter.OrderExpired.selector));
        (bool swapped,) = router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertFalse(swapped);
        assertEq(_bal(USDG, address(vault)), amountIn);
        assertEq(_bal(NVDA, user), 0);
    }

    function test_escrow_otherAmount_refundsAll() public {
        uint256 amountIn = 100e6;
        IOstraVault vault = _newVault(USDG, amountIn + 5e6);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _order(vault, amountIn, 0, user, legOut);
        address escrow = router.escrowAddress(o);
        _transfer(vault, escrow, amountIn + 5e6);
        (bool swapped,) = router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertFalse(swapped);
        assertEq(_bal(USDG, address(vault)), amountIn + 5e6);

        // Tokens sent to an escrow after it was used are swept to the order's refundTo by the next execution.
        deal(USDG, escrow, 7e6);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertEq(_bal(USDG, address(vault)), amountIn + 12e6);
        assertEq(_bal(USDG, escrow), 0);
    }

    /// @dev Independent review, finding 4: whoever executes an order cannot choose the route. Other legs than the
    ///      order's (here: legs paying a thief) are refused and the input goes back to the vault.
    function test_escrow_executorCannotChooseTheRoute() public {
        uint256 amountIn = 250e6;
        IOstraVault vault = _newVault(USDG, amountIn);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _order(vault, amountIn, 1, user, legOut);
        _transfer(vault, router.escrowAddress(o), amountIn);
        address thief = makeAddr("thief");
        OstraRouter.Leg memory skim;
        skim.commands = abi.encodePacked(bytes1(0x06), bytes1(0x00));
        skim.inputs = new bytes[](2);
        skim.inputs[0] = abi.encode(USDG, thief, uint256(90));
        skim.inputs[1] = legOut.inputs[0];
        vm.prank(thief);
        (bool swapped,) = router.executeEscrow(o, USDG, Legs.none(), skim);
        assertFalse(swapped);
        assertEq(_bal(USDG, thief), 0);
        assertEq(_bal(USDG, address(vault)), amountIn);
        // Another hub is another route too.
        OstraRouter.Order memory o2 = _order(vault, amountIn, 1, user, legOut);
        o2.salt = bytes32(uint256(2));
        _transfer(vault, router.escrowAddress(o2), amountIn);
        (swapped,) = router.executeEscrow(o2, WETH, Legs.none(), legOut);
        assertFalse(swapped);
        assertEq(_bal(USDG, address(vault)), amountIn);
    }

    /// @dev An escrow's address binds every term: another minOut, recipient, deadline or route is another address.
    function test_escrow_addressBindsTheOrder() public view {
        IOstraVault vault = IOstraVault(address(0x1234));
        OstraRouter.Order memory o = _order(vault, 100e6, 5, user, Legs.v3(USDG, 500, NVDA));
        address a = router.escrowAddress(o);
        o.minOut = 4;
        assertTrue(router.escrowAddress(o) != a);
        o.minOut = 5;
        o.recipient = address(0xBEEF);
        assertTrue(router.escrowAddress(o) != a);
        o.recipient = user;
        o.deadline += 1;
        assertTrue(router.escrowAddress(o) != a);
        o.deadline -= 1;
        o.route = router.routeHash(USDG, Legs.none(), Legs.v3(USDG, 3000, NVDA));
        assertTrue(router.escrowAddress(o) != a);
        o.route = router.routeHash(USDG, Legs.none(), Legs.v3(USDG, 500, NVDA));
        assertEq(router.escrowAddress(o), a);
    }

    // ---------------------------------------------------------------------------------------------
    // Hostile pools: executeEscrow never reverts, the vault's spend always lands
    // ---------------------------------------------------------------------------------------------

    /// @dev A v4 pool USDG/NVDA whose hook (BEFORE_SWAP flag) runs `runtime`.
    function _hookPool(bytes memory runtime, uint256 tag) internal returns (PoolKey memory key) {
        address hook = address(uint160((uint256(keccak256(abi.encode("hook", tag))) & ~uint256(0x3fff)) | 0x80));
        vm.etch(hook, runtime);
        key = PoolKey({currency0: USDG, currency1: NVDA, fee: 3000, tickSpacing: 60, hooks: hook});
        IPoolManagerInit(POOL_MANAGER).initialize(key, 79228162514264337593543950336);
    }

    /// @dev Relays a vault swap through a hostile pool at several gas limits: every relay lands, the key moves on,
    ///      and the vault gets its USDG back.
    function _assertRefundsAtEveryGasLimit(bytes memory hookRuntime, uint256 tag) internal {
        PoolKey memory key = _hookPool(hookRuntime, tag);
        OstraRouter.Leg memory legOut = Legs.v4(key, true, false);
        uint256[5] memory limits = [uint256(1_000_000), 2_000_000, 3_000_000, 6_000_000, 15_000_000];
        for (uint256 i; i < limits.length; i++) {
            uint256 snap = vm.snapshotState();
            IOstraVault vault = _newVault(USDG, 100e6);
            OstraRouter.Order memory o = _order(vault, 100e6, 1, user, legOut);
            assertTrue(_relay(vault, o, legOut, limits[i]), "the relayer's transaction landed");
            assertEq(vault.nonce(), 1, "the key moved on");
            assertEq(_bal(USDG, address(vault)), 100e6, "refunded");
            vm.revertToState(snap);
        }
    }

    /// @dev Independent review, finding 1: a hook reverting with a payload sized to its gas (a return bomb).
    function test_hostile_returnBombHook_refunds() public {
        _assertRefundsAtEveryGasLimit(type(AdaptiveBombHook).runtimeCode, 1);
    }

    function test_hostile_largeRevertHook_refunds() public {
        _assertRefundsAtEveryGasLimit(type(BombHook).runtimeCode, 2);
    }

    function test_hostile_gasBurnHook_refunds() public {
        _assertRefundsAtEveryGasLimit(type(GasBurnHook).runtimeCode, 3);
    }

    function test_hostile_plainRevertHook_refunds() public {
        _assertRefundsAtEveryGasLimit(type(PlainRevertHook).runtimeCode, 4);
    }

    /// @dev Independent review, finding 6: scanning the gas executeEscrow gets, a failure is only ever running out of
    ///      gas itself (no panic, no revert data), never a revert of its own.
    function test_escrow_gasScan_noOwnRevert() public {
        IOstraVault vault = _newVault(USDG, 250e6);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _order(vault, 250e6, 1, user, legOut);
        _transfer(vault, router.escrowAddress(o), 250e6);
        bytes memory data = abi.encodeCall(OstraRouter.executeEscrow, (o, USDG, Legs.none(), legOut));
        uint256 snap = vm.snapshotState();
        for (uint256 g = 200_000; g < 700_000; g += 997) {
            vm.revertToState(snap);
            (bool ok, bytes memory ret) = address(router).call{gas: g}(data);
            if (!ok) assertEq(ret.length, 0, "a failure is out of gas, never a revert");
        }
    }

    /// @dev Independent re-review: the relayer's transaction, stepped through gas limits, never reverts above the
    ///      lowest limit at which it lands (it refunds, then swaps, as the gas grows), so a gas limit set above a
    ///      simulation that swapped can only swap or refund, never revert the vault's spend.
    function test_escrow_relayGasLimits_neverRevertAboveTheFirstLanding() public {
        IOstraVault vault = _newVault(USDG, 250e6);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _order(vault, 250e6, 1, user, legOut);
        IMulticall3.Call3[] memory calls = new IMulticall3.Call3[](2);
        calls[0] = IMulticall3.Call3(address(vault), false, _spendCall(vault, router.escrowAddress(o), o.amountIn));
        calls[1] = IMulticall3.Call3(address(router), false, abi.encodeCall(OstraRouter.executeEscrow, (o, USDG, Legs.none(), legOut)));
        bytes memory data = abi.encodeCall(IMulticall3.aggregate3, (calls));
        uint256 snap = vm.snapshotState();
        bool landed;
        bool swappedOnce;
        for (uint256 g = 300_000; g < 1_300_000; g += 4_999) {
            vm.revertToState(snap);
            (bool ok,) = MULTICALL3.call{gas: g}(data);
            if (landed) assertTrue(ok, "no revert above the first landing gas limit");
            if (ok) {
                landed = true;
                assertEq(vault.nonce(), 1);
                bool swapped = _bal(NVDA, user) > 0;
                if (swappedOnce) assertTrue(swapped, "more gas never turns a swap back into a refund");
                if (swapped) swappedOnce = true;
                else assertEq(_bal(USDG, address(vault)), 250e6);
            }
        }
        assertTrue(landed && swappedOnce);
    }

    function test_escrow_routerAsRecipient_refunds() public {
        IOstraVault vault = _newVault(USDG, 100e6);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _order(vault, 100e6, 1, address(router), legOut);
        assertTrue(_relay(vault, o, legOut, 3_000_000));
        assertEq(_bal(USDG, address(vault)), 100e6);
        _assertRouterHoldsNothing();
    }

    // ---------------------------------------------------------------------------------------------
    // Standing orders: limit, take-profit, DCA
    // ---------------------------------------------------------------------------------------------

    address internal canceller = makeAddr("canceller");

    /// @dev A standing order from a USDG vault to NVDA in `tranches`, run by the keeper along `legOut` (route
    ///      bound) or, with `openRoute`, along a route the keeper chooses. Thirty days to run; the canceller key may
    ///      send it back to the vault at any time.
    function _standing(
        IOstraVault vault,
        uint256 amountIn,
        uint256 minOut,
        address recipient,
        OstraRouter.Leg memory legOut,
        uint32 tranches,
        uint32 interval,
        bool openRoute
    ) internal view returns (OstraRouter.Order memory) {
        return OstraRouter.Order({
            tokenIn: USDG,
            tokenOut: NVDA,
            amountIn: amountIn,
            minOut: minOut,
            recipient: recipient,
            refundTo: address(vault),
            notBefore: uint64(block.timestamp),
            deadline: uint64(block.timestamp + 30 days),
            tranches: tranches,
            interval: interval,
            executor: keeper,
            canceller: canceller,
            route: openRoute ? bytes32(0) : router.routeHash(USDG, Legs.none(), legOut),
            salt: keccak256(abi.encode("standing", address(vault), amountIn, minOut, tranches))
        });
    }

    /// @dev Places a standing order the way the relayer does: Multicall3 [vault.spend(Transfer to the escrow),
    ///      router.announce(order)], the spend required, the announcement allowed to fail.
    function _place(IOstraVault vault, OstraRouter.Order memory o) internal returns (address escrow) {
        escrow = router.escrowAddress(o);
        IMulticall3.Call3[] memory calls = new IMulticall3.Call3[](2);
        calls[0] = IMulticall3.Call3(address(vault), false, _spendCall(vault, escrow, o.amountIn));
        calls[1] = IMulticall3.Call3(address(router), true, abi.encodeCall(OstraRouter.announce, (o)));
        vm.expectEmit(address(router));
        emit OstraRouter.OrderAnnounced(router.orderHash(o), escrow, o.amountIn, o);
        IMulticall3(MULTICALL3).aggregate3(calls);
        assertEq(_bal(USDG, escrow), o.amountIn);
        assertEq(_bal(USDG, address(vault)), 0);
    }

    /// @dev Sells `amount` NVDA for USDG in the NVDA/USDG v3 pool (fee 500) from a whale: NVDA gets cheaper.
    function _dumpNvda(uint256 amount) internal {
        address whale = makeAddr("nvdaWhale");
        deal(NVDA, whale, amount);
        vm.startPrank(whale);
        IERC20(NVDA).approve(address(router), amount);
        router.swap(NVDA, USDG, amount, 1, whale, USDG, Legs.v3(NVDA, 500, USDG), Legs.none());
        vm.stopPrank();
    }

    /// @dev Real sales of NVDA, each twice the one before (10 NVDA first, at most 12 sales), until `hubIn` USDG
    ///      buys at least `asked` NVDA; returns what it buys then. The sizes needed follow the pool's liquidity on
    ///      the day the fork is taken.
    function _sellNvdaUntil(uint256 hubIn, uint256 asked) internal returns (uint256 now_) {
        uint256 sale = 10e18;
        now_ = _quoteV3(USDG, 500, NVDA, hubIn);
        for (uint256 i; i < 12 && now_ < asked; i++) {
            _dumpNvda(sale);
            now_ = _quoteV3(USDG, 500, NVDA, hubIn);
            sale *= 2;
        }
        assertGe(now_, asked, "the market reached the ask");
    }

    /// @dev A limit order asking 2% more NVDA than the market gives: it waits in the escrow (the keeper's attempts
    ///      revert and move nothing) until a real sale of NVDA moves the pool, then fills at the price asked or
    ///      better, in full, the fee taken.
    function test_standing_limitOrder_waitsThenFills() public {
        uint256 amountIn = 500e6;
        IOstraVault vault = _newVault(USDG, amountIn);
        address nvdaVault = makeAddr("nvdaVault");
        uint256 fee = (amountIn * 20) / 10_000;
        uint256 market = _quoteV3(USDG, 500, NVDA, amountIn - fee);
        uint256 asked = (market * 102) / 100;
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _standing(vault, amountIn, asked, nvdaVault, legOut, 1, 0, false);
        address escrow = _place(vault, o);
        assertEq(vault.nonce(), 1);

        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(OstraRouter.TooLittleReceived.selector, asked, market));
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertEq(_bal(USDG, escrow), amountIn);

        uint256 now_ = _sellNvdaUntil(amountIn - fee, asked);

        vm.expectEmit(address(router));
        emit OstraRouter.TrancheExecuted(router.orderHash(o), 0, amountIn, now_);
        vm.prank(keeper);
        (bool swapped, uint256 out) = router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertTrue(swapped);
        assertEq(out, now_);
        assertGe(out, asked);
        assertEq(_bal(NVDA, nvdaVault), out);
        assertEq(_bal(USDG, escrow), 0);
        assertEq(_bal(USDG, address(vault)), 0);
        assertTrue(router.closed(router.orderHash(o)));
        assertEq(router.tranchesDone(router.orderHash(o)), 1);
        _assertRouterHoldsNothing();

        vm.prank(keeper);
        vm.expectRevert(OstraRouter.OrderIsClosed.selector);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
    }

    /// @dev A DCA in three tranches a day apart: each runs once its time has come, the last takes the remainder,
    ///      and the order closes.
    function test_standing_dca_threeTranches() public {
        uint256 amountIn = 300e6 + 2;
        IOstraVault vault = _newVault(USDG, amountIn);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _standing(vault, amountIn, 0, user, legOut, 3, 1 days, false);
        address escrow = _place(vault, o);
        bytes32 h = router.orderHash(o);
        uint256 t0 = block.timestamp;

        vm.prank(keeper);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertEq(_bal(USDG, escrow), amountIn - 100e6);
        assertEq(router.tranchesDone(h), 1);

        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(OstraRouter.NotYet.selector, t0 + 1 days));
        router.executeEscrow(o, USDG, Legs.none(), legOut);

        vm.warp(t0 + 1 days);
        vm.prank(keeper);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertEq(_bal(USDG, escrow), 100e6 + 2);

        vm.warp(t0 + 2 days);
        uint256 last = amountIn - 200e6;
        assertEq(last, 100e6 + 2);
        uint256 lastOut = _quoteV3(USDG, 500, NVDA, last - (last * 20) / 10_000);
        vm.expectEmit(address(router));
        emit OstraRouter.TrancheExecuted(h, 2, last, lastOut);
        vm.prank(keeper);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertEq(_bal(USDG, escrow), 0);
        assertEq(router.tranchesDone(h), 3);
        assertTrue(router.closed(h));
        assertGt(_bal(NVDA, user), 0);
        _assertRouterHoldsNothing();
    }

    /// @dev A tranche's fee is the recipient's, like an immediate order's: a lock naming the recipient lowers it.
    function test_standing_trancheFeeIsTheRecipients() public {
        _buyOstra(user, 0.05 ether);
        vm.startPrank(user);
        IERC20(OSTRA).approve(address(stake), type(uint256).max);
        stake.lock(100_000e18, _one(user));
        vm.stopPrank();
        assertEq(stake.feeBps(user), 15);

        uint256 amountIn = 200e6;
        IOstraVault vault = _newVault(USDG, amountIn);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _standing(vault, amountIn, 0, user, legOut, 1, 0, false);
        _place(vault, o);
        uint256 fee = (amountIn * 15) / 10_000;
        uint256 expected = _quoteV3(USDG, 500, NVDA, amountIn - fee);
        vm.expectEmit(address(router));
        emit OstraRouter.Swapped(user, USDG, NVDA, amountIn, expected, USDG, fee, 15, user);
        vm.prank(keeper);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertEq(_bal(NVDA, user), expected);
        assertEq(_bal(USDG, address(buyback)), fee / 2);
    }

    /// @dev Each tranche is held to its share of minOut (rounded up): a share the market cannot meet reverts.
    function test_standing_trancheHeldToItsShareOfMinOut() public {
        uint256 amountIn = 200e6;
        IOstraVault vault = _newVault(USDG, amountIn);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        uint256 half = 100e6;
        uint256 market = _quoteV3(USDG, 500, NVDA, half - (half * 20) / 10_000);
        OstraRouter.Order memory o = _standing(vault, amountIn, 2 * market + 1, user, legOut, 2, 1 hours, false);
        _place(vault, o);
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(OstraRouter.TooLittleReceived.selector, market + 1, market));
        router.executeEscrow(o, USDG, Legs.none(), legOut);
    }

    function test_standing_onlyTheExecutorRunsTranches() public {
        IOstraVault vault = _newVault(USDG, 100e6);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _standing(vault, 100e6, 0, user, legOut, 1, 0, false);
        address escrow = _place(vault, o);
        vm.prank(user);
        vm.expectRevert(OstraRouter.NotExecutor.selector);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertEq(_bal(USDG, escrow), 100e6);
    }

    /// @dev The canceller key can only send the escrow back to the vault, never to itself; nobody else may close
    ///      an order before its deadline.
    function test_standing_cancel_returnsToTheVaultOnly() public {
        IOstraVault vault = _newVault(USDG, 100e6);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _standing(vault, 100e6, 0, user, legOut, 2, 1 days, false);
        address escrow = _place(vault, o);
        vm.prank(keeper);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertEq(_bal(USDG, escrow), 50e6);

        vm.prank(user);
        vm.expectRevert(OstraRouter.NotCanceller.selector);
        router.closeEscrow(o);

        vm.expectEmit(address(router));
        emit OstraRouter.OrderClosed(router.orderHash(o), 50e6, true);
        vm.prank(canceller);
        assertEq(router.closeEscrow(o), 50e6);
        assertEq(_bal(USDG, address(vault)), 50e6);
        assertEq(_bal(USDG, canceller), 0);
        assertEq(_bal(USDG, escrow), 0);

        vm.warp(block.timestamp + 1 days);
        vm.prank(keeper);
        vm.expectRevert(OstraRouter.OrderIsClosed.selector);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
    }

    /// @dev After the deadline anyone sends what is left back to the vault, through closeEscrow or executeEscrow.
    function test_standing_afterDeadline_anyoneRefunds() public {
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        IOstraVault vault = _newVault(USDG, 100e6);
        OstraRouter.Order memory o = _standing(vault, 100e6, type(uint128).max, user, legOut, 1, 0, false);
        _place(vault, o);
        vm.warp(uint256(o.deadline) + 1);
        vm.prank(user);
        assertEq(router.closeEscrow(o), 100e6);
        assertEq(_bal(USDG, address(vault)), 100e6);

        IOstraVault vault2 = _newVault(USDG, 100e6);
        OstraRouter.Order memory o2 = _standing(vault2, 100e6, 0, user, legOut, 1, 0, false);
        _place(vault2, o2);
        vm.warp(uint256(o2.deadline) + 1);
        vm.prank(user);
        (bool swapped, uint256 out) = router.executeEscrow(o2, USDG, Legs.none(), legOut);
        assertFalse(swapped);
        assertEq(out, 0);
        assertEq(_bal(USDG, address(vault2)), 100e6);
        assertEq(_bal(NVDA, user), 0);
    }

    /// @dev Independent review: legs an executor writes could pay the recipient its minimum and keep the rest, so
    ///      every tranche goes along the route the order binds. An order without one never runs (its canceller or
    ///      the deadline returns it), and the keeper's own legs (here: a swap to the Universal Router, TRANSFER of
    ///      the minimum, SWEEP of the rest to the keeper) are refused before anything moves.
    function test_standing_executorCannotWriteTheLegs() public {
        uint256 amountIn = 250e6;
        IOstraVault vault = _newVault(USDG, amountIn);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        uint256 market = _quoteV3(USDG, 500, NVDA, amountIn - (amountIn * 20) / 10_000);
        uint256 minOut = (market * 95) / 100;

        OstraRouter.Order memory open = _standing(vault, amountIn, minOut, user, legOut, 1, 0, true);
        address openEscrow = _place(vault, open);
        OstraRouter.Leg memory skim;
        skim.commands = abi.encodePacked(bytes1(0x00), bytes1(0x05), bytes1(0x04));
        skim.inputs = new bytes[](3);
        skim.inputs[0] = abi.encode(address(2), Legs.CONTRACT_BALANCE, uint256(0), abi.encodePacked(USDG, uint24(500), NVDA), false, new uint256[](0));
        skim.inputs[1] = abi.encode(NVDA, address(1), minOut);
        skim.inputs[2] = abi.encode(NVDA, keeper, uint256(0));
        vm.prank(keeper);
        vm.expectRevert(OstraRouter.RouteMismatch.selector);
        router.executeEscrow(open, USDG, Legs.none(), skim);
        vm.prank(keeper);
        vm.expectRevert(OstraRouter.RouteMismatch.selector);
        router.executeEscrow(open, USDG, Legs.none(), legOut);
        assertEq(_bal(USDG, openEscrow), amountIn);
        assertEq(_bal(NVDA, keeper), 0);
        vm.prank(canceller);
        router.closeEscrow(open);
        assertEq(_bal(USDG, address(vault)), amountIn);
    }

    /// @dev A bound route through a pool whose hook reverts: the tranche reverts and the funds keep waiting.
    function test_standing_failingPool_keepsTheFunds() public {
        IOstraVault vault = _newVault(USDG, 100e6);
        PoolKey memory bad = _hookPool(type(PlainRevertHook).runtimeCode, 9);
        OstraRouter.Leg memory legOut = Legs.v4(bad, true, false);
        OstraRouter.Order memory o = _standing(vault, 100e6, 1, user, legOut, 1, 0, false);
        address escrow = _place(vault, o);
        vm.prank(keeper);
        vm.expectRevert();
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertEq(_bal(USDG, escrow), 100e6);
        assertEq(router.tranchesDone(router.orderHash(o)), 0);
    }

    /// @dev Independent review: overdue DCA tranches do not all run at once; each waits half an interval after the
    ///      one before, so a late order catches up at most two tranches per interval.
    function test_standing_dca_overdueTranchesCatchUpPaced() public {
        IOstraVault vault = _newVault(USDG, 300e6);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _standing(vault, 300e6, 1, user, legOut, 3, 1 days, false);
        _place(vault, o);
        vm.warp(block.timestamp + 5 days);
        vm.prank(keeper);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(OstraRouter.NotYet.selector, block.timestamp + 12 hours));
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        vm.warp(block.timestamp + 12 hours);
        vm.prank(keeper);
        router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertEq(router.tranchesDone(router.orderHash(o)), 2);
        assertEq(router.lastTrancheAt(router.orderHash(o)), block.timestamp);
    }

    /// @dev Independent review: ETH forced into the router (selfdestruct skips receive) no longer blocks legs
    ///      whose input is WETH; it stays where it is.
    function test_forcedEth_doesNotBlockWethLegs() public {
        new ForceEth{value: 1}(address(router));
        assertEq(address(router).balance, 1);
        uint256 amountIn = 0.1 ether;
        uint256 hub = _quoteV4(_ethUsdgV4(), true, amountIn);
        vm.deal(user, amountIn);
        vm.prank(user);
        uint256 out = router.swap{value: amountIn}(address(0), USDG, amountIn, hub - (hub * 20) / 10_000, user, USDG, Legs.v4(_ethUsdgV4(), true, true), Legs.none());
        assertEq(out, hub - (hub * 20) / 10_000);
        assertEq(address(router).balance, 1);

        new ForceEth{value: 1}(address(buyback));
        deal(WETH, address(buyback), 0.01 ether);
        vm.prank(keeper);
        assertGt(buyback.burnOnCurve(0.01 ether, 1), 0);
        assertEq(address(buyback).balance, 1);
    }

    /// @dev Independent review: one position cannot lend its tier around, one account per transaction: while it
    ///      is locked, accounts can join its list (a new vault) but none can leave it.
    function test_stake_beneficiariesOnlyGrowWhileLocked() public {
        _buyOstra(user, 0.05 ether);
        vm.startPrank(user);
        IERC20(OSTRA).approve(address(stake), type(uint256).max);
        stake.lock(500_000e18, _one(makeAddr("a")));
        (, uint40 unlockAt,) = stake.positionOf(user);
        vm.expectRevert(abi.encodeWithSelector(OstraStake.BeneficiariesLocked.selector, unlockAt));
        stake.lock(0, _one(makeAddr("b")));
        vm.expectRevert(abi.encodeWithSelector(OstraStake.BeneficiariesLocked.selector, unlockAt));
        stake.lock(1e18, _one(makeAddr("b")));
        stake.lock(1e18, _one(makeAddr("a")));
        assertEq(stake.feeBps(makeAddr("b")), 20);
        stake.lock(0, _two(makeAddr("b"), makeAddr("a")));
        (, unlockAt,) = stake.positionOf(user);
        vm.expectRevert(abi.encodeWithSelector(OstraStake.BeneficiariesLocked.selector, unlockAt));
        stake.lock(0, _one(makeAddr("b")));
        vm.stopPrank();
        assertEq(stake.feeBps(makeAddr("a")), 0);
        assertEq(stake.feeBps(makeAddr("b")), 0);
    }

    /// @dev A bound route refuses any other legs before anything moves.
    function test_standing_boundRoute_refusesOtherLegs() public {
        IOstraVault vault = _newVault(USDG, 100e6);
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        OstraRouter.Order memory o = _standing(vault, 100e6, 0, user, legOut, 1, 0, false);
        address escrow = _place(vault, o);
        vm.prank(keeper);
        vm.expectRevert(OstraRouter.RouteMismatch.selector);
        router.executeEscrow(o, USDG, Legs.none(), Legs.v3(USDG, 3000, NVDA));
        assertEq(_bal(USDG, escrow), 100e6);
    }

    /// @dev An escrow funded with less than a tranche needs waits (EscrowShort) and is refunded after the deadline;
    ///      one funded with more refunds the excess when its last tranche runs.
    function test_standing_fundedShortOrLong() public {
        OstraRouter.Leg memory legOut = Legs.v3(USDG, 500, NVDA);
        IOstraVault vault = _newVault(USDG, 200e6);
        OstraRouter.Order memory o = _standing(vault, 100e6, 0, user, legOut, 1, 0, false);
        address escrow = router.escrowAddress(o);
        _transfer(vault, escrow, 40e6);
        vm.prank(keeper);
        vm.expectRevert(abi.encodeWithSelector(OstraRouter.EscrowShort.selector, 100e6, 40e6));
        router.executeEscrow(o, USDG, Legs.none(), legOut);

        _transfer(vault, escrow, 70e6);
        vm.prank(keeper);
        (bool swapped,) = router.executeEscrow(o, USDG, Legs.none(), legOut);
        assertTrue(swapped);
        assertEq(_bal(USDG, escrow), 0);
        assertEq(_bal(USDG, address(vault)), 200e6 - 110e6 + 10e6);
    }

    // ---------------------------------------------------------------------------------------------
    // Quotes: OstraQuoteBatch (the SDK runs its creation code in an eth_call)
    // ---------------------------------------------------------------------------------------------

    /// @dev Runs OstraQuoteBatch's constructor as the SDK's eth_call does (here by deploying it: the code it leaves
    ///      is its answer).
    function _quoteBatch(address[] memory targets, bytes[] memory data, uint256 gasPerCall)
        internal
        returns (OstraQuoteBatch.Result[] memory)
    {
        address answer = address(new OstraQuoteBatch(targets, data, gasPerCall));
        return abi.decode(answer.code, (OstraQuoteBatch.Result[]));
    }

    /// @dev The SDK fork test's first route (1 ETH to USDG) hung: one Multicall3 of 39 quotes needed more than the
    ///      RPC's 50,000,000 gas, because a nearly empty v4 pool (here ETH/USDG fee 1, tick spacing 1, measured on
    ///      chain 4663, 20 Oct 2026) burns every bit of gas its quote gets. With 500,000 gas per quote it fails on
    ///      its own and the healthy pool beside it still quotes, exactly as V4Quoter quotes it alone.
    function test_quoteBatch_gasBurningPoolFailsAlone() public {
        PoolKey memory bad = PoolKey({currency0: address(0), currency1: USDG, fee: 1, tickSpacing: 1, hooks: address(0)});
        address[] memory targets = new address[](2);
        bytes[] memory data = new bytes[](2);
        targets[0] = V4_QUOTER;
        targets[1] = V4_QUOTER;
        data[0] = abi.encodeCall(
            IV4Quoter.quoteExactInputSingle,
            (IV4Quoter.QuoteExactSingleParams({poolKey: bad, zeroForOne: true, exactAmount: 1 ether, hookData: ""}))
        );
        data[1] = abi.encodeCall(
            IV4Quoter.quoteExactInputSingle,
            (IV4Quoter.QuoteExactSingleParams({poolKey: _ethUsdgV4(), zeroForOne: true, exactAmount: 1 ether, hookData: ""}))
        );
        uint256 expected = _quoteV4(_ethUsdgV4(), true, 1 ether);
        uint256 g = gasleft();
        OstraQuoteBatch.Result[] memory r = _quoteBatch(targets, data, 500_000);
        uint256 used = g - gasleft();
        assertFalse(r[0].success, "the gas-burning pool fails");
        assertTrue(r[1].success, "the healthy pool quotes");
        (uint256 out,) = abi.decode(r[1].returnData, (uint256, uint256));
        assertEq(out, expected);
        assertLt(used, 2_000_000, "the batch stays within its gas bound");

        vm.expectRevert(OstraQuoteBatch.LengthMismatch.selector);
        new OstraQuoteBatch(targets, new bytes[](1), 500_000);
    }

    // ---------------------------------------------------------------------------------------------
    // Buyback and burn
    // ---------------------------------------------------------------------------------------------

    function test_buyback_usdgToWeth_thenBurnOnCurve() public {
        deal(USDG, address(buyback), 200e6);
        uint256 expectedWeth = _quoteV3(USDG, 100, WETH, 200e6);
        bytes memory path = abi.encodePacked(USDG, uint24(100), WETH);

        vm.expectRevert(OstraBuyback.OnlyKeeper.selector);
        buyback.toWeth(USDG, 200e6, expectedWeth, path);

        vm.prank(keeper);
        uint256 weth = buyback.toWeth(USDG, 200e6, expectedWeth, path);
        assertEq(weth, expectedWeth);
        assertEq(_bal(WETH, address(buyback)), expectedWeth);
        assertEq(_bal(USDG, address(buyback)), 0);

        uint256 deadBefore = _bal(OSTRA, DEAD);
        vm.recordLogs();
        vm.prank(keeper);
        uint256 burned = buyback.burnOnCurve(weth, 1);
        assertGt(burned, 0);
        console.log("OSTRA burned for the WETH", burned, weth);
        assertEq(_bal(OSTRA, DEAD) - deadBefore, burned);
        assertEq(_bal(OSTRA, address(buyback)), 0);
        assertEq(_bal(WETH, address(buyback)), 0);
        assertEq(address(buyback).balance, 0);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool seen;
        for (uint256 i; i < logs.length; i++) {
            if (logs[i].emitter == address(buyback) && logs[i].topics[0] == OstraBuyback.Burned.selector) seen = true;
        }
        assertTrue(seen);
    }

    function test_buyback_stockThroughUsdgToWeth() public {
        deal(NVDA, address(buyback), 2e18);
        bytes memory path = abi.encodePacked(NVDA, uint24(500), USDG, uint24(100), WETH);
        vm.prank(keeper);
        uint256 weth = buyback.toWeth(NVDA, 2e18, 1, path);
        assertGt(weth, 0);
        assertEq(_bal(NVDA, address(buyback)), 0);
        assertEq(_bal(WETH, address(buyback)), weth);
    }

    /// @dev Independent review, finding 3: the keeper names only a v3 path from the token to WETH (through USDG at
    ///      most), never commands, so it cannot pay anything anywhere.
    function test_buyback_keeperCannotRouteElsewhere() public {
        deal(USDG, address(buyback), 200e6);
        vm.startPrank(keeper);
        vm.expectRevert(OstraBuyback.BadPath.selector);
        buyback.toWeth(USDG, 200e6, 0, abi.encodePacked(USDG, uint24(100), NVDA));
        vm.expectRevert(OstraBuyback.BadPath.selector);
        buyback.toWeth(USDG, 200e6, 0, abi.encodePacked(NVDA, uint24(100), WETH));
        vm.expectRevert(OstraBuyback.BadPath.selector);
        buyback.toWeth(USDG, 200e6, 0, abi.encodePacked(USDG, uint24(500), TSLA, uint24(100), WETH));
        vm.expectRevert(OstraBuyback.BadPath.selector);
        buyback.toWeth(USDG, 200e6, 0, hex"");
        vm.expectRevert(OstraBuyback.BadToken.selector);
        buyback.toWeth(WETH, 1, 0, abi.encodePacked(WETH, uint24(100), WETH));
        vm.stopPrank();
        assertEq(_bal(USDG, address(buyback)), 200e6);
    }

    /// @dev Before OSTRA graduates its v4 pool does not exist: burnOnRouter fails and moves nothing.
    function test_buyback_burnOnRouter_beforeGraduation_reverts() public {
        deal(WETH, address(buyback), 0.01 ether);
        vm.prank(keeper);
        vm.expectRevert();
        buyback.burnOnRouter(0.01 ether, 1);
        assertEq(_bal(WETH, address(buyback)), 0.01 ether);
    }

    /// @dev burnOnRouter's own commands (unwrap, then v4 SETTLE / SWAP_EXACT_IN_SINGLE / TAKE on a native-ETH pool
    ///      paying this contract), run on the ETH/USDG v4 pool by a harness that stands USDG in for OSTRA.
    function test_buyback_burnOnRouter_commandsWork() public {
        BuybackHarness h = new BuybackHarness(USDG, USDG, WETH, UNIVERSAL_ROUTER, OSTRA_CURVE, address(0), owner, keeper);
        deal(WETH, address(h), 0.01 ether);
        uint256 expected = _quoteV4(_ethUsdgV4(), true, 0.01 ether);
        uint256 deadBefore = _bal(USDG, DEAD);
        vm.prank(keeper);
        uint256 burned = h.burnOnRouter(0.01 ether, expected);
        assertEq(burned, expected);
        assertEq(_bal(USDG, DEAD) - deadBefore, expected);
        assertEq(_bal(WETH, address(h)), 0);
    }

    function test_buyback_curveMinimumHolds() public {
        deal(WETH, address(buyback), 0.01 ether);
        vm.prank(keeper);
        vm.expectRevert();
        buyback.burnOnCurve(0.01 ether, type(uint256).max);
        assertEq(_bal(WETH, address(buyback)), 0.01 ether);
    }

    function test_buyback_onlyOwnerSetsKeeper() public {
        vm.expectRevert();
        buyback.setKeeper(user);
        vm.prank(owner);
        buyback.setKeeper(user);
        assertEq(buyback.keeper(), user);
    }

    function _assertRouterHoldsNothing() internal view {
        assertEq(_bal(USDG, address(router)), 0);
        assertEq(_bal(WETH, address(router)), 0);
        assertEq(_bal(NVDA, address(router)), 0);
        assertEq(_bal(TSLA, address(router)), 0);
        assertEq(address(router).balance, 0);
    }
}

/// @dev OstraBuyback with the ETH/USDG v4 pool (no hook, 0.05%) in place of OSTRA's graduated pool.
contract BuybackHarness is OstraBuyback {
    constructor(
        address ostra,
        address usdg,
        address weth,
        address universalRouter,
        address curve,
        address ponsHook,
        address owner_,
        address keeper_
    ) OstraBuyback(ostra, usdg, weth, universalRouter, curve, ponsHook, owner_, keeper_) {}

    function ostraPoolKey() public pure override returns (OstraBuyback.PoolKey memory) {
        return OstraBuyback.PoolKey({currency0: address(0), currency1: 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168, fee: 500, tickSpacing: 10, hooks: address(0)});
    }
}

/// @dev Sends its ETH to `target` without calling it (selfdestruct in its constructor).
contract ForceEth {
    constructor(address target) payable {
        selfdestruct(payable(target));
    }
}

/// @dev Hooks of hostile pools (flags: BEFORE_SWAP), from the independent review of 20 Oct 2026.
contract BombHook {
    fallback() external {
        assembly {
            revert(0, 200000)
        }
    }
}

/// @dev Reverts with a payload sized to the gas it gets.
contract AdaptiveBombHook {
    fallback() external {
        uint256 w = Math.sqrt(512 * (gasleft() / 10));
        assembly {
            revert(0, mul(w, 32))
        }
    }
}

contract PlainRevertHook {
    fallback() external {
        revert("no");
    }
}

contract GasBurnHook {
    fallback() external {
        assembly {
            invalid()
        }
    }
}
