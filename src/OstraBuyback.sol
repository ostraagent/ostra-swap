// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {IUniversalRouter, IWETH9} from "./OstraRouter.sol";

/// @notice The Pons bonding curve OSTRA trades on until it graduates: buy(ethIn, minOut, recipient), payable with
///         ethIn (read from OSTRA's buy transactions on chain 4663, 20 Oct 2026).
interface IPonsCurve {
    function buy(uint256 ethIn, uint256 minOut, address recipient) external payable;
}

/// @title OstraBuyback
/// @notice Buys OSTRA with what it receives and burns it (design v0.4, "Ostra Swap", decided 20 Oct 2026): half of
///         every Ostra Swap fee (OstraRouter) and the launchpad's buyback part (OstraDispatcher.claimBuyback). The
///         keeper turns what arrives into WETH (toWeth: a Uniswap v3 path from the token to WETH, through USDG at
///         most), then buys OSTRA with it, on OSTRA's Pons bonding curve before OSTRA graduates (burnOnCurve) or in
///         the pool Pons graduates OSTRA to (burnOnRouter: native ETH / OSTRA on Uniswap v4, fee 0, tick spacing
///         200, the Pons V2 meme hook), and sends every OSTRA it bought to the burn address 0x…dEaD, where Ostra's
///         burns go. This contract builds every Universal Router command itself, each paying only this contract
///         (independent review, 20 Oct 2026), so funds leave only as OSTRA to the burn address or as the input of a
///         swap into WETH or OSTRA that pays this contract. The keeper chooses the amounts, the v3 path and each
///         trade's minimum (from its quote); the owner only names the keeper.
contract OstraBuyback is Ownable2Step, ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    address public constant DEAD = 0x000000000000000000000000000000000000dEaD;

    /// @dev Universal Router commands and v4-periphery actions (Commands.sol, Actions.sol, ActionConstants.sol).
    bytes1 private constant V3_SWAP_EXACT_IN = 0x00;
    bytes1 private constant UNWRAP_WETH = 0x0c;
    bytes1 private constant V4_SWAP = 0x10;
    uint8 private constant SWAP_EXACT_IN_SINGLE = 0x06;
    uint8 private constant SETTLE = 0x0b;
    uint8 private constant TAKE = 0x0e;
    uint256 private constant CONTRACT_BALANCE = 1 << 255;
    address private constant MSG_SENDER = address(1);
    address private constant ADDRESS_THIS = address(2);

    /// @notice v4-core PoolKey (currencies and hooks as addresses).
    struct PoolKey {
        address currency0;
        address currency1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }

    /// @notice v4-periphery IV4Router.ExactInputSingleParams.
    struct ExactInputSingleParams {
        PoolKey poolKey;
        bool zeroForOne;
        uint128 amountIn;
        uint128 amountOutMinimum;
        uint256 minHopPriceX36;
        bytes hookData;
    }

    IERC20 public immutable OSTRA;
    address public immutable USDG;
    address public immutable WETH;
    IUniversalRouter public immutable UNIVERSAL_ROUTER;
    IPonsCurve public immutable CURVE;
    /// @notice The Pons V2 meme hook: the hook of the pool Pons graduates OSTRA to.
    address public immutable PONS_HOOK;

    address public keeper;
    bool private transient _inTrade;

    event KeeperSet(address keeper);
    event ConvertedToWeth(address indexed token, uint256 amountIn, uint256 wethOut);
    /// @notice `wethIn` bought `bought` OSTRA, and the burn address's OSTRA rose by `burned`.
    event Burned(uint256 wethIn, uint256 bought, uint256 burned, bool onCurve);

    error OnlyKeeper();
    error BadToken();
    error BadPath();
    error ZeroAmount();
    error TooLittleReceived(uint256 minOut, uint256 amountOut);
    error InputTouched();
    error UnexpectedEth();

    constructor(
        address ostra,
        address usdg,
        address weth,
        address universalRouter,
        address curve,
        address ponsHook,
        address owner_,
        address keeper_
    ) Ownable(owner_) {
        OSTRA = IERC20(ostra);
        USDG = usdg;
        WETH = weth;
        UNIVERSAL_ROUTER = IUniversalRouter(universalRouter);
        CURVE = IPonsCurve(curve);
        PONS_HOOK = ponsHook;
        keeper = keeper_;
        emit KeeperSet(keeper_);
    }

    modifier onlyKeeper() {
        if (msg.sender != keeper) revert OnlyKeeper();
        _;
    }

    /// @notice ETH comes in only during a trade (a v4 leg's native output, the curve's change) or from WETH's withdraw.
    receive() external payable {
        if (!_inTrade && msg.sender != WETH) revert UnexpectedEth();
    }

    function setKeeper(address keeper_) external onlyOwner {
        keeper = keeper_;
        emit KeeperSet(keeper_);
    }

    /// @notice The pool Pons graduates OSTRA to: native ETH / OSTRA, fee 0, tick spacing 200, the Pons V2 meme hook.
    function ostraPoolKey() public view virtual returns (PoolKey memory) {
        return PoolKey({currency0: address(0), currency1: address(OSTRA), fee: 0, tickSpacing: 200, hooks: PONS_HOOK});
    }

    /// @notice Turns `amountIn` of `token` (USDG, a stock token: what fees arrive in) into at least `minWethOut` WETH
    ///         along the Uniswap v3 `path` (token, fee, [USDG, fee,] WETH), paid to this contract.
    function toWeth(address token, uint256 amountIn, uint256 minWethOut, bytes calldata path)
        external
        onlyKeeper
        nonReentrant
        returns (uint256 wethOut)
    {
        if (token == WETH || token == address(OSTRA)) revert BadToken();
        if (amountIn == 0) revert ZeroAmount();
        _checkPath(token, path);
        uint256 inBefore = IERC20(token).balanceOf(address(this));
        uint256 wethBefore = IERC20(WETH).balanceOf(address(this));
        IERC20(token).safeTransfer(address(UNIVERSAL_ROUTER), amountIn);
        bytes[] memory inputs = new bytes[](1);
        inputs[0] = abi.encode(MSG_SENDER, CONTRACT_BALANCE, uint256(0), path, false, new uint256[](0));
        UNIVERSAL_ROUTER.execute(abi.encodePacked(V3_SWAP_EXACT_IN), inputs, block.timestamp);
        if (IERC20(token).balanceOf(address(this)) != inBefore - amountIn) revert InputTouched();
        wethOut = IERC20(WETH).balanceOf(address(this)) - wethBefore;
        if (wethOut < minWethOut) revert TooLittleReceived(minWethOut, wethOut);
        emit ConvertedToWeth(token, amountIn, wethOut);
    }

    /// @notice Buys OSTRA on its Pons bonding curve with `wethIn` WETH (as ETH), at least `minOstra`, and burns it.
    ///         Change the curve sends back is wrapped again and counted as not spent.
    function burnOnCurve(uint256 wethIn, uint256 minOstra) external onlyKeeper nonReentrant returns (uint256 burned) {
        if (wethIn == 0) revert ZeroAmount();
        uint256 ostraBefore = OSTRA.balanceOf(address(this));
        // ETH forced in without receive (selfdestruct) is left as it is; only the curve's change is counted.
        uint256 ethBefore = address(this).balance;
        IWETH9(WETH).withdraw(wethIn);
        _inTrade = true;
        CURVE.buy{value: wethIn}(wethIn, minOstra, address(this));
        _inTrade = false;
        uint256 change = address(this).balance - ethBefore;
        if (change != 0) IWETH9(WETH).deposit{value: change}();
        uint256 bought = OSTRA.balanceOf(address(this)) - ostraBefore;
        if (bought < minOstra) revert TooLittleReceived(minOstra, bought);
        burned = _burn(bought);
        emit Burned(wethIn - change, bought, burned, true);
    }

    /// @notice Buys at least `minOstra` OSTRA with `wethIn` WETH in the pool Pons graduated OSTRA to (ostraPoolKey),
    ///         paid to this contract, and burns it.
    function burnOnRouter(uint256 wethIn, uint256 minOstra) external onlyKeeper nonReentrant returns (uint256 burned) {
        if (wethIn == 0) revert ZeroAmount();
        uint256 wethBefore = IERC20(WETH).balanceOf(address(this));
        uint256 ostraBefore = OSTRA.balanceOf(address(this));
        uint256 ethBefore = address(this).balance;
        IERC20(WETH).safeTransfer(address(UNIVERSAL_ROUTER), wethIn);
        bytes[] memory params = new bytes[](3);
        params[0] = abi.encode(address(0), CONTRACT_BALANCE, false);
        params[1] = abi.encode(
            ExactInputSingleParams({
                poolKey: ostraPoolKey(),
                zeroForOne: true,
                amountIn: 0,
                amountOutMinimum: 0,
                minHopPriceX36: 0,
                hookData: ""
            })
        );
        params[2] = abi.encode(address(OSTRA), MSG_SENDER, uint256(0));
        bytes[] memory inputs = new bytes[](2);
        inputs[0] = abi.encode(ADDRESS_THIS, uint256(0));
        inputs[1] = abi.encode(abi.encodePacked(SETTLE, SWAP_EXACT_IN_SINGLE, TAKE), params);
        _inTrade = true;
        UNIVERSAL_ROUTER.execute(abi.encodePacked(UNWRAP_WETH, V4_SWAP), inputs, block.timestamp);
        _inTrade = false;
        uint256 ethPaid = address(this).balance - ethBefore;
        if (ethPaid != 0) IWETH9(WETH).deposit{value: ethPaid}();
        if (IERC20(WETH).balanceOf(address(this)) < wethBefore - wethIn) revert InputTouched();
        uint256 bought = OSTRA.balanceOf(address(this)) - ostraBefore;
        if (bought < minOstra) revert TooLittleReceived(minOstra, bought);
        burned = _burn(bought);
        emit Burned(wethIn, bought, burned, false);
    }

    /// @dev A v3 path from `token` to WETH: token, fee, WETH; or token, fee, USDG, fee, WETH.
    function _checkPath(address token, bytes calldata path) private view {
        if (path.length != 43 && path.length != 66) revert BadPath();
        if (address(bytes20(path[0:20])) != token) revert BadPath();
        if (address(bytes20(path[path.length - 20:])) != WETH) revert BadPath();
        if (path.length == 66 && address(bytes20(path[23:43])) != USDG) revert BadPath();
    }

    /// @dev Sends `amount` OSTRA to the burn address; returns how much the burn address's balance rose.
    function _burn(uint256 amount) private returns (uint256) {
        uint256 before = OSTRA.balanceOf(DEAD);
        OSTRA.safeTransfer(DEAD, amount);
        return OSTRA.balanceOf(DEAD) - before;
    }
}
