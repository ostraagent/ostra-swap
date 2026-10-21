// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";

import {OstraStake} from "./OstraStake.sol";

interface IUniversalRouter {
    function execute(bytes calldata commands, bytes[] calldata inputs, uint256 deadline) external payable;
}

interface IWETH9 {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
}

/// @title OstraSwapEscrow
/// @notice The address a vault sends an order's input to (OstraRouter.escrowAddress). OstraRouter deploys it with
///         CREATE2 the first time it executes the order, and only OstraRouter moves what it holds: pay sends the
///         router the amount the router asks for, and nothing else can move it. pay never reverts on the token's
///         account and copies none of the token's return data: the router counts only what arrived.
contract OstraSwapEscrow {
    address public immutable ROUTER;

    error OnlyRouter();

    constructor() {
        ROUTER = msg.sender;
    }

    function pay(address token, uint256 amount) external {
        if (msg.sender != ROUTER) revert OnlyRouter();
        bytes4 selector = IERC20.transfer.selector;
        address to = ROUTER;
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, selector)
            mstore(add(p, 0x04), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(p, 0x24), amount)
            pop(call(gas(), token, 0, p, 0x44, 0, 0))
        }
    }
}

/// @title OstraRouter
/// @notice Ostra Swap (design v0.4, "Ostra Swap", decided 20 Oct 2026): swaps any token that has a Uniswap v3 or v4
///         pool against a hub (USDG or WETH) through Uniswap's Universal Router, and charges the Ostra fee on the
///         hub amount between the two legs: OstraStake.feeBps of the account (20 bps, lower for OSTRA locked for it,
///         0 from 500,000 OSTRA). Half the fee goes to OstraBuyback (OSTRA bought and burned), the rest to the
///         treasury. A swap is a leg in (tokenIn to the hub, skipped when tokenIn is the hub) and a leg out (the hub
///         to tokenOut, skipped when tokenOut is the hub); each leg is Universal Router commands which spend the
///         router's balance of the leg's input (CONTRACT_BALANCE) and pay its output to this contract
///         (MSG_SENDER). The router gives the Universal Router exactly a leg's input and trusts nothing the commands
///         say: it counts its own balances before and after, the Universal Router must hold no more of the input
///         than before (all of it was swapped), and the swap stands only when tokenOut arrived for at least minOut
///         after the fee. Native ETH a leg pays out is wrapped to WETH.
///
///         Two ways in:
///         * swap: from a wallet. tokenIn is pulled with transferFrom (or sent as ETH: tokenIn = address(0)); the
///           fee is the sender's; a swap that does not reach minOut reverts. swapAtBaseFee is the same at the base
///           fee, whatever OSTRA is locked for the sender: OstraPrivatePool swaps for every note owner as one account,
///           and a lock naming it would lower all of their fees at once (decided 21 Oct 2026).
///         * executeEscrow: from an Ostra vault, which has no swap through this router: its WOTS key signs a
///           Transfer of amountIn to escrowAddress(order), an address CREATE2 derives from the whole order, so that
///           one post-quantum signature binds every term of the swap. Nobody holds a key that can move the funds
///           afterwards: the escrow pays only this router, and this router pays only the order's recipient (the
///           swap's output), refundTo (what is left) and the fee. The fee is the recipient's: the account that gets
///           the output is the one whose lock lowers the fee, so naming someone else's account gains nothing.
///           Orders are of two kinds:
///           - Immediate (tranches = 0): sent by the relayer in the same transaction as the vault's Transfer, along
///             the route the order binds (route = routeHash(hub, legIn, legOut)). Once refundTo is set it never
///             reverts (independent review, 20 Oct 2026): an order that does not hold (wrong route, amount, hub,
///             tokens or recipient, after the deadline), a swap that fails or misses minOut, and a swap that runs out
///             of the gas it was given send everything back to refundTo in the same transaction, so the vault's spend
///             always lands and its key always moves on. The swap's revert data is copied up to MAX_REASON_BYTES
///             only, so no revert payload can exhaust the refund's gas.
///           - Standing (tranches >= 1; decided 20 Oct 2026): the vault's Transfer lands on its own and the input
///             waits in the escrow. A limit or take-profit order is one tranche whose minOut is the price asked; a
///             DCA is several tranches, tranche k executable from notBefore + k * interval, each with its share of
///             amountIn and of minOut. A tranche runs only when its time has come and its swap pays at least its
///             minimum; otherwise the call reverts and the funds keep waiting (the vault's spend landed already, so a
///             revert here touches no WOTS key). `executor` (the Ostra keeper, or anyone when zero) runs tranches,
///             always along the route the order binds: an executor chooses only when, never how (independent
///             review, 20 Oct 2026: legs an executor wrote could pay the recipient its minimum and keep the rest),
///             so even a stolen executor key moves nothing anywhere but the recipient, the fee and refundTo. A DCA
///             catches up overdue tranches at most two per interval, never all at once. After the deadline anyone
///             sends what is left back to refundTo, and so does the order's `canceller` at any time: that key can
///             only return the funds to the vault. A tranche's minimum is the only price it is held to (a limit
///             order fills at the price asked or better, never below it); a stop below the market needs a price
///             feed, which this router does not read. announce publishes an order's terms for its executor.
///           A refund the token refuses is kept for refundTo (owed, claimOwed), counted from what actually left.
///         No owner, no upgrade.
contract OstraRouter is ReentrancyGuardTransient {
    using SafeERC20 for IERC20;

    uint256 public constant BPS = 10_000;
    /// @notice Gas kept back from an escrow's swap so that its refund can still run when the swap runs out of gas.
    uint256 public constant REFUND_GAS_RESERVE = 120_000;
    /// @notice The most of a failed swap's revert data an escrow refund records.
    uint256 public constant MAX_REASON_BYTES = 256;

    IUniversalRouter public immutable UNIVERSAL_ROUTER;
    address public immutable USDG;
    address public immutable WETH;
    OstraStake public immutable STAKE;
    /// @notice OstraBuyback: receives half of every fee (rounded down).
    address public immutable BUYBACK;
    /// @notice Receives the rest of every fee.
    address public immutable TREASURY;

    /// @notice A leg: Universal Router commands and their inputs.
    struct Leg {
        bytes commands;
        bytes[] inputs;
    }

    /// @notice A vault's order, every term of which its escrow address binds.
    struct Order {
        address tokenIn;
        address tokenOut;
        /// @notice The whole input (a standing order's tranches share it).
        uint256 amountIn;
        /// @notice The least tokenOut the recipient gets for all of amountIn, after the fee (a tranche gets its
        ///         share, rounded up).
        uint256 minOut;
        /// @notice Gets the output; its OSTRA lock sets the fee.
        address recipient;
        /// @notice The vault the input came from: what is not swapped goes back to it.
        address refundTo;
        /// @notice Standing orders: when tranche 0 may run (unix seconds). Immediate orders: 0.
        uint64 notBefore;
        uint64 deadline;
        /// @notice 0: an immediate order. 1 or more: a standing order in that many tranches.
        uint32 tranches;
        /// @notice Standing orders: seconds between tranches.
        uint32 interval;
        /// @notice Standing orders: who runs tranches (zero: anyone).
        address executor;
        /// @notice May send what the escrow holds back to refundTo at any time (zero: nobody).
        address canceller;
        /// @notice routeHash(hub, legIn, legOut): every swap of the order goes along it.
        bytes32 route;
        bytes32 salt;
    }

    /// @dev One swap's terms, as _swap runs them.
    struct Job {
        address account;
        address tokenIn;
        address tokenOut;
        uint256 amountIn;
        uint256 minOut;
        address recipient;
        address hub;
        bool ethOut;
        /// @dev The base fee, whatever is locked for account (swapAtBaseFee).
        bool atBaseFee;
    }

    /// @notice What a refund the token refused left here, per account and token.
    mapping(address account => mapping(address token => uint256)) public owed;
    /// @notice Standing orders: how many tranches ran.
    mapping(bytes32 orderHash => uint32) public tranchesDone;
    /// @notice A standing order that finished, expired or was cancelled: it runs no more.
    mapping(bytes32 orderHash => bool) public closed;
    /// @notice Standing orders: when the last tranche ran (unix seconds).
    mapping(bytes32 orderHash => uint64) public lastTrancheAt;

    bool private transient _inLeg;

    event Swapped(
        address indexed account,
        address indexed tokenIn,
        address indexed tokenOut,
        uint256 amountIn,
        uint256 amountOut,
        address hub,
        uint256 fee,
        uint16 feeBps,
        address recipient
    );
    event EscrowExecuted(bytes32 indexed orderHash, address indexed escrow, uint256 received, bool swapped);
    /// @notice An escrow's input went back to refundTo; `owedNow` of it stays here for refundTo (the token refused).
    ///         `reason`: the swap's revert data (at most MAX_REASON_BYTES), or the selector of why it was not tried.
    event EscrowRefunded(
        bytes32 indexed orderHash, address indexed refundTo, address token, uint256 amount, uint256 owedNow, bytes reason
    );
    event OwedClaimed(address indexed account, address indexed token, uint256 amount);
    event TrancheExecuted(bytes32 indexed orderHash, uint32 tranche, uint256 amountIn, uint256 amountOut);
    /// @notice A standing order runs no more; `refunded` went back to refundTo.
    event OrderClosed(bytes32 indexed orderHash, uint256 refunded, bool cancelled);
    /// @notice An order's terms, published so that its executor (and anyone, for an open order) can find it.
    ///         `held`: what its escrow held then. Publishing proves nothing: an executor checks the escrow itself.
    event OrderAnnounced(bytes32 indexed orderHash, address indexed escrow, uint256 held, Order order);

    error BadHub();
    error SameToken();
    error ZeroAmount();
    error ZeroRecipient();
    error BadLeg();
    error LegTouchedInput();
    error LegLeftInput();
    error TooLittleReceived(uint256 minOut, uint256 amountOut);
    error OnlySelf();
    error UnexpectedEth();
    error BadValue();
    error EthTransferFailed();
    error NothingOwed();
    /// @notice Why an escrow order was refunded without trying the swap.
    error OrderExpired();
    error AmountMismatch(uint256 amountIn, uint256 received);
    error RouteMismatch();
    error NotEnoughGas();
    error OrderIsClosed();
    error NotYet(uint256 at);
    error NotExecutor();
    error NotCanceller();
    error EscrowShort(uint256 needed, uint256 held);

    constructor(address universalRouter, address usdg, address weth, address stake, address buyback, address treasury) {
        UNIVERSAL_ROUTER = IUniversalRouter(universalRouter);
        USDG = usdg;
        WETH = weth;
        STAKE = OstraStake(stake);
        BUYBACK = buyback;
        TREASURY = treasury;
    }

    /// @notice ETH comes in only as a leg's native output (from the Universal Router) or from WETH's withdraw.
    receive() external payable {
        if (!_inLeg && msg.sender != WETH) revert UnexpectedEth();
    }

    // ---------------------------------------------------------------------------------------------
    // From a wallet
    // ---------------------------------------------------------------------------------------------

    /// @notice Swaps `amountIn` of `tokenIn` (address(0): the ETH sent) for at least `minOut` of `tokenOut`
    ///         (address(0): paid as ETH) to `recipient`, through `hub`. The fee is the sender's. Returns what the
    ///         recipient got.
    function swap(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minOut,
        address recipient,
        address hub,
        Leg calldata legIn,
        Leg calldata legOut
    ) external payable nonReentrant returns (uint256 amountOut) {
        amountOut = _swap(_walletJob(tokenIn, tokenOut, amountIn, minOut, recipient, hub, false), legIn, legOut);
    }

    /// @notice swap at the base fee (OstraStake.FEE_BASE_BPS), whatever OSTRA is locked for the sender: for a sender
    ///         that swaps for others, such as OstraPrivatePool. Returns what the recipient got.
    function swapAtBaseFee(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minOut,
        address recipient,
        address hub,
        Leg calldata legIn,
        Leg calldata legOut
    ) external payable nonReentrant returns (uint256 amountOut) {
        amountOut = _swap(_walletJob(tokenIn, tokenOut, amountIn, minOut, recipient, hub, true), legIn, legOut);
    }

    /// @dev A wallet swap's job: tokenIn taken from the sender (or the ETH sent, wrapped).
    function _walletJob(
        address tokenIn,
        address tokenOut,
        uint256 amountIn,
        uint256 minOut,
        address recipient,
        address hub,
        bool atBaseFee
    ) private returns (Job memory j) {
        if (recipient == address(0) || recipient == address(this)) revert ZeroRecipient();
        address inToken = tokenIn;
        uint256 received;
        if (tokenIn == address(0)) {
            if (msg.value == 0 || msg.value != amountIn) revert BadValue();
            IWETH9(WETH).deposit{value: msg.value}();
            inToken = WETH;
            received = msg.value;
        } else {
            if (msg.value != 0) revert UnexpectedEth();
            uint256 before = IERC20(tokenIn).balanceOf(address(this));
            IERC20(tokenIn).safeTransferFrom(msg.sender, address(this), amountIn);
            received = IERC20(tokenIn).balanceOf(address(this)) - before;
        }
        bool ethOut = tokenOut == address(0);
        j = Job({
            account: msg.sender,
            tokenIn: inToken,
            tokenOut: ethOut ? WETH : tokenOut,
            amountIn: received,
            minOut: minOut,
            recipient: recipient,
            hub: hub,
            ethOut: ethOut,
            atBaseFee: atBaseFee
        });
    }

    // ---------------------------------------------------------------------------------------------
    // From a vault, through an escrow
    // ---------------------------------------------------------------------------------------------

    /// @notice The route an order binds: its hub and both legs.
    function routeHash(address hub, Leg calldata legIn, Leg calldata legOut) public pure returns (bytes32) {
        return keccak256(abi.encode(hub, legIn, legOut));
    }

    /// @notice The hash an order's escrow address is derived from.
    function orderHash(Order calldata order) public pure returns (bytes32) {
        return keccak256(abi.encode(order));
    }

    /// @notice Where a vault sends `order.amountIn` of `order.tokenIn` to make the order.
    function escrowAddress(Order calldata order) public view returns (address) {
        bytes32 initCodeHash = keccak256(type(OstraSwapEscrow).creationCode);
        return address(uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), orderHash(order), initCodeHash)))));
    }

    /// @notice Executes `order` (see the contract notice). Anyone may call it for an immediate order; a standing
    ///         order's tranches run only for its executor. An immediate order reverts only without refundTo, before
    ///         anything moves; a standing order's tranche reverts when it cannot run yet, and moves nothing then.
    function executeEscrow(Order calldata order, address hub, Leg calldata legIn, Leg calldata legOut)
        external
        nonReentrant
        returns (bool swapped, uint256 amountOut)
    {
        if (order.refundTo == address(0)) revert ZeroRecipient();
        bytes32 h = orderHash(order);
        address escrow = _escrow(order, h);
        if (order.tranches != 0) return _runTranche(order, h, escrow, hub, legIn, legOut);

        (, uint256 held) = _balanceOf(order.tokenIn, escrow);
        uint256 received = _pull(order.tokenIn, escrow, held);
        if (received == 0) {
            emit EscrowExecuted(h, escrow, 0, false);
            return (false, 0);
        }

        bytes memory reason;
        if (block.timestamp > order.deadline) {
            reason = abi.encodeWithSelector(OrderExpired.selector);
        } else if (received != order.amountIn) {
            reason = abi.encodeWithSelector(AmountMismatch.selector, order.amountIn, received);
        } else if (order.route == bytes32(0) || routeHash(hub, legIn, legOut) != order.route) {
            reason = abi.encodeWithSelector(RouteMismatch.selector);
        } else {
            bool ok;
            (ok, amountOut, reason) = _runSwapBounded(order, hub, legIn, legOut);
            if (ok) {
                emit EscrowExecuted(h, escrow, received, true);
                return (true, amountOut);
            }
        }
        _refund(h, order.refundTo, order.tokenIn, received, reason);
        emit EscrowExecuted(h, escrow, received, false);
        return (false, 0);
    }

    /// @notice Sends what a standing order's escrow holds back to refundTo and closes the order: anyone after the
    ///         deadline, the order's canceller at any time. An immediate order's canceller may do the same with an
    ///         escrow nobody executed. Never reverts for a caller entitled to it.
    function closeEscrow(Order calldata order) external nonReentrant returns (uint256 refunded) {
        if (order.refundTo == address(0)) revert ZeroRecipient();
        bool cancelling = block.timestamp <= order.deadline;
        if (cancelling && (order.canceller == address(0) || msg.sender != order.canceller)) revert NotCanceller();
        bytes32 h = orderHash(order);
        refunded = _close(order, h, _escrow(order, h), cancelling);
    }

    /// @notice Publishes `order` (OrderAnnounced). Anyone may call it; it moves nothing and never reverts, so a
    ///         relayer may send it in the same transaction as the vault's Transfer that funds a standing order.
    function announce(Order calldata order) external {
        address escrow = escrowAddress(order);
        (, uint256 held) = _balanceOf(order.tokenIn, escrow);
        emit OrderAnnounced(orderHash(order), escrow, held, order);
    }

    /// @dev Deploys the order's escrow if it is not there yet; returns its address.
    function _escrow(Order calldata order, bytes32 h) private returns (address escrow) {
        escrow = escrowAddress(order);
        if (escrow.code.length == 0) new OstraSwapEscrow{salt: h}();
    }

    /// @dev Has `escrow` pay this contract `amount` of `token`; returns what arrived (0 when the token refused).
    function _pull(address token, address escrow, uint256 amount) private returns (uint256) {
        if (amount == 0) return 0;
        (, uint256 before) = _balanceOf(token, address(this));
        OstraSwapEscrow(escrow).pay(token, amount);
        (, uint256 afterPay) = _balanceOf(token, address(this));
        return afterPay > before ? afterPay - before : 0;
    }

    /// @dev Runs a standing order's next tranche: its time has come (notBefore + k * interval, and half an interval
    ///      after the tranche before), its executor calls along the order's route, its escrow holds its share,
    ///      and its swap pays at least its minimum, or nothing happens (revert). The last tranche returns what the
    ///      escrow still holds to refundTo; after the deadline, the call only does that.
    function _runTranche(Order calldata order, bytes32 h, address escrow, address hub, Leg calldata legIn, Leg calldata legOut)
        private
        returns (bool swapped, uint256 amountOut)
    {
        if (closed[h]) revert OrderIsClosed();
        if (block.timestamp > order.deadline) {
            _close(order, h, escrow, false);
            return (false, 0);
        }
        if (order.executor != address(0) && msg.sender != order.executor) revert NotExecutor();
        uint32 k = tranchesDone[h];
        uint256 at = uint256(order.notBefore) + uint256(k) * order.interval;
        // Late tranches catch up at most two per interval (re-review: a full interval after the last one let any
        // delay push the last tranche past the deadline), so overdue tranches never all run at once.
        if (k != 0 && uint256(lastTrancheAt[h]) + order.interval / 2 > at) at = uint256(lastTrancheAt[h]) + order.interval / 2;
        if (block.timestamp < at) revert NotYet(at);
        if (routeHash(hub, legIn, legOut) != order.route) revert RouteMismatch();
        tranchesDone[h] = k + 1;
        lastTrancheAt[h] = uint64(block.timestamp);
        uint256 trancheIn;
        (trancheIn, amountOut) = _trancheSwap(order, k, escrow, hub, legIn, legOut);
        emit TrancheExecuted(h, k, trancheIn, amountOut);
        if (k + 1 == order.tranches) _close(order, h, escrow, false);
        swapped = true;
    }

    /// @dev Tranche `k` of a standing order: its share of amountIn (the last takes the remainder) pulled from the
    ///      escrow, swapped for at least its share of minOut (rounded up), paid to the recipient.
    function _trancheSwap(Order calldata order, uint32 k, address escrow, address hub, Leg calldata legIn, Leg calldata legOut)
        private
        returns (uint256 trancheIn, uint256 amountOut)
    {
        uint256 share = order.amountIn / order.tranches;
        trancheIn = k + 1 == order.tranches ? order.amountIn - share * (order.tranches - 1) : share;
        uint256 trancheMin = order.amountIn == 0 ? 0 : Math.mulDiv(order.minOut, trancheIn, order.amountIn, Math.Rounding.Ceil);
        (, uint256 held) = _balanceOf(order.tokenIn, escrow);
        if (held < trancheIn) revert EscrowShort(trancheIn, held);
        if (_pull(order.tokenIn, escrow, trancheIn) != trancheIn) revert EscrowShort(trancheIn, held);
        if (order.recipient == address(0) || order.recipient == address(this)) revert ZeroRecipient();
        amountOut = _swap(
            Job({
                account: order.recipient,
                tokenIn: order.tokenIn,
                tokenOut: order.tokenOut,
                amountIn: trancheIn,
                minOut: trancheMin,
                recipient: order.recipient,
                hub: hub,
                ethOut: false,
                atBaseFee: false
            }),
            legIn,
            legOut
        );
    }

    /// @dev Closes an order: what its escrow holds goes back to refundTo (owed when the token refuses).
    function _close(Order calldata order, bytes32 h, address escrow, bool cancelled) private returns (uint256 refunded) {
        closed[h] = true;
        (, uint256 held) = _balanceOf(order.tokenIn, escrow);
        refunded = _pull(order.tokenIn, escrow, held);
        if (refunded != 0) _refund(h, order.refundTo, order.tokenIn, refunded, "");
        emit OrderClosed(h, refunded, cancelled);
    }

    /// @notice An escrow's swap, called by this contract on itself so that a failure reverts only the swap.
    function runSwap(Order calldata order, address hub, Leg calldata legIn, Leg calldata legOut)
        external
        returns (uint256)
    {
        if (msg.sender != address(this)) revert OnlySelf();
        if (order.recipient == address(0) || order.recipient == address(this)) revert ZeroRecipient();
        return _swap(
            Job({
                account: order.recipient,
                tokenIn: order.tokenIn,
                tokenOut: order.tokenOut,
                amountIn: order.amountIn,
                minOut: order.minOut,
                recipient: order.recipient,
                hub: hub,
                ethOut: false,
                atBaseFee: false
            }),
            legIn,
            legOut
        );
    }

    /// @notice Pays `account` what a refused refund left here in `token`. Anyone may call it; it pays only `account`.
    function claimOwed(address account, address token) external nonReentrant {
        uint256 amount = owed[account][token];
        if (amount == 0) revert NothingOwed();
        owed[account][token] = 0;
        IERC20(token).safeTransfer(account, amount);
        emit OwedClaimed(account, token, amount);
    }

    /// @dev Calls runSwap on this contract with all the gas but REFUND_GAS_RESERVE, reading gasleft once, and keeps
    ///      at most MAX_REASON_BYTES of what it returns or reverts with.
    function _runSwapBounded(Order calldata order, address hub, Leg calldata legIn, Leg calldata legOut)
        private
        returns (bool ok, uint256 amountOut, bytes memory reason)
    {
        bytes memory data = abi.encodeCall(this.runSwap, (order, hub, legIn, legOut));
        uint256 available = gasleft();
        if (available <= REFUND_GAS_RESERVE) return (false, 0, abi.encodeWithSelector(NotEnoughGas.selector));
        uint256 give = available - REFUND_GAS_RESERVE;
        assembly ("memory-safe") {
            ok := call(give, address(), 0, add(data, 0x20), mload(data), 0, 0)
            let size := returndatasize()
            if gt(size, 256) { size := 256 }
            reason := mload(0x40)
            mstore(reason, size)
            returndatacopy(add(reason, 0x20), 0, size)
            mstore(0x40, add(add(reason, 0x20), and(add(size, 31), not(31))))
        }
        if (ok) {
            if (reason.length < 32) return (false, 0, reason);
            amountOut = abi.decode(reason, (uint256));
            reason = "";
        }
    }

    /// @dev Sends `amount` of `token` back to `to`; what the token does not let leave is owed to `to`.
    function _refund(bytes32 h, address to, address token, uint256 amount, bytes memory reason) private {
        (, uint256 before) = _balanceOf(token, address(this));
        _tryTransfer(token, to, amount);
        (, uint256 afterRefund) = _balanceOf(token, address(this));
        uint256 left = before > afterRefund ? before - afterRefund : 0;
        uint256 owedNow = left >= amount ? 0 : amount - left;
        if (owedNow != 0) owed[to][token] += owedNow;
        emit EscrowRefunded(h, to, token, amount, owedNow, reason);
    }

    // ---------------------------------------------------------------------------------------------
    // The swap
    // ---------------------------------------------------------------------------------------------

    function _swap(Job memory j, Leg calldata legIn, Leg calldata legOut) private returns (uint256 amountOut) {
        if (j.hub != USDG && j.hub != WETH) revert BadHub();
        if (j.tokenIn == j.tokenOut) revert SameToken();
        if (j.amountIn == 0) revert ZeroAmount();

        uint256 hubAmount;
        if (j.tokenIn == j.hub) {
            if (legIn.commands.length != 0) revert BadLeg();
            hubAmount = j.amountIn;
        } else {
            hubAmount = _leg(j.tokenIn, j.amountIn, j.hub, legIn);
        }

        uint16 feeBps = j.atBaseFee ? STAKE.FEE_BASE_BPS() : STAKE.feeBps(j.account);
        uint256 fee = (hubAmount * feeBps) / BPS;
        uint256 net = hubAmount - fee;

        if (j.tokenOut == j.hub) {
            if (legOut.commands.length != 0) revert BadLeg();
            amountOut = net;
        } else {
            amountOut = _leg(j.hub, net, j.tokenOut, legOut);
        }
        if (amountOut < j.minOut) revert TooLittleReceived(j.minOut, amountOut);

        if (fee != 0) {
            uint256 toBuyback = fee / 2;
            if (toBuyback != 0) IERC20(j.hub).safeTransfer(BUYBACK, toBuyback);
            IERC20(j.hub).safeTransfer(TREASURY, fee - toBuyback);
        }
        if (j.ethOut) {
            IWETH9(WETH).withdraw(amountOut);
            (bool ok,) = j.recipient.call{value: amountOut}("");
            if (!ok) revert EthTransferFailed();
        } else {
            IERC20(j.tokenOut).safeTransfer(j.recipient, amountOut);
        }
        _emitSwapped(j, amountOut, fee, feeBps);
    }

    function _emitSwapped(Job memory j, uint256 amountOut, uint256 fee, uint16 feeBps) private {
        emit Swapped(
            j.account, j.tokenIn, j.ethOut ? address(0) : j.tokenOut, j.amountIn, amountOut, j.hub, fee, feeBps, j.recipient
        );
    }

    /// @dev Runs a leg: gives the Universal Router exactly `amountIn` of `tokenIn`, runs its commands, wraps any ETH
    ///      they paid out, and returns how much `tokenOut` this contract gained. The router's own `tokenIn` must be
    ///      down by exactly `amountIn` (the commands cannot reach it, as it never approves anyone; checked anyway).
    function _leg(address tokenIn, uint256 amountIn, address tokenOut, Leg calldata leg) private returns (uint256 got) {
        if (leg.commands.length == 0) revert BadLeg();
        uint256 inBefore = IERC20(tokenIn).balanceOf(address(this));
        uint256 outBefore = IERC20(tokenOut).balanceOf(address(this));
        // ETH forced in without receive (selfdestruct) stays as it is: only the ETH the leg paid is wrapped
        // (independent review, 20 Oct 2026: wrapping it all made every WETH-input leg fail LegTouchedInput).
        uint256 ethBefore = address(this).balance;
        uint256 urInBefore = _urHoldings(tokenIn);
        IERC20(tokenIn).safeTransfer(address(UNIVERSAL_ROUTER), amountIn);
        _inLeg = true;
        UNIVERSAL_ROUTER.execute(leg.commands, leg.inputs, block.timestamp);
        _inLeg = false;
        // A pool that runs dry fills only part of an exact-input swap (Uniswap v3 stops at the price limit) and the
        // rest of the input stays in the Universal Router, where anyone could sweep it (independent review, 20 Oct
        // 2026): every unit given must have been spent.
        if (_urHoldings(tokenIn) > urInBefore) revert LegLeftInput();
        uint256 ethPaid = address(this).balance - ethBefore;
        if (ethPaid != 0) IWETH9(WETH).deposit{value: ethPaid}();
        if (IERC20(tokenIn).balanceOf(address(this)) != inBefore - amountIn) revert LegTouchedInput();
        got = IERC20(tokenOut).balanceOf(address(this)) - outBefore;
    }

    /// @dev What the Universal Router holds of a leg's input: the token, plus its native ETH when the input is WETH
    ///      (a leg into a native-ETH pool unwraps it there first).
    function _urHoldings(address tokenIn) private view returns (uint256 held) {
        held = IERC20(tokenIn).balanceOf(address(UNIVERSAL_ROUTER));
        if (tokenIn == WETH) held += address(UNIVERSAL_ROUTER).balance;
    }

    /// @dev balanceOf that never reverts and reads at most one word back; (false, 0) when the token does not answer.
    function _balanceOf(address token, address who) private view returns (bool ok, uint256 amount) {
        bytes4 selector = IERC20.balanceOf.selector;
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, selector)
            // Addresses from inline assembly may carry dirty high bits (an escrow address is a cut keccak).
            mstore(add(p, 0x04), and(who, 0xffffffffffffffffffffffffffffffffffffffff))
            ok := staticcall(gas(), token, p, 0x24, p, 0x20)
            if lt(returndatasize(), 0x20) { ok := 0 }
            if ok { amount := mload(p) }
        }
    }

    /// @dev A transfer that never reverts and reads at most one word back.
    function _tryTransfer(address token, address to, uint256 amount) private {
        bytes4 selector = IERC20.transfer.selector;
        assembly ("memory-safe") {
            let p := mload(0x40)
            mstore(p, selector)
            mstore(add(p, 0x04), and(to, 0xffffffffffffffffffffffffffffffffffffffff))
            mstore(add(p, 0x24), amount)
            pop(call(gas(), token, 0, p, 0x44, p, 0x20))
        }
    }
}
