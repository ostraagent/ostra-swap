// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {OstraRouter} from "./OstraRouter.sol";

interface IERC20Check {
    function balanceOf(address account) external view returns (uint256);
    function transfer(address to, uint256 amount) external returns (bool);
}

interface IWETHCheck {
    function deposit() external payable;
}

/// @dev Uniswap v3 QuoterV2 (v3-periphery), as verified on chain 4663.
interface IQuoterV2Check {
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

/// @dev Uniswap v4 V4Quoter (v4-periphery), as verified on chain 4663.
interface IV4QuoterCheck {
    struct PoolKey {
        address currency0;
        address currency1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }

    struct QuoteExactSingleParams {
        PoolKey poolKey;
        bool zeroForOne;
        uint128 exactAmount;
        bytes hookData;
    }

    function quoteExactInputSingle(QuoteExactSingleParams memory params) external returns (uint256 amountOut, uint256 gasEstimate);
}

/// @title OstraTokenCheck
/// @notice Never deployed. The SDK runs `run` in an eth_call to an address whose code a state override sets to this
///         contract's, from the account that sends the vaults' transactions, with ETH and that account's balance set
///         by the override. It does to a token what an Ostra vault does, as a holder with code: wraps the ETH sent
///         and buys the token with the WETH through an immediate escrow order of OstraRouter (`buy`: the WETH sent
///         to the order's escrow, executeEscrow, the token paid to this contract), sends `probeBps` of what arrived
///         to `probe` (a fresh address, as a vault's Transfer out), then sells the rest for WETH the same way (`sell`:
///         the same pools the other way, the token sent to the sale's escrow, executeEscrow). Right before the buy and
///         right before the sale it quotes that route in the same state with Uniswap's quoters (which never move a
///         token), so a token that takes a cut when it moves shows as what arrived falling short of the quote, and a
///         token that can be bought but not sold, or that refuses to move, shows as the step that failed. A step that
///         fails stops the steps after it; its revert data is kept (at most MAX_REASON bytes). A balance the token
///         does not answer stops the check too (FAILED_READ), so the token never makes the call itself revert.
contract OstraTokenCheck {
    /// @notice The most bytes kept of a step's revert data.
    uint256 public constant MAX_REASON = 256;
    /// @notice The gas a balanceOf of the token may use.
    uint256 public constant READ_GAS = 100_000;
    /// @notice How long the check's escrow orders last (seconds).
    uint64 public constant ORDER_TTL = 600;

    /// @dev Uniswap v3 TickMath.MIN_SQRT_RATIO + 1 and MAX_SQRT_RATIO - 1: where QuoterV2 stops when a pool runs dry.
    uint160 private constant V3_MIN_SQRT_PRICE_LIMIT = 4295128740;
    uint160 private constant V3_MAX_SQRT_PRICE_LIMIT = 1461446703485210103287273052203988822378723970341;

    /// @notice The step a check stopped at.
    uint8 public constant FAILED_NONE = 0;
    uint8 public constant FAILED_BUY_QUOTE = 1;
    uint8 public constant FAILED_BUY = 2;
    uint8 public constant FAILED_MOVE = 3;
    uint8 public constant FAILED_SELL_QUOTE = 4;
    /// @notice The Transfer of what was left to the sale's escrow reverted or returned false.
    uint8 public constant FAILED_SELL_MOVE = 5;
    /// @notice executeEscrow of the sale did not swap (the router sent the token back) or reverted.
    uint8 public constant FAILED_SELL = 6;
    /// @notice The token's balanceOf reverted, ran out of READ_GAS or returned less than 32 bytes.
    uint8 public constant FAILED_READ = 7;

    /// @notice How to quote one leg: kind 0 (no leg), 3 (Uniswap v3: tokenIn, tokenOut, fee) or 4 (Uniswap v4:
    ///         key, zeroForOne).
    struct Quote {
        uint8 kind;
        address tokenIn;
        address tokenOut;
        uint24 fee;
        IV4QuoterCheck.PoolKey key;
        bool zeroForOne;
    }

    /// @notice A route as OstraRouter runs it (hub and legs) and as the quoters quote it (one Quote per leg).
    struct Route {
        address hub;
        OstraRouter.Leg legIn;
        OstraRouter.Leg legOut;
        Quote quoteIn;
        Quote quoteOut;
    }

    struct Plan {
        OstraRouter router;
        address token;
        address weth;
        IQuoterV2Check v3Quoter;
        IV4QuoterCheck v4Quoter;
        address probe;
        uint256 probeBps;
        /// @notice The escrow orders' salts are derived from it.
        bytes32 salt;
        Route buy;
        Route sell;
    }

    struct Result {
        /// @notice The step the check stopped at (FAILED_NONE when every step landed, or when the buy paid nothing).
        uint8 failed;
        /// @notice The buy: its quote, what the router reported, what this contract's balance gained, its gas.
        uint256 buyQuoted;
        uint256 buyReported;
        uint256 buyHeld;
        uint256 buyGas;
        /// @notice The move to `probe`: what was sent, what `probe`'s balance gained, what this contract's balance
        ///         lost, its gas.
        uint256 moveSent;
        uint256 moveArrived;
        uint256 moveLeft;
        uint256 moveGas;
        /// @notice The sale of the rest: the amount, its quote, what its escrow's balance gained from the Transfer,
        ///         what the router reported, the WETH this contract's balance gained, its gas.
        uint256 sellAmount;
        uint256 sellQuoted;
        uint256 sellArrived;
        uint256 sellReported;
        uint256 sellWeth;
        uint256 sellGas;
        /// @notice A sale that did not swap: what came back to this contract, and what its escrow still holds.
        uint256 sellRefunded;
        uint256 sellStuck;
        /// @notice A sale that did not swap: what the router owes this contract, as the token refused its refund.
        uint256 sellOwed;
        /// @notice The revert data of the step that failed (at most MAX_REASON bytes), or empty.
        bytes reason;
    }

    function run(Plan calldata p) external payable returns (Result memory r) {
        uint16 feeBps = p.router.STAKE().feeBps(address(this));
        if (_buy(r, p, feeBps) && _move(r, p)) _sell(r, p, feeBps);
    }

    /// @dev 1. Quotes the buy, then buys `token` with the ETH sent, wrapped, through an escrow order. False when it
    ///      failed or paid nothing.
    function _buy(Result memory r, Plan calldata p, uint16 feeBps) private returns (bool) {
        bool ok;
        (ok, r.buyQuoted) = _quoteRoute(p, p.buy, msg.value, feeBps);
        if (!ok) {
            r.failed = FAILED_BUY_QUOTE;
            return false;
        }
        IWETHCheck(p.weth).deposit{value: msg.value}();
        uint256 before;
        (ok, before) = _balance(p.token, address(this));
        if (!ok) return _readFailed(r);
        uint256 g = gasleft();
        Executed memory e = _execute(p, p.buy, p.weth, p.token, msg.value, p.salt);
        r.buyGas = g - gasleft();
        if (e.outcome == READ_FAILED) return _readFailed(r);
        if (e.outcome != SWAPPED) {
            r.failed = FAILED_BUY;
            r.reason = e.reason;
            return false;
        }
        r.buyReported = e.out;
        uint256 held;
        (ok, held) = _balance(p.token, address(this));
        if (!ok) return _readFailed(r);
        r.buyHeld = _gain(before, held);
        return r.buyHeld != 0;
    }

    /// @dev 2. Sends `probeBps` of what was bought (at least 1 unit) to `probe`.
    function _move(Result memory r, Plan calldata p) private returns (bool) {
        r.moveSent = (r.buyHeld * p.probeBps) / 10_000;
        if (r.moveSent == 0 && r.buyHeld > 1) r.moveSent = 1;
        (bool ok1, uint256 held) = _balance(p.token, address(this));
        (bool ok2, uint256 probeBefore) = _balance(p.token, p.probe);
        if (!ok1 || !ok2) return _readFailed(r);
        uint256 g = gasleft();
        (bool sent, bytes memory reason) = _transfer(p.token, p.probe, r.moveSent);
        r.moveGas = g - gasleft();
        if (!sent) {
            r.failed = FAILED_MOVE;
            r.reason = reason;
            return false;
        }
        (bool ok3, uint256 heldAfter) = _balance(p.token, address(this));
        (bool ok4, uint256 probeAfter) = _balance(p.token, p.probe);
        if (!ok3 || !ok4) return _readFailed(r);
        r.moveArrived = _gain(probeBefore, probeAfter);
        r.moveLeft = _gain(heldAfter, held);
        return true;
    }

    /// @dev 3. Quotes the sale of what the buy left after the move (not anything this address held before), then
    ///      sells it for WETH through an escrow order.
    function _sell(Result memory r, Plan calldata p, uint16 feeBps) private {
        bool ok;
        r.sellAmount = r.moveLeft < r.buyHeld ? r.buyHeld - r.moveLeft : 0;
        (ok, r.sellQuoted) = _quoteRoute(p, p.sell, r.sellAmount, feeBps);
        if (!ok) {
            r.failed = FAILED_SELL_QUOTE;
            return;
        }
        uint256 wethBefore = IERC20Check(p.weth).balanceOf(address(this));
        uint256 g = gasleft();
        Executed memory e = _execute(p, p.sell, p.token, p.weth, r.sellAmount, bytes32(uint256(p.salt) ^ 1));
        r.sellGas = g - gasleft();
        r.sellArrived = e.arrived;
        if (e.outcome == READ_FAILED) {
            _readFailed(r);
        } else if (e.outcome == TRANSFER_REFUSED) {
            r.failed = FAILED_SELL_MOVE;
            r.reason = e.reason;
        } else if (e.outcome != SWAPPED) {
            // The router sent back what reached it (one that did not get the whole amount refunds it as an amount
            // mismatch); what the escrow could not pay it stays there.
            r.failed = FAILED_SELL;
            r.reason = e.reason;
            r.sellRefunded = e.refunded;
            r.sellStuck = e.stuck;
            r.sellOwed = p.router.owed(address(this), p.token);
        } else {
            r.sellReported = e.out;
            r.sellWeth = _gain(wethBefore, IERC20Check(p.weth).balanceOf(address(this)));
        }
    }

    uint8 private constant SWAPPED = 0;
    uint8 private constant TRANSFER_REFUSED = 1;
    uint8 private constant NOT_SWAPPED = 2;
    uint8 private constant READ_FAILED = 3;

    /// @dev An escrow order's outcome: SWAPPED, TRANSFER_REFUSED, NOT_SWAPPED or READ_FAILED; what the router
    ///      reported; what the escrow's balance gained from the Transfer; the revert data of the Transfer or of
    ///      executeEscrow (empty when the router refunded: it says why only in its EscrowRefunded event).
    struct Executed {
        uint8 outcome;
        uint256 out;
        uint256 arrived;
        /// @dev NOT_SWAPPED: what this contract's balance of tokenIn gained back, and what the escrow still holds.
        uint256 refunded;
        uint256 stuck;
        bytes reason;
        /// @dev The order's escrow, and this contract's balance of tokenIn right after funding it.
        address escrow;
        uint256 before;
    }

    /// @dev An immediate escrow order of `amountIn` of tokenIn for tokenOut along `route`, paid to and refunded to
    ///      this contract, as a vault's: the Transfer to its escrow, then executeEscrow.
    function _execute(Plan calldata p, Route calldata route, address tokenIn, address tokenOut, uint256 amountIn, bytes32 salt)
        private
        returns (Executed memory e)
    {
        OstraRouter.Order memory order = _order(p.router, route, tokenIn, tokenOut, amountIn, salt);
        e = _fund(p.router.escrowAddress(order), tokenIn, amountIn);
        if (e.outcome == SWAPPED) _run(e, p.router, order, route);
        if (e.outcome == NOT_SWAPPED) {
            (bool ok1, uint256 held) = _balance(tokenIn, address(this));
            (bool ok2, uint256 stuck) = _balance(tokenIn, e.escrow);
            if (!ok1 || !ok2) {
                e.outcome = READ_FAILED;
                return e;
            }
            e.refunded = _gain(e.before, held);
            e.stuck = stuck;
        }
    }

    function _order(OstraRouter router, Route calldata route, address tokenIn, address tokenOut, uint256 amountIn, bytes32 salt)
        private
        view
        returns (OstraRouter.Order memory)
    {
        return OstraRouter.Order({
            tokenIn: tokenIn,
            tokenOut: tokenOut,
            amountIn: amountIn,
            minOut: 0,
            recipient: address(this),
            refundTo: address(this),
            notBefore: 0,
            deadline: uint64(block.timestamp) + ORDER_TTL,
            tranches: 0,
            interval: 0,
            executor: address(0),
            canceller: address(0),
            route: router.routeHash(route.hub, route.legIn, route.legOut),
            salt: salt
        });
    }

    /// @dev The Transfer of `amountIn` to `escrow`, and what the escrow's balance gained; outcome SWAPPED here only
    ///      means it was sent (_run decides).
    function _fund(address escrow, address tokenIn, uint256 amountIn) private returns (Executed memory e) {
        e.escrow = escrow;
        (bool ok, uint256 escrowBefore) = _balance(tokenIn, escrow);
        if (!ok) {
            e.outcome = READ_FAILED;
            return e;
        }
        bool sent;
        (sent, e.reason) = _transfer(tokenIn, escrow, amountIn);
        if (!sent) {
            e.outcome = TRANSFER_REFUSED;
            return e;
        }
        uint256 escrowAfter;
        (ok, escrowAfter) = _balance(tokenIn, escrow);
        bool ok2;
        (ok2, e.before) = _balance(tokenIn, address(this));
        if (!ok || !ok2) {
            e.outcome = READ_FAILED;
            return e;
        }
        e.arrived = _gain(escrowBefore, escrowAfter);
    }

    /// @dev executeEscrow of the funded `order`.
    function _run(Executed memory e, OstraRouter router, OstraRouter.Order memory order, Route calldata route) private {
        try router.executeEscrow(order, route.hub, route.legIn, route.legOut) returns (bool swapped, uint256 out) {
            e.outcome = swapped ? SWAPPED : NOT_SWAPPED;
            e.out = out;
        } catch (bytes memory err) {
            e.outcome = NOT_SWAPPED;
            e.reason = _cut(err);
        }
    }

    function _readFailed(Result memory r) private pure returns (bool) {
        r.failed = FAILED_READ;
        return false;
    }

    /// @dev What `route` gives for `amountIn` now, as OstraRouter would run it: the leg in, the fee on the hub
    ///      amount, the leg out. False when a leg does not quote.
    function _quoteRoute(Plan calldata p, Route calldata route, uint256 amountIn, uint16 feeBps) private returns (bool, uint256) {
        uint256 hubAmount = amountIn;
        if (route.quoteIn.kind != 0) {
            bool ok;
            (ok, hubAmount) = _quote(p, route.quoteIn, amountIn);
            if (!ok) return (false, 0);
        }
        uint256 net = hubAmount - (hubAmount * feeBps) / 10_000;
        if (route.quoteOut.kind == 0) return (true, net);
        return _quote(p, route.quoteOut, net);
    }

    /// @dev One leg's quote: false when it reverts, gives nothing, or (v3) the pool runs dry before taking it all.
    function _quote(Plan calldata p, Quote calldata q, uint256 amountIn) private returns (bool, uint256) {
        if (amountIn == 0) return (false, 0);
        if (q.kind == 3) {
            try p.v3Quoter.quoteExactInputSingle(
                IQuoterV2Check.QuoteExactInputSingleParams({tokenIn: q.tokenIn, tokenOut: q.tokenOut, amountIn: amountIn, fee: q.fee, sqrtPriceLimitX96: 0})
            ) returns (uint256 out, uint160 after_, uint32, uint256) {
                if (after_ == V3_MIN_SQRT_PRICE_LIMIT || after_ == V3_MAX_SQRT_PRICE_LIMIT) return (false, 0);
                return (out != 0, out);
            } catch {
                return (false, 0);
            }
        }
        if (q.kind == 4 && amountIn < 1 << 128) {
            try p.v4Quoter.quoteExactInputSingle(
                // casting to 'uint128' is safe because amountIn is below 2**128 (checked above)
                // forge-lint: disable-next-line(unsafe-typecast)
                IV4QuoterCheck.QuoteExactSingleParams({poolKey: q.key, zeroForOne: q.zeroForOne, exactAmount: uint128(amountIn), hookData: ""})
            ) returns (uint256 out, uint256) {
                return (out != 0, out);
            } catch {
                return (false, 0);
            }
        }
        return (false, 0);
    }

    /// @dev The token's balance of `who`, read with at most READ_GAS; false when it does not answer with a word.
    function _balance(address token, address who) private view returns (bool, uint256) {
        (bool ok, bytes memory ret) = token.staticcall{gas: READ_GAS}(abi.encodeCall(IERC20Check.balanceOf, (who)));
        if (!ok || ret.length < 32) return (false, 0);
        return (true, abi.decode(ret, (uint256)));
    }

    /// @dev An ERC-20 transfer that did not revert and returned true, or nothing (tokens that return no bool); the
    ///      revert data (at most MAX_REASON bytes) otherwise.
    function _transfer(address token, address to, uint256 amount) private returns (bool, bytes memory) {
        (bool ok, bytes memory ret) = token.call(abi.encodeCall(IERC20Check.transfer, (to, amount)));
        if (ok && (ret.length == 0 || (ret.length >= 32 && abi.decode(ret, (uint256)) == 1))) return (true, "");
        return (false, _cut(ret));
    }

    /// @dev What a balance gained from `a` to `b`, or 0 when it did not grow (a token whose balances shift by
    ///      themselves never makes the check revert).
    function _gain(uint256 a, uint256 b) private pure returns (uint256) {
        return b > a ? b - a : 0;
    }

    function _cut(bytes memory b) private pure returns (bytes memory) {
        if (b.length > MAX_REASON) {
            assembly ("memory-safe") {
                mstore(b, MAX_REASON)
            }
        }
        return b;
    }
}
