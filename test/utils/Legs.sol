// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {OstraRouter} from "../../src/OstraRouter.sol";

/// @notice A Uniswap v4 pool key, ABI-identical to v4-core's PoolKey (Currency and IHooks are addresses).
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

/// @notice Builds the legs OstraRouter runs, as Universal Router commands (Uniswap's universal-router Commands.sol
///         and Dispatcher.sol, v4-periphery Actions.sol and ActionConstants.sol, as verified at
///         0x8876789976dEcBfCbBbe364623C63652db8C0904 on chain 4663). Every leg spends the router's whole balance of
///         its input (CONTRACT_BALANCE) and pays its output to the caller of the router (MSG_SENDER), so a leg does
///         not depend on the amount it will swap.
library Legs {
    uint256 internal constant CONTRACT_BALANCE = 1 << 255;
    address internal constant MSG_SENDER = address(1);
    address internal constant ADDRESS_THIS = address(2);

    bytes1 internal constant V3_SWAP_EXACT_IN = 0x00;
    bytes1 internal constant UNWRAP_WETH = 0x0c;
    bytes1 internal constant V4_SWAP = 0x10;

    uint8 internal constant SWAP_EXACT_IN_SINGLE = 0x06;
    uint8 internal constant SETTLE = 0x0b;
    uint8 internal constant TAKE = 0x0e;

    function none() internal pure returns (OstraRouter.Leg memory leg) {
        leg.inputs = new bytes[](0);
    }

    /// @notice One exact-input swap on the Uniswap v3 pool (tokenIn, fee, tokenOut).
    function v3(address tokenIn, uint24 fee, address tokenOut) internal pure returns (OstraRouter.Leg memory leg) {
        leg.commands = abi.encodePacked(V3_SWAP_EXACT_IN);
        leg.inputs = new bytes[](1);
        leg.inputs[0] =
            abi.encode(MSG_SENDER, CONTRACT_BALANCE, uint256(0), abi.encodePacked(tokenIn, fee, tokenOut), false, new uint256[](0));
    }

    /// @notice One exact-input swap on the v4 pool `key`; `unwrapFirst` turns the router's WETH into ETH first (an
    ///         ETH-in leg on a native-ETH pool). A native-ETH output arrives as ETH, which OstraRouter wraps.
    function v4(PoolKey memory key, bool zeroForOne, bool unwrapFirst) internal pure returns (OstraRouter.Leg memory leg) {
        address currencyIn = zeroForOne ? key.currency0 : key.currency1;
        address currencyOut = zeroForOne ? key.currency1 : key.currency0;
        bytes[] memory params = new bytes[](3);
        params[0] = abi.encode(currencyIn, CONTRACT_BALANCE, false);
        params[1] = abi.encode(
            ExactInputSingleParams({
                poolKey: key,
                zeroForOne: zeroForOne,
                amountIn: 0,
                amountOutMinimum: 0,
                minHopPriceX36: 0,
                hookData: ""
            })
        );
        params[2] = abi.encode(currencyOut, MSG_SENDER, uint256(0));
        bytes memory swapInput = abi.encode(abi.encodePacked(SETTLE, SWAP_EXACT_IN_SINGLE, TAKE), params);
        if (unwrapFirst) {
            leg.commands = abi.encodePacked(UNWRAP_WETH, V4_SWAP);
            leg.inputs = new bytes[](2);
            leg.inputs[0] = abi.encode(ADDRESS_THIS, uint256(0));
            leg.inputs[1] = swapInput;
        } else {
            leg.commands = abi.encodePacked(V4_SWAP);
            leg.inputs = new bytes[](1);
            leg.inputs[0] = swapInput;
        }
    }
}
