// The legs OstraRouter runs, as Universal Router commands (Uniswap's universal-router Commands.sol and
// Dispatcher.sol, v4-periphery Actions.sol and ActionConstants.sol, as verified at UNIVERSAL_ROUTER on chain
// 4663). A leg spends the router's whole balance of its input (CONTRACT_BALANCE) and pays its output to the
// caller of the Universal Router, OstraRouter (MSG_SENDER), so it does not depend on the amount it will swap: the
// leg out runs on what is left of the hub after the Ostra fee. test/utils/Legs.sol builds the same bytes for
// the Forge tests.

import { concatHex, encodeAbiParameters, encodePacked, getAddress, toHex, type Address, type Hex } from "viem";
import { ADDRESS_THIS, COMMAND, CONTRACT_BALANCE, ETH, MSG_SENDER, OPEN_DELTA, V4_ACTION, WETH } from "./constants.ts";
import { exactInputSingleParam } from "./uniswap.ts";

/** OstraRouter.Leg: Universal Router commands and their inputs. */
export type Leg = { commands: Hex; inputs: Hex[] };

export type PoolKey = { currency0: Address; currency1: Address; fee: number; tickSpacing: number; hooks: Address };

/** A pool a leg swaps on: Uniswap v3 (by fee tier) or v4 (by key). */
export type Pool =
  | { kind: "v3"; address: Address; tokenA: Address; tokenB: Address; fee: number }
  | { kind: "v4"; id: Hex; key: PoolKey };

export const NO_LEG: Leg = { commands: "0x", inputs: [] };

const byte = (n: number): Hex => toHex(n, { size: 1 });

/**
 * One exact-input swap of `tokenIn` (an ERC-20; WETH for ETH) on `pool`, for `tokenOut` (an ERC-20; WETH stands
 * for ETH: a native-ETH v4 pool is entered by unwrapping, and its ETH output is wrapped by OstraRouter), paid to
 * the Universal Router's caller (MSG_SENDER), or kept in the Universal Router (ADDRESS_THIS) for a next leg.
 */
export function legFor(pool: Pool, tokenIn: Address, tokenOut: Address, recipient: Address = MSG_SENDER): Leg {
  const inAddr = getAddress(tokenIn);
  const outAddr = getAddress(tokenOut);
  if (pool.kind === "v3") {
    const path = encodePacked(["address", "uint24", "address"], [inAddr, pool.fee, outAddr]);
    const input = encodeAbiParameters(
      [{ type: "address" }, { type: "uint256" }, { type: "uint256" }, { type: "bytes" }, { type: "bool" }, { type: "uint256[]" }],
      [recipient, CONTRACT_BALANCE, 0n, path, false, []],
    );
    return { commands: byte(COMMAND.V3_SWAP_EXACT_IN), inputs: [input] };
  }
  const k = pool.key;
  const asCurrency = (t: Address): Address => (t === WETH && (k.currency0 === ETH || k.currency1 === ETH) ? ETH : t);
  const currencyIn = asCurrency(inAddr);
  const currencyOut = asCurrency(outAddr);
  const zeroForOne = currencyIn === getAddress(k.currency0);
  if (!zeroForOne && currencyIn !== getAddress(k.currency1)) throw new Error(`${tokenIn} is not in the pool ${pool.id}`);
  if (currencyOut !== getAddress(zeroForOne ? k.currency1 : k.currency0)) throw new Error(`${tokenOut} is not the other side of the pool ${pool.id}`);
  const settle = encodeAbiParameters([{ type: "address" }, { type: "uint256" }, { type: "bool" }], [currencyIn, CONTRACT_BALANCE, false]);
  const swap = encodeAbiParameters(
    [exactInputSingleParam],
    [{ poolKey: k, zeroForOne, amountIn: OPEN_DELTA, amountOutMinimum: 0n, minHopPriceX36: 0n, hookData: "0x" }],
  );
  if (recipient === ADDRESS_THIS && currencyOut === ETH) throw new Error("a leg kept in the Universal Router pays an ERC-20, not native ETH");
  const take = encodeAbiParameters([{ type: "address" }, { type: "address" }, { type: "uint256" }], [currencyOut, recipient, OPEN_DELTA]);
  const actions = concatHex([byte(V4_ACTION.SETTLE), byte(V4_ACTION.SWAP_EXACT_IN_SINGLE), byte(V4_ACTION.TAKE)]);
  const v4Input = encodeAbiParameters([{ type: "bytes" }, { type: "bytes[]" }], [actions, [settle, swap, take]]);
  if (currencyIn === ETH) {
    const unwrap = encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [ADDRESS_THIS, 0n]);
    return { commands: concatHex([byte(COMMAND.UNWRAP_WETH), byte(COMMAND.V4_SWAP)]), inputs: [unwrap, v4Input] };
  }
  return { commands: byte(COMMAND.V4_SWAP), inputs: [v4Input] };
}
