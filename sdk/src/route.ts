// Picks a swap's route: through each hub (USDG, WETH), the leg in with the best quote among the pools tokenIn
// trades in against that hub, the Ostra fee on the hub amount, then the leg out with the best quote for what is
// left; the hub whose route gives the most tokenOut wins. Quotes come from Uniswap's QuoterV2 and V4Quoter, run in
// an eth_call of OstraQuoteBatch's creation code (nothing is deployed) that bounds each quote's gas, so a pool whose
// quote fails (a hook that refuses, a pool too thin, a nearly empty v4 pool that burns its gas crossing ticks) is
// skipped without taking the others' gas; a quote that failed is tried once more with more gas, as the deepest
// pools need more to quote very large sizes. A v3 quote that stops at the price limit is a pool running dry: it
// would swap only part of the input, so it is skipped (OstraRouter refuses such a leg too). A quote is what the pool
// would do now: minOut leaves room for the market to move by `slippageBps`.

import { decodeAbiParameters, decodeFunctionResult, encodeDeployData, encodeFunctionData, getAddress, type Address, type Hex, type PublicClient } from "viem";
import { OSTRA_QUOTE_BATCH_CREATION_CODE, ostraQuoteBatchAbi } from "./abi.ts";
import {
  DEFAULT_SLIPPAGE_BPS,
  ETH,
  HUBS,
  MAX_SLIPPAGE_BPS,
  QUOTE_BATCH_OVERHEAD_GAS,
  QUOTE_GAS_LIMIT,
  QUOTE_GAS_LIMIT_RETRY,
  QUOTES_PER_CALL,
  QUOTES_PER_RETRY_CALL,
  UNISWAP_V3_QUOTER_V2,
  UNISWAP_V4_QUOTER,
  V3_MAX_SQRT_PRICE_LIMIT,
  V3_MIN_SQRT_PRICE_LIMIT,
  WETH,
} from "./constants.ts";
import { NO_LEG, legFor, type Leg, type Pool } from "./legs.ts";
import { hubPools, type PoolIndex } from "./pools.ts";
import { quoterV2Abi, v4QuoterAbi } from "./uniswap.ts";

export type LegQuote = { pool: Pool; amountIn: bigint; amountOut: bigint; leg: Leg };

export type Route = {
  tokenIn: Address;
  tokenOut: Address;
  amountIn: bigint;
  hub: Address;
  /** The leg in (none when tokenIn is the hub) and the leg out (none when tokenOut is the hub). */
  legIn: LegQuote | null;
  legOut: LegQuote | null;
  hubAmount: bigint;
  feeBps: number;
  fee: bigint;
  expectedOut: bigint;
  slippageBps: number;
  minOut: bigint;
};

export class NoRouteError extends Error {
  constructor(tokenIn: Address, tokenOut: Address) {
    super(`no Uniswap v3 or v4 route from ${tokenIn} to ${tokenOut} through USDG or WETH quotes now`);
    this.name = "NoRouteError";
  }
}

/** The ERC-20 a token is routed as: WETH for native ETH. */
export function routedToken(token: Address): Address {
  const t = getAddress(token);
  return t === ETH ? WETH : t;
}

function quoteCall(pool: Pool, tokenIn: Address, tokenOut: Address, amountIn: bigint): { target: Address; callData: Hex } {
  if (pool.kind === "v3") {
    return {
      target: UNISWAP_V3_QUOTER_V2,
      callData: encodeFunctionData({ abi: quoterV2Abi, functionName: "quoteExactInputSingle", args: [{ tokenIn, tokenOut, amountIn, fee: pool.fee, sqrtPriceLimitX96: 0n }] }),
    };
  }
  const k = pool.key;
  const native = k.currency0 === ETH;
  const currencyIn = tokenIn === WETH && native ? ETH : tokenIn;
  const zeroForOne = currencyIn === k.currency0;
  return {
    target: UNISWAP_V4_QUOTER,
    callData: encodeFunctionData({ abi: v4QuoterAbi, functionName: "quoteExactInputSingle", args: [{ poolKey: k, zeroForOne, exactAmount: amountIn, hookData: "0x" }] }),
  };
}

const quoteResults = [
  {
    type: "tuple[]",
    components: [
      { name: "success", type: "bool" },
      { name: "returnData", type: "bytes" },
    ],
  },
] as const;

type QuoteResult = { success: boolean; returnData: Hex };

/**
 * Runs `calls`, `perCall` at a time, each eth_call the creation code of OstraQuoteBatch (no `to`, nothing deployed)
 * with `gasPerCall` gas per call; returns one result per call, in order.
 */
export async function quoteBatch(
  client: PublicClient,
  calls: readonly { target: Address; callData: Hex }[],
  gasPerCall: bigint,
  perCall: number,
): Promise<QuoteResult[]> {
  const chunks: (typeof calls)[] = [];
  for (let i = 0; i < calls.length; i += perCall) chunks.push(calls.slice(i, i + perCall));
  const answers = await Promise.all(
    chunks.map(async (chunk) => {
      const data = encodeDeployData({
        abi: ostraQuoteBatchAbi,
        bytecode: OSTRA_QUOTE_BATCH_CREATION_CODE,
        args: [chunk.map((c) => c.target), chunk.map((c) => c.callData), gasPerCall],
      });
      const gas = gasPerCall * BigInt(chunk.length) + QUOTE_BATCH_OVERHEAD_GAS;
      const { data: ret } = await client.call({ data, gas });
      if (ret === undefined) throw new Error("OstraQuoteBatch returned nothing");
      const [results] = decodeAbiParameters(quoteResults, ret);
      if (results.length !== chunk.length) throw new Error("OstraQuoteBatch returned another number of results");
      return results;
    }),
  );
  return answers.flat();
}

/** Quotes `amountIn` of `tokenIn` for `tokenOut` in each of `pools`; the best quote, or null when none quotes. */
export async function bestLeg(client: PublicClient, pools: readonly Pool[], tokenIn: Address, tokenOut: Address, amountIn: bigint): Promise<LegQuote | null> {
  if (pools.length === 0 || amountIn === 0n || amountIn >= 1n << 128n) return null;
  const calls = pools.map((p) => quoteCall(p, tokenIn, tokenOut, amountIn));
  const results = await quoteBatch(client, calls, QUOTE_GAS_LIMIT, QUOTES_PER_CALL);
  const failed = results.flatMap((r, i) => (r.success && r.returnData !== "0x" ? [] : [i]));
  if (failed.length > 0) {
    const retried = await quoteBatch(client, failed.map((i) => calls[i] as (typeof calls)[number]), QUOTE_GAS_LIMIT_RETRY, QUOTES_PER_RETRY_CALL);
    failed.forEach((i, k) => {
      results[i] = retried[k] as QuoteResult;
    });
  }
  let best: LegQuote | null = null;
  results.forEach((r, i) => {
    const pool = pools[i] as Pool;
    if (!r.success || r.returnData === "0x") return;
    let amountOut: bigint;
    try {
      if (pool.kind === "v3") {
        const q = decodeFunctionResult({ abi: quoterV2Abi, functionName: "quoteExactInputSingle", data: r.returnData }) as readonly [bigint, bigint, number, bigint];
        // The pool ran dry before taking all of amountIn: only part would swap.
        if (q[1] === V3_MIN_SQRT_PRICE_LIMIT || q[1] === V3_MAX_SQRT_PRICE_LIMIT) return;
        amountOut = q[0];
      } else {
        amountOut = (decodeFunctionResult({ abi: v4QuoterAbi, functionName: "quoteExactInputSingle", data: r.returnData }) as readonly [bigint, bigint])[0];
      }
    } catch {
      return;
    }
    if (amountOut > 0n && (best === null || amountOut > best.amountOut)) best = { pool, amountIn, amountOut, leg: legFor(pool, tokenIn, tokenOut) };
  });
  return best;
}

export type RouteRequest = {
  /** Reads state and runs the quotes. */
  client: PublicClient;
  /** Serves eth_getLogs over LOG_WINDOW_BLOCKS (Robinhood Chain's public RPC). */
  logsClient: PublicClient;
  index: PoolIndex;
  /** ETH (address 0) for native ETH. */
  tokenIn: Address;
  tokenOut: Address;
  amountIn: bigint;
  /** The account's Ostra fee (OstraStake.feeBps). */
  feeBps: number;
  slippageBps?: number;
};

/** The best route now (see the file comment). Throws NoRouteError when no hub gives a quote. */
export async function findRoute(r: RouteRequest): Promise<Route> {
  const slippageBps = r.slippageBps ?? DEFAULT_SLIPPAGE_BPS;
  if (!Number.isInteger(slippageBps) || slippageBps < 0 || slippageBps > MAX_SLIPPAGE_BPS) throw new Error(`slippage must be 0 to ${MAX_SLIPPAGE_BPS} bps`);
  if (!Number.isInteger(r.feeBps) || r.feeBps < 0 || r.feeBps > 10_000) throw new Error("bad fee");
  if (r.amountIn <= 0n) throw new Error("the amount must be above 0");
  const tokenIn = routedToken(r.tokenIn);
  const tokenOut = routedToken(r.tokenOut);
  if (tokenIn === tokenOut) throw new Error("tokenIn and tokenOut are the same");

  let best: Route | null = null;
  for (const hub of HUBS) {
    let legIn: LegQuote | null = null;
    let hubAmount = r.amountIn;
    if (tokenIn !== hub) {
      legIn = await bestLeg(r.client, await hubPools(r.client, r.logsClient, r.index, tokenIn, hub), tokenIn, hub, r.amountIn);
      if (legIn === null) continue;
      hubAmount = legIn.amountOut;
    }
    const fee = (hubAmount * BigInt(r.feeBps)) / 10_000n;
    const net = hubAmount - fee;
    let legOut: LegQuote | null = null;
    let expectedOut = net;
    if (tokenOut !== hub) {
      legOut = await bestLeg(r.client, await hubPools(r.client, r.logsClient, r.index, tokenOut, hub), hub, tokenOut, net);
      if (legOut === null) continue;
      expectedOut = legOut.amountOut;
    }
    if (best === null || expectedOut > best.expectedOut) {
      best = {
        tokenIn: getAddress(r.tokenIn),
        tokenOut: getAddress(r.tokenOut),
        amountIn: r.amountIn,
        hub,
        legIn,
        legOut,
        hubAmount,
        feeBps: r.feeBps,
        fee,
        expectedOut,
        slippageBps,
        minOut: (expectedOut * BigInt(10_000 - slippageBps)) / 10_000n,
      };
    }
  }
  if (best === null) throw new NoRouteError(r.tokenIn, r.tokenOut);
  return best;
}

/** The two legs OstraRouter runs for a route. */
export function routeLegs(route: Route): { legIn: Leg; legOut: Leg } {
  return { legIn: route.legIn?.leg ?? NO_LEG, legOut: route.legOut?.leg ?? NO_LEG };
}
