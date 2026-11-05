// Whether an Ostra vault can trade a token: OstraTokenCheck run in one eth_call (nothing is sent or deployed), its
// code set by a state override at the address of the agent's vault for the token (`holder`; a fresh address
// without), so the token sees a holder with code at the vault's own address. The call is made from the account that
// sends the vaults' transactions (`from`: the relayer's or the agent's fee payer, so tx.origin is the real one) at the chain's gas price, with a little ETH (that account's balance given by the
// override). It wraps the ETH and buys the token with the WETH through an immediate escrow order of OstraRouter along
// the route findRoute picks (the WETH sent to the order's escrow, executeEscrow), as a vault buys; sends a share of
// what arrived to a fresh address, as a vault's Transfer out; and sells the rest for WETH the same way, through the
// same pools the other way (a pool a buy went through can take a sale back, even one whose liquidity sat all on the
// token's side before). Right before the buy and right before the sale the contract quotes that route in the same
// state with Uniswap's quoters, which never move a token, so what arrived is compared with a quote of the very same
// swap:
//   ok            bought, moved whole and sold, each within TAX_TOLERANCE_BPS of its quote
//   no_route      no Uniswap v3 or v4 route to it through USDG or WETH quotes now
//   not_buyable   the buy's escrow order did not swap
//   buy_tax       fewer tokens arrived than the buy's quote (or none)
//   move_refused  a Transfer of it (to a fresh address, or to the sale's escrow) reverted or returned false
//   move_tax      a Transfer of it delivered less than was sent, or took more from the sender
//   not_sellable  the sale did not quote, or its escrow order did not swap (a token that can be bought, not sold)
//   sell_tax      less WETH arrived than the sale's quote
//   costly        bought, moved and sold as quoted, but the round trip lost more than MAX_ROUND_TRIP_LOSS_BPS of
//                 the ETH (a pool fee near the cap on each side, or a pool so thin a few dollars move its price)
//   unreadable    its balanceOf did not answer
// A pool too thin for CHECK_ETH ends as no_route: such a token cannot be traded sensibly either.
//
// What it cannot see: a token that tells an Ostra vault or escrow apart from the check by its code hash, that treats
// the escrow of a real order apart from the check's, or that changes later (its owner raises a tax, a proxy is upgraded). So a verdict that passed is kept CHECK_OK_TTL_MS only,
// and a buy is checked again when it is signed after that; one that did not pass is kept CHECK_REFUSED_TTL_MS.

import { decodeFunctionResult, encodeFunctionData, getAddress, keccak256, toHex, zeroAddress, type Address, type Hex, type PublicClient } from "viem";
import { privateKeyToAddress } from "viem/accounts";
import { OSTRA_TOKEN_CHECK_RUNTIME_CODE, ostraTokenCheckAbi } from "./abi.ts";
import { ETH, HUBS, UNISWAP_V3_QUOTER_V2, UNISWAP_V4_QUOTER, WETH } from "./constants.ts";
import { NO_LEG, legFor, type Leg, type Pool } from "./legs.ts";
import type { PoolIndex } from "./pools.ts";
import { NoRouteError, findRoute, routedToken, type Route } from "./route.ts";

/** The ETH the check buys with: 0.001 ETH, a few dollars, enough to cross any pool's dust and little enough to move none. */
export const CHECK_ETH = 1_000_000_000_000_000n;
/** The share of what was bought sent to a fresh address (1%). */
export const CHECK_PROBE_BPS = 100n;
/**
 * How far what arrived may fall short of its quote. The quote and the swap run in the same state, so a token that
 * moves whole arrives exactly as quoted; the margin only absorbs rounding (0.1%).
 */
export const TAX_TOLERANCE_BPS = 10n;
/** How far a Transfer may deliver or take other than what was sent (wei): a share-based token rounds by one or two. */
export const MOVE_TOLERANCE = 2n;
/**
 * The most a buy and a sale back of CHECK_ETH may lose, on the part sold (25%): two 1% pools and the Ostra fee
 * twice lose about 2.4%, two pools at MAX_HOOKLESS_V4_FEE about 19%.
 */
export const MAX_ROUND_TRIP_LOSS_BPS = 2_500n;
/** The gas the check's eth_call may use. */
export const CHECK_GAS = 30_000_000n;
/** How long a verdict that passed is kept (TokenChecks): a buy signed later is checked again. */
export const CHECK_OK_TTL_MS = 60 * 1000;
/** How long a verdict that did not pass is kept (TokenChecks). */
export const CHECK_REFUSED_TTL_MS = 10 * 60 * 1000;
/** OstraStake.FEE_BASE_BPS: the fee of the check's fresh address, at which findRoute quotes its buy too. */
const BASE_FEE_BPS = 20;

/** OstraTokenCheck.FAILED_*: the step a check stopped at. */
const FAILED = { NONE: 0, BUY_QUOTE: 1, BUY: 2, MOVE: 3, SELL_QUOTE: 4, SELL_MOVE: 5, SELL: 6, READ: 7 } as const;

export type TokenVerdictKind = "ok" | "no_route" | "not_buyable" | "buy_tax" | "move_refused" | "move_tax" | "not_sellable" | "sell_tax" | "costly" | "unreadable";

export type TokenVerdict = {
  token: Address;
  ok: boolean;
  kind: TokenVerdictKind;
  /** Why it is not ok, in words an agent can pass on; null when ok. */
  reason: string | null;
  /** The figures the verdict rests on (base units), for logs and tests. */
  figures: Record<string, string>;
  /** When it was checked (ms). */
  at: number;
};

/** Short of `quoted` by more than TAX_TOLERANCE_BPS. */
const short = (got: bigint, quoted: bigint) => got * 10_000n < quoted * (10_000n - TAX_TOLERANCE_BPS);
/** Apart by more than MOVE_TOLERANCE. */
const apart = (a: bigint, b: bigint) => (a > b ? a - b : b - a) > MOVE_TOLERANCE;

const NO_QUOTE = {
  kind: 0,
  tokenIn: zeroAddress,
  tokenOut: zeroAddress,
  fee: 0,
  key: { currency0: zeroAddress, currency1: zeroAddress, fee: 0, tickSpacing: 0, hooks: zeroAddress },
  zeroForOne: false,
};

/** OstraTokenCheck.Quote for a swap of tokenIn for tokenOut on `pool` (WETH stands for a v4 pool's native ETH). */
function quoteOf(pool: Pool, tokenIn: Address, tokenOut: Address) {
  const a = routedToken(tokenIn);
  const b = routedToken(tokenOut);
  if (pool.kind === "v3") return { ...NO_QUOTE, kind: 3, tokenIn: a, tokenOut: b, fee: pool.fee };
  const k = pool.key;
  const currencyIn = a === WETH && (k.currency0 === ETH || k.currency1 === ETH) ? ETH : a;
  return { ...NO_QUOTE, kind: 4, key: k, zeroForOne: currencyIn === getAddress(k.currency0) };
}

type CheckRoute = { hub: Address; legIn: Leg; legOut: Leg; quoteIn: ReturnType<typeof quoteOf>; quoteOut: ReturnType<typeof quoteOf> };

/** The buy (WETH for `token`) as findRoute picked it, and the sale of `token` for WETH through the same pools. */
function checkRoutes(buy: Route, token: Address): { buy: CheckRoute; sell: CheckRoute } {
  const out = buy.legOut;
  if (out === null) throw new Error("a check's buy has a leg out");
  const back = buy.legIn;
  return {
    buy: {
      hub: buy.hub,
      legIn: back?.leg ?? NO_LEG,
      legOut: out.leg,
      quoteIn: back === null ? NO_QUOTE : quoteOf(back.pool, WETH, buy.hub),
      quoteOut: quoteOf(out.pool, buy.hub, token),
    },
    sell: {
      hub: buy.hub,
      legIn: legFor(out.pool, token, buy.hub),
      legOut: back === null ? NO_LEG : legFor(back.pool, buy.hub, WETH),
      quoteIn: quoteOf(out.pool, token, buy.hub),
      quoteOut: back === null ? NO_QUOTE : quoteOf(back.pool, buy.hub, WETH),
    },
  };
}

export type CheckRequest = {
  client: PublicClient;
  /** Serves eth_getLogs over LOG_WINDOW_BLOCKS (Robinhood Chain's public RPC). */
  logsClient: PublicClient;
  index: PoolIndex;
  router: Address;
  token: Address;
  /** The account that sends the vaults' transactions (the relayer's or the agent's fee payer); a fresh one without. */
  from?: Address | (() => Promise<Address>);
  /**
   * Where the check runs: the address of the agent's vault for the token (its code replaced for the call), so a token
   * that treats that address apart is seen doing it; a fresh address without.
   */
  holder?: (token: Address) => Promise<Address>;
  now?: () => number;
};

const fresh = (what: string) => privateKeyToAddress(keccak256(toHex(`ostra-token-check:${what}:${Date.now()}:${Math.random()}`)));

/** Checks `token` (see the file comment). Throws only when the chain cannot be read, never for what the token does. */
export async function checkSwapToken(r: CheckRequest): Promise<TokenVerdict> {
  const token = getAddress(r.token);
  const at = (r.now ?? Date.now)();
  const verdict = (kind: TokenVerdictKind, reason: string | null, figures: Record<string, string> = {}): TokenVerdict => ({ token, ok: kind === "ok", kind, reason, figures, at });
  if (token === ETH || (HUBS as readonly Address[]).includes(token)) return verdict("ok", null);
  let route: Route;
  try {
    route = await findRoute({ client: r.client, logsClient: r.logsClient, index: r.index, tokenIn: WETH, tokenOut: token, amountIn: CHECK_ETH, feeBps: BASE_FEE_BPS, slippageBps: 0 });
  } catch (err) {
    if (err instanceof NoRouteError) return verdict("no_route", `${token} has no Uniswap v3 or v4 pool against USDG or WETH that quotes a buy now`);
    throw err;
  }
  const { buy, sell } = checkRoutes(route, token);
  const from = getAddress(r.from === undefined ? fresh("from") : typeof r.from === "function" ? await r.from() : r.from);
  // The probe is fresh; the check runs at the holder's address, or a fresh one. It measures what moves by balance
  // deltas and sells only what it bought, so what a vault there holds already changes nothing.
  const checkAt = r.holder === undefined ? fresh("at") : getAddress(await r.holder(token));
  const probe = fresh("probe");
  const salt = keccak256(toHex(`ostra-token-check:salt:${token}:${at}:${Math.random()}`));
  // A real gas price (an eth_call at 0 is a tell a token can test): twice the base fee, at least what the node asks.
  const [block, asked] = await Promise.all([r.client.getBlock(), r.client.getGasPrice()]);
  const base = block.baseFeePerGas ?? 0n;
  const gasPrice = asked > base * 2n ? asked : base * 2n;
  const data = encodeFunctionData({
    abi: ostraTokenCheckAbi,
    functionName: "run",
    args: [{ router: r.router, token, weth: WETH, v3Quoter: UNISWAP_V3_QUOTER_V2, v4Quoter: UNISWAP_V4_QUOTER, probe, probeBps: CHECK_PROBE_BPS, salt, buy, sell }],
  });
  const { data: ret } = await r.client.call({
    account: from,
    to: checkAt,
    data,
    value: CHECK_ETH,
    gas: CHECK_GAS,
    gasPrice,
    stateOverride: [
      { address: checkAt, code: OSTRA_TOKEN_CHECK_RUNTIME_CODE as Hex },
      { address: from, balance: CHECK_ETH * 10n + CHECK_GAS * gasPrice * 2n },
    ],
  });
  if (ret === undefined) throw new Error("OstraTokenCheck returned nothing");
  const x = decodeFunctionResult({ abi: ostraTokenCheckAbi, functionName: "run", data: ret });
  const figures: Record<string, string> = {
    hub: route.hub,
    buyQuoted: x.buyQuoted.toString(),
    buyHeld: x.buyHeld.toString(),
    moveSent: x.moveSent.toString(),
    moveArrived: x.moveArrived.toString(),
    moveLeft: x.moveLeft.toString(),
    sellAmount: x.sellAmount.toString(),
    sellQuoted: x.sellQuoted.toString(),
    sellArrived: x.sellArrived.toString(),
    sellRefunded: x.sellRefunded.toString(),
    sellStuck: x.sellStuck.toString(),
    sellOwed: x.sellOwed.toString(),
    sellWeth: x.sellWeth.toString(),
    gas: (x.buyGas + x.moveGas + x.sellGas).toString(),
  };
  const why = x.reason === "0x" ? "" : ` (revert data ${x.reason.slice(0, 74)})`;
  switch (x.failed) {
    case FAILED.BUY_QUOTE:
      return verdict("no_route", `${token} has no pool that quotes a buy now`, figures);
    case FAILED.BUY:
      return verdict("not_buyable", `a buy of ${token} through an OstraRouter escrow order did not swap${why}`, figures);
    case FAILED.READ:
      return verdict("unreadable", `${token} did not answer balanceOf`, figures);
  }
  // A buy that delivered short (or nothing) is told before what it stopped the steps after it from showing.
  if (x.buyHeld === 0n || short(x.buyHeld, x.buyQuoted)) return verdict("buy_tax", `a buy of ${token} delivered ${x.buyHeld} of the ${x.buyQuoted} quoted: it takes a cut when bought`, figures);
  if (x.failed === FAILED.MOVE) return verdict("move_refused", `${token} refused a transfer from a holder with code to a fresh address${why}`, figures);
  if (apart(x.moveArrived, x.moveSent) || apart(x.moveLeft, x.moveSent)) {
    return verdict("move_tax", `a transfer of ${x.moveSent} ${token} delivered ${x.moveArrived} and took ${x.moveLeft}: it does not move whole`, figures);
  }
  switch (x.failed) {
    case FAILED.SELL_QUOTE:
      return verdict("not_sellable", `${token} can be bought but a sale of it back into the same pools does not quote`, figures);
    case FAILED.SELL_MOVE:
      return verdict("move_refused", `${token} refused the transfer of a sale to its escrow${why}`, figures);
    case FAILED.SELL:
      if (apart(x.sellArrived, x.sellAmount)) {
        return verdict("move_tax", `a transfer of ${x.sellAmount} ${token} to a sale's escrow delivered ${x.sellArrived}: it does not move whole`, figures);
      }
      if (x.sellStuck > MOVE_TOLERANCE) {
        return verdict("not_sellable", `${token} can be bought but a sale of it left ${x.sellStuck} in its escrow${why === "" ? ", which the token does not let pay out" : why}: what a vault sells would stay there`, figures);
      }
      if (x.sellOwed > 0n) {
        return verdict("move_refused", `${token} can be bought but refused the refund of a sale that did not swap: OstraRouter owes ${x.sellOwed} until it is claimed${why}`, figures);
      }
      if (apart(x.sellRefunded, x.sellArrived)) {
        return verdict("move_tax", `a sale of ${x.sellArrived} ${token} came back as ${x.sellRefunded}: it does not move whole between contracts, and OstraRouter needs the exact amount`, figures);
      }
      return verdict("not_sellable", `${token} can be bought but a sale of it through an OstraRouter escrow order did not swap and came back whole${why}`, figures);
  }
  if (x.failed !== FAILED.NONE) throw new Error(`OstraTokenCheck stopped at an unknown step ${x.failed}`);
  if (x.sellWeth === 0n || short(x.sellWeth, x.sellQuoted)) return verdict("sell_tax", `a sale of ${token} paid ${x.sellWeth} WETH of the ${x.sellQuoted} quoted: it takes a cut when sold`, figures);
  // The ETH the part sold was bought with, against the WETH its sale paid.
  const spent = (CHECK_ETH * x.sellAmount) / x.buyHeld;
  if (x.sellWeth * 10_000n < spent * (10_000n - MAX_ROUND_TRIP_LOSS_BPS)) {
    return verdict("costly", `buying ${token} and selling it straight back loses ${((spent - x.sellWeth) * 10_000n) / spent / 100n}% through its pools`, figures);
  }
  return verdict("ok", null, figures);
}

/**
 * Verdicts kept per token (one that passed CHECK_OK_TTL_MS, one that did not CHECK_REFUSED_TTL_MS), and checks of the
 * same token at once made once.
 */
export class TokenChecks {
  readonly #request: Omit<CheckRequest, "token">;
  readonly #okTtlMs: number;
  readonly #refusedTtlMs: number;
  readonly #kept = new Map<string, TokenVerdict>();
  readonly #running = new Map<string, Promise<TokenVerdict>>();

  constructor(request: Omit<CheckRequest, "token">, ttl: { okMs?: number; refusedMs?: number } = {}) {
    this.#request = request;
    this.#okTtlMs = ttl.okMs ?? CHECK_OK_TTL_MS;
    this.#refusedTtlMs = ttl.refusedMs ?? CHECK_REFUSED_TTL_MS;
  }

  #fresh(v: TokenVerdict, now: number): boolean {
    return now - v.at < (v.ok ? this.#okTtlMs : this.#refusedTtlMs);
  }

  async check(tokenText: Address): Promise<TokenVerdict> {
    const token = getAddress(tokenText);
    const k = token.toLowerCase();
    const now = (this.#request.now ?? Date.now)();
    const kept = this.#kept.get(k);
    if (kept !== undefined && this.#fresh(kept, now)) return kept;
    const running = this.#running.get(k);
    if (running !== undefined) return running;
    const p = checkSwapToken({ ...this.#request, token })
      .then((v) => {
        this.#kept.set(k, v);
        if (this.#kept.size > 5_000) for (const [key, old] of this.#kept) if (!this.#fresh(old, now)) this.#kept.delete(key);
        return v;
      })
      .finally(() => this.#running.delete(k));
    this.#running.set(k, p);
    return p;
  }
}
