// The transactions of Ostra Swap: a wallet's OstraRouter.swap, and an Ostra vault's orders through an escrow.
// An immediate order is the vault's Transfer spend to escrowAddress(order), then OstraRouter.executeEscrow, in one
// transaction. A standing order (limit, take-profit, DCA) is the vault's Transfer spend alone (with
// OstraRouter.announce beside it); its executor runs each tranche later with executeEscrow, and closeEscrow sends
// what is left back to the vault (its canceller at any time, anyone after the deadline). The escrow address is
// computed here exactly as OstraRouter.escrowAddress does (CREATE2 of OstraSwapEscrow, which takes no constructor
// arguments, with the order's hash as salt); the fork tests check the two agree.

import { encodeAbiParameters, encodeFunctionData, getAddress, getContractAddress, keccak256, toHex, type Address, type Hex } from "viem";
import { OSTRA_SWAP_ESCROW_CREATION_CODE, ostraRouterAbi, ostraStakeAbi } from "./abi.ts";
import { DEFAULT_ORDER_TTL_SECONDS, ETH, MAX_LOCK_BENEFICIARIES } from "./constants.ts";

const ZERO: Address = "0x0000000000000000000000000000000000000000";
const MAX_UINT32 = 2 ** 32 - 1;
const MAX_UINT64 = (1n << 64n) - 1n;
/** The longest a standing order may stay open: a year. */
export const MAX_STANDING_ORDER_SECONDS = 365n * 24n * 3_600n;
import type { Leg } from "./legs.ts";
import { routeLegs, type Route } from "./route.ts";

/** Where Ostra Swap is deployed (deployments/robinhood-mainnet.json). */
export type SwapDeployment = {
  chainId: number;
  /** The block the contracts were deployed at. */
  fromBlock: string;
  router: Address;
  stake: Address;
  buyback: Address;
};

/**
 * OstraRouter.Order: every term of a vault's order, bound by its escrow address. The fee is the recipient's (its
 * OSTRA lock); what is not swapped goes back to refundTo.
 */
export type Order = {
  tokenIn: Address;
  tokenOut: Address;
  /** The whole input (a standing order's tranches share it). */
  amountIn: bigint;
  /** The least tokenOut for all of amountIn, after the fee (each tranche: its share, rounded up). */
  minOut: bigint;
  recipient: Address;
  refundTo: Address;
  /** Standing orders: when tranche 0 may run (unix seconds). Immediate orders: 0. */
  notBefore: bigint;
  deadline: bigint;
  /** 0: an immediate order. 1 or more: a standing order in that many tranches. */
  tranches: number;
  /** Standing orders: seconds between tranches. */
  interval: number;
  /** Standing orders: who runs tranches (zero: anyone). */
  executor: Address;
  /** May send what the escrow holds back to refundTo at any time (zero: nobody). */
  canceller: Address;
  /** routeHash(hub, legIn, legOut): every swap of the order goes along it. */
  route: Hex;
  salt: Hex;
};

const legParam = {
  type: "tuple",
  components: [
    { name: "commands", type: "bytes" },
    { name: "inputs", type: "bytes[]" },
  ],
} as const;

/** OstraRouter.routeHash: keccak256(abi.encode(hub, legIn, legOut)). */
export function routeHash(hub: Address, legIn: Leg, legOut: Leg): Hex {
  return keccak256(encodeAbiParameters([{ type: "address" }, legParam, legParam], [getAddress(hub), legIn, legOut]));
}

const orderParam = {
  type: "tuple",
  components: [
    { name: "tokenIn", type: "address" },
    { name: "tokenOut", type: "address" },
    { name: "amountIn", type: "uint256" },
    { name: "minOut", type: "uint256" },
    { name: "recipient", type: "address" },
    { name: "refundTo", type: "address" },
    { name: "notBefore", type: "uint64" },
    { name: "deadline", type: "uint64" },
    { name: "tranches", type: "uint32" },
    { name: "interval", type: "uint32" },
    { name: "executor", type: "address" },
    { name: "canceller", type: "address" },
    { name: "route", type: "bytes32" },
    { name: "salt", type: "bytes32" },
  ],
} as const;

/** OstraRouter.orderHash. */
export function orderHash(order: Order): Hex {
  return keccak256(encodeAbiParameters([orderParam], [order]));
}

/** OstraRouter.escrowAddress: where the vault sends order.amountIn of order.tokenIn. */
export function escrowAddress(router: Address, order: Order): Address {
  return getContractAddress({ opcode: "CREATE2", from: getAddress(router), salt: orderHash(order), bytecode: OSTRA_SWAP_ESCROW_CREATION_CODE });
}

/**
 * The order of a vault's swap along `route`: the route's tokens, amount, minOut and legs, the output to
 * `recipient` (the vault of tokenOut), a failed swap back to `vault` (which holds `vaultToken`: it must be
 * route.tokenIn, as the escrow hands over only the order's tokenIn), executable for `ttlSeconds` from `now`.
 */
export function orderFor(route: Route, vault: Address, vaultToken: Address, recipient: Address, now: bigint, salt: Hex, ttlSeconds = DEFAULT_ORDER_TTL_SECONDS): Order {
  if (route.tokenIn === ETH || route.tokenOut === ETH) throw new Error("a vault swaps ERC-20 tokens: WETH, not native ETH");
  if (getAddress(vaultToken) !== getAddress(route.tokenIn)) throw new Error(`the vault holds ${vaultToken}, not the route's tokenIn ${route.tokenIn}`);
  if (!/^0x[0-9a-fA-F]{64}$/.test(salt)) throw new Error("the salt is 32 bytes");
  const { legIn, legOut } = routeLegs(route);
  return {
    tokenIn: route.tokenIn,
    tokenOut: route.tokenOut,
    amountIn: route.amountIn,
    minOut: route.minOut,
    recipient: getAddress(recipient),
    refundTo: getAddress(vault),
    notBefore: 0n,
    deadline: now + BigInt(ttlSeconds),
    tranches: 0,
    interval: 0,
    executor: ZERO,
    canceller: ZERO,
    route: routeHash(route.hub, legIn, legOut),
    salt,
  };
}

/** The terms of a standing order (standingOrderFor). */
export type StandingOrderTerms = {
  tokenIn: Address;
  tokenOut: Address;
  amountIn: bigint;
  /**
   * The least tokenOut for all of amountIn, after the fee: the price asked (a limit or take-profit order) or the
   * worst price accepted (a DCA). It is the only price a tranche is held to, so it must be above zero.
   */
  minOut: bigint;
  /** The vault the input comes from (refundTo), and the token it holds (must be tokenIn). */
  vault: Address;
  vaultToken: Address;
  /** Gets the output: the vault of tokenOut. Its OSTRA lock sets the fee. */
  recipient: Address;
  /** The chain's time now (the latest block's timestamp). */
  now: bigint;
  notBefore: bigint;
  deadline: bigint;
  /** 1: a limit or take-profit order. More: a DCA, tranche k from notBefore + k * intervalSeconds. */
  tranches: number;
  intervalSeconds: number;
  /** Runs tranches: the Ostra keeper (zero: anyone). Either way it chooses only when, never how. */
  executor: Address;
  /** May return the escrow to the vault at any time; it can send it nowhere else. */
  canceller: Address;
  /** The route every tranche takes: its legs spend whatever they get, so one route serves every tranche. */
  route: Route;
  salt: Hex;
};

/** A standing order: the vault's Transfer of amountIn to escrowAddress(order) places it. */
export function standingOrderFor(t: StandingOrderTerms): Order {
  const tokenIn = getAddress(t.tokenIn);
  const tokenOut = getAddress(t.tokenOut);
  if (tokenIn === ETH || tokenOut === ETH) throw new Error("a vault swaps ERC-20 tokens: WETH, not native ETH");
  if (tokenIn === tokenOut) throw new Error("tokenIn and tokenOut are the same token");
  if (getAddress(t.vaultToken) !== tokenIn) throw new Error(`the vault holds ${t.vaultToken}, not tokenIn ${tokenIn}`);
  if (t.amountIn <= 0n) throw new Error("amountIn must be above zero");
  if (t.minOut <= 0n) throw new Error("a standing order needs a minOut above zero: it is the only price a tranche is held to");
  if (!Number.isInteger(t.tranches) || t.tranches < 1 || t.tranches > MAX_UINT32) throw new Error("tranches is 1 to 2^32 - 1");
  if (BigInt(t.tranches) > t.amountIn) throw new Error("more tranches than units of amountIn");
  if (!Number.isInteger(t.intervalSeconds) || t.intervalSeconds < 0 || t.intervalSeconds > MAX_UINT32) throw new Error("intervalSeconds is 0 to 2^32 - 1");
  // OstraRouter paces late tranches half an interval apart: under a minute that pacing means nothing.
  if (t.tranches > 1 && t.intervalSeconds < 60) throw new Error("a DCA needs at least 60 seconds between tranches");
  if (t.notBefore < 0n || t.deadline > MAX_UINT64) throw new Error("notBefore and deadline are uint64 unix seconds");
  if (t.deadline <= t.now) throw new Error("the deadline has passed");
  if (t.deadline - (t.notBefore > t.now ? t.notBefore : t.now) > MAX_STANDING_ORDER_SECONDS) throw new Error("a standing order stays open a year at most");
  const lastAt = t.notBefore + BigInt(t.tranches - 1) * BigInt(t.intervalSeconds);
  // A tranche that runs late moves the ones after it (OstraRouter paces them half an interval apart): one more
  // interval before the deadline leaves the last tranche room to catch up, as long as tranche 0 runs by
  // notBefore + tranches * interval - (tranches - 1) * floor(interval / 2) (independent re-review); a later
  // start returns the last tranches to the vault unswapped at the deadline.
  const lastWithSlack = lastAt + BigInt(t.intervalSeconds);
  if (t.deadline < lastWithSlack) throw new Error(`the deadline ${t.deadline} leaves no room after the last tranche's time ${lastAt} (at least ${lastWithSlack})`);
  if (t.notBefore > t.now + MAX_STANDING_ORDER_SECONDS) throw new Error("notBefore is more than a year away");
  const recipient = getAddress(t.recipient);
  const vault = getAddress(t.vault);
  if (recipient === ZERO || vault === ZERO) throw new Error("the recipient and the vault must be set");
  if (recipient === vault) throw new Error("the recipient is the vault of tokenOut, not the vault the input comes from");
  if (getAddress(t.canceller) === ZERO) throw new Error("a standing order needs a canceller: without one only the deadline returns the funds");
  if (!/^0x[0-9a-fA-F]{64}$/.test(t.salt)) throw new Error("the salt is 32 bytes");
  if (t.route.tokenIn === ETH || getAddress(t.route.tokenIn) !== tokenIn || getAddress(t.route.tokenOut) !== tokenOut) throw new Error("the route is for other tokens");
  const { legIn, legOut } = routeLegs(t.route);
  const route = routeHash(t.route.hub, legIn, legOut);
  return {
    tokenIn,
    tokenOut,
    amountIn: t.amountIn,
    minOut: t.minOut,
    recipient,
    refundTo: vault,
    notBefore: t.notBefore,
    deadline: t.deadline,
    tranches: t.tranches,
    interval: t.intervalSeconds,
    executor: getAddress(t.executor),
    canceller: getAddress(t.canceller),
    route,
    salt: t.salt,
  };
}

/**
 * Tranche k of a standing order, as OstraRouter runs it: when it may run (notBefore + k * interval, and an
 * half an interval after the tranche before, which ran at `lastTrancheAt`: OstraRouter.lastTrancheAt), its input, and its
 * minimum output.
 */
export function trancheTerms(order: Order, k: number, lastTrancheAt?: bigint): { at: bigint; amountIn: bigint; minOut: bigint } {
  if (order.tranches < 1 || !Number.isInteger(k) || k < 0 || k >= order.tranches) throw new Error(`no tranche ${k}`);
  if (k !== 0 && lastTrancheAt === undefined) throw new Error("tranche k > 0 needs OstraRouter.lastTrancheAt");
  const n = BigInt(order.tranches);
  const share = order.amountIn / n;
  const amountIn = k + 1 === order.tranches ? order.amountIn - share * (n - 1n) : share;
  const minOut = order.amountIn === 0n ? 0n : (order.minOut * amountIn + order.amountIn - 1n) / order.amountIn;
  let at = order.notBefore + BigInt(k) * BigInt(order.interval);
  const paced = (lastTrancheAt ?? 0n) + BigInt(order.interval) / 2n;
  if (k !== 0 && paced > at) at = paced;
  return { at, amountIn, minOut };
}

/** OstraRouter.announce(order) calldata: publishes a standing order's terms for its executor. */
export function announceData(order: Order): Hex {
  return encodeFunctionData({ abi: ostraRouterAbi, functionName: "announce", args: [order] });
}

/** OstraRouter.closeEscrow(order) calldata: the canceller's (any time) or anyone's (after the deadline). */
export function closeEscrowData(order: Order): Hex {
  return encodeFunctionData({ abi: ostraRouterAbi, functionName: "closeEscrow", args: [order] });
}

/** A random order salt. */
export function randomSalt(): Hex {
  return toHex(crypto.getRandomValues(new Uint8Array(32)));
}

/** OstraVault spend action 0 (Transfer) params: abi.encode(address to, uint256 amount). */
export function transferParams(to: Address, amount: bigint): Hex {
  return encodeAbiParameters([{ type: "address" }, { type: "uint256" }], [getAddress(to), amount]);
}

/** OstraRouter.executeEscrow(order, hub, legIn, legOut) calldata along the order's `route`: an immediate order, or
 *  a standing order's next tranche. */
export function executeEscrowData(order: Order, route: Route): Hex {
  const { legIn, legOut } = routeLegs(route);
  return encodeFunctionData({ abi: ostraRouterAbi, functionName: "executeEscrow", args: [order, route.hub, legIn, legOut] });
}

/**
 * OstraRouter.swap calldata and value for a wallet: route.tokenIn ETH is sent as value; an ERC-20 needs an
 * allowance of route.amountIn for the router first. Output to `recipient` (ETH when route.tokenOut is ETH).
 */
export function walletSwapCall(router: Address, route: Route, recipient: Address): { to: Address; data: Hex; value: bigint } {
  const { legIn, legOut } = routeLegs(route);
  return {
    to: getAddress(router),
    data: encodeFunctionData({
      abi: ostraRouterAbi,
      functionName: "swap",
      args: [route.tokenIn, route.tokenOut, route.amountIn, route.minOut, getAddress(recipient), route.hub, legIn, legOut],
    }),
    value: route.tokenIn === ETH ? route.amountIn : 0n,
  };
}

/** OstraStake.lock(amount, beneficiaries) calldata: 1 to MAX_LOCK_BENEFICIARIES distinct accounts, replacing the previous ones. */
export function lockData(amount: bigint, beneficiaries: readonly Address[]): Hex {
  const list = beneficiaries.map((b) => getAddress(b));
  if (list.length === 0 || list.length > MAX_LOCK_BENEFICIARIES || new Set(list).size !== list.length) throw new Error(`a lock names 1 to ${MAX_LOCK_BENEFICIARIES} distinct accounts`);
  return encodeFunctionData({ abi: ostraStakeAbi, functionName: "lock", args: [amount, list] });
}

export function withdrawLockData(): Hex {
  return encodeFunctionData({ abi: ostraStakeAbi, functionName: "withdraw" });
}
