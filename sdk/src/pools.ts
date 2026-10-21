// Finds the pools a token can be swapped in against a hub: Uniswap v3 pools by fee tier (UniswapV3Factory.getPool)
// and Uniswap v4 pools from the PoolManager's Initialize events for that exact pair of currencies (one
// eth_getLogs per 10,000,000 blocks, on an RPC that serves that range: Robinhood Chain's public one does; a window
// with more logs than the RPC returns is split in halves). Only pools with liquidity in range now are kept; which
// one a leg uses is decided by quotes (route.ts), never by these numbers. Against the WETH hub a v4 pool may hold
// native ETH instead (the leg unwraps or OstraRouter wraps). A v4 pool counts only with no hook or a hook in
// ROUTABLE_HOOKS.
//
// A PoolIndex remembers the v4 pools found per pair of currencies and the block it searched up to, so a pair is
// searched from the start only once; data() and the constructor hand that memory to a file or anything else.

import { encodeAbiParameters, encodeFunctionData, decodeFunctionResult, getAddress, hexToBigInt, keccak256, toHex, zeroAddress, type Address, type Hex, type PublicClient } from "viem";
import { ETH, LOG_WINDOW_BLOCKS, MULTICALL3, ROUTABLE_HOOKS, UNISWAP_V3_FACTORY, UNISWAP_V4_POOL_MANAGER, V3_FEE_TIERS, WETH } from "./constants.ts";
import type { Pool, PoolKey } from "./legs.ts";
import { initializeEvent, multicall3Abi, poolManagerAbi, v3FactoryAbi, v3PoolAbi } from "./uniswap.ts";

/** A v4 pool of a token, as its Initialize event gave it. */
export type V4PoolRecord = { id: Hex; key: PoolKey };
type PairEntry = { searchedTo: string; pools: V4PoolRecord[] };
/** tokens: per pair of currencies, "currency0-currency1". */
export type PoolIndexData = { version: 1; tokens: Record<string, PairEntry> };

/** v4-core StateLibrary: the pools mapping sits at slot 6; a pool's liquidity three slots into its state. */
const POOLS_SLOT = 6n;
const LIQUIDITY_OFFSET = 3n;

export function poolId(key: PoolKey): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "address" }, { type: "address" }, { type: "uint24" }, { type: "int24" }, { type: "address" }],
      [key.currency0, key.currency1, key.fee, key.tickSpacing, key.hooks],
    ),
  );
}

function stateSlot(id: Hex, offset: bigint): Hex {
  const base = hexToBigInt(keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "uint256" }], [id, POOLS_SLOT])));
  return toHex(base + offset, { size: 32 });
}

export class PoolIndex {
  #data: PoolIndexData;

  constructor(data?: PoolIndexData) {
    if (data !== undefined && data.version !== 1) throw new Error("unknown pool index version");
    this.#data = data ?? { version: 1, tokens: {} };
  }

  /** What to save to keep the index. */
  data(): PoolIndexData {
    return this.#data;
  }

  /**
   * The v4 pools of the pair (a, b), in either order, searched up to the latest block with `logsClient` (an RPC
   * that serves LOG_WINDOW_BLOCKS per request).
   */
  async v4PoolsOfPair(logsClient: PublicClient, a: Address, b: Address): Promise<V4PoolRecord[]> {
    const [c0, c1] = BigInt(getAddress(a)) < BigInt(getAddress(b)) ? [getAddress(a), getAddress(b)] : [getAddress(b), getAddress(a)];
    const pairKey = `${c0}-${c1}`;
    const entry = this.#data.tokens[pairKey] ?? { searchedTo: "-1", pools: [] };
    const head = await logsClient.getBlockNumber();
    const seen = new Set(entry.pools.map((p) => p.id));
    let from = BigInt(entry.searchedTo) + 1n;
    while (from <= head) {
      const to = from + LOG_WINDOW_BLOCKS - 1n < head ? from + LOG_WINDOW_BLOCKS - 1n : head;
      for (const l of await initializeLogs(logsClient, c0, c1, from, to)) {
        const x = l.args;
        if (x.id === undefined || x.fee === undefined || x.tickSpacing === undefined || x.hooks === undefined || seen.has(x.id)) continue;
        seen.add(x.id);
        entry.pools.push({ id: x.id, key: { currency0: c0, currency1: c1, fee: x.fee, tickSpacing: x.tickSpacing, hooks: getAddress(x.hooks) } });
      }
      entry.searchedTo = to.toString();
      from = to + 1n;
    }
    this.#data.tokens[pairKey] = entry;
    return entry.pools;
  }
}

type InitializeArgs = { id?: Hex; fee?: number; tickSpacing?: number; hooks?: Address };

/** Initialize logs of the pair (c0, c1) in [from, to]; a range the RPC refuses as too many logs is split in halves. */
async function initializeLogs(logsClient: PublicClient, c0: Address, c1: Address, from: bigint, to: bigint): Promise<{ args: InitializeArgs }[]> {
  try {
    return await logsClient.getLogs({ address: UNISWAP_V4_POOL_MANAGER, event: initializeEvent, args: { currency0: c0, currency1: c1 }, fromBlock: from, toBlock: to });
  } catch (err) {
    if (from >= to || !/exceeds limit|too many|query returned more than/i.test(String((err as Error).message ?? err))) throw err;
    const mid = from + (to - from) / 2n;
    return [...(await initializeLogs(logsClient, c0, c1, from, mid)), ...(await initializeLogs(logsClient, c0, c1, mid + 1n, to))];
  }
}

/** The currencies a v4 pool may hold on the hub's side: the hub, and native ETH for the WETH hub. */
function hubCurrencies(hub: Address): Address[] {
  return getAddress(hub) === WETH ? [WETH, ETH] : [getAddress(hub)];
}

async function aggregate(client: PublicClient, calls: { target: Address; callData: Hex }[]): Promise<{ success: boolean; returnData: Hex }[]> {
  if (calls.length === 0) return [];
  const data = encodeFunctionData({ abi: multicall3Abi, functionName: "aggregate3", args: [calls.map((c) => ({ ...c, allowFailure: true }))] });
  const { data: ret } = await client.call({ to: MULTICALL3, data });
  if (ret === undefined) throw new Error("Multicall3 returned nothing");
  return decodeFunctionResult({ abi: multicall3Abi, functionName: "aggregate3", data: ret }) as { success: boolean; returnData: Hex }[];
}

/**
 * The pools `token` trades in against `hub` with liquidity now: Uniswap v3 at every fee tier, and Uniswap v4 from
 * `index` (searched with `logsClient`). `client` reads the state.
 */
export async function hubPools(client: PublicClient, logsClient: PublicClient, index: PoolIndex, token: Address, hub: Address): Promise<Pool[]> {
  const t = getAddress(token);
  const h = getAddress(hub);
  if (t === h) return [];
  const out: Pool[] = [];

  // Uniswap v3: the pool address per fee tier, then its in-range liquidity.
  const found = await aggregate(
    client,
    V3_FEE_TIERS.map((fee) => ({ target: UNISWAP_V3_FACTORY, callData: encodeFunctionData({ abi: v3FactoryAbi, functionName: "getPool", args: [t, h, fee] }) })),
  );
  const v3: { address: Address; fee: number }[] = [];
  found.forEach((r, i) => {
    if (!r.success) return;
    const address = decodeFunctionResult({ abi: v3FactoryAbi, functionName: "getPool", data: r.returnData }) as Address;
    if (address !== zeroAddress) v3.push({ address: getAddress(address), fee: V3_FEE_TIERS[i] as number });
  });
  const v3Liquidity = await aggregate(client, v3.map((p) => ({ target: p.address, callData: encodeFunctionData({ abi: v3PoolAbi, functionName: "liquidity" }) })));
  v3.forEach((p, i) => {
    const r = v3Liquidity[i];
    if (r === undefined || !r.success) return;
    const l = decodeFunctionResult({ abi: v3PoolAbi, functionName: "liquidity", data: r.returnData }) as bigint;
    if (l > 0n) out.push({ kind: "v3", address: p.address, tokenA: t, tokenB: h, fee: p.fee });
  });

  // Uniswap v4: the token's pools whose other currency is the hub's, with liquidity in range now.
  const records: V4PoolRecord[] = [];
  for (const side of hubCurrencies(h)) {
    for (const p of await index.v4PoolsOfPair(logsClient, t, side)) if (ROUTABLE_HOOKS.includes(getAddress(p.key.hooks))) records.push(p);
  }
  if (records.length > 0) {
    const slots = records.map((p) => stateSlot(p.id, LIQUIDITY_OFFSET));
    const values = (await client.readContract({ address: UNISWAP_V4_POOL_MANAGER, abi: poolManagerAbi, functionName: "extsload", args: [slots] })) as Hex[];
    records.forEach((p, i) => {
      const v = values[i];
      if (v !== undefined && hexToBigInt(v) % (1n << 128n) > 0n) out.push({ kind: "v4", id: p.id, key: p.key });
    });
  }
  return out;
}
