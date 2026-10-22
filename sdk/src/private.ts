// Private balances on Ostra Swap (src/OstraPrivatePool.sol): what an agent runs to keep tokens as notes and to swap
// or withdraw them without showing which note it spends, or whose (privacy/README.md).
//
// A note is a commitment P(value || tag) in one of the pool's commitment trees: value binds the token and the amount,
// tag = P(rho || sk) the agent's secret key sk and the note's nonce rho. The agent keeps sk (one per agent) and each
// note's rho; whoever knows them can spend the note. Proofs come from `ostra-prove` (privacy/circuit) through a Prover:
// cli-prover.ts runs its binary as a child process on Node (sk and rho go to it on stdin, never on its command line);
// this file imports nothing of Node's, so it also runs in a browser with another Prover.
//
// The pool's trees are rebuilt from its NoteAdded events (PoolTrees), in index order; a Merkle path is checked
// against the root the pool recorded before a proof is made from it. Every spend is bound to its exact call through
// the bind hashes below, computed here exactly as the pool computes them (unshieldHash, swapHash); the fork tests
// check the two agree. A private swap pays the router's base fee (OstraRouter.swapAtBaseFee): its route is found
// with feeBps PRIVATE_SWAP_FEE_BPS.

import { encodeAbiParameters, encodeFunctionData, getAbiItem, getAddress, getContractAddress, keccak256, parseEventLogs, toHex, type Address, type Hex, type PublicClient, type TransactionReceipt } from "viem";
import { OSTRA_SHIELD_ESCROW_CREATION_CODE, ostraPrivatePoolAbi } from "./abi.ts";
import { ETH, LOG_WINDOW_BLOCKS } from "./constants.ts";
import type { Leg } from "./legs.ts";
import { routeHash } from "./orders.ts";
import { routeLegs, type Route } from "./route.ts";

/** KoalaBear: the field of the spend circuit. */
export const FIELD_P = 2130706433n;
/** Leaves per commitment tree (depth 20): when one is full the pool starts the next. */
export const TREE_DEPTH = 20;
/** OstraStake.FEE_BASE_BPS: the router's fee on every private swap. */
export const PRIVATE_SWAP_FEE_BPS = 20;
/** OstraPrivatePool.UNSHIELD_DOMAIN and SWAP_DOMAIN. */
export const UNSHIELD_DOMAIN: Hex = keccak256(toHex("OstraPrivatePool.unshield.v1"));
export const SWAP_DOMAIN: Hex = keccak256(toHex("OstraPrivatePool.privateSwap.v1"));

const MAX_AMOUNT = 1n << 128n;
const MAX_UINT64 = (1n << 64n) - 1n;
const ZERO: Address = "0x0000000000000000000000000000000000000000";

// ---------------------------------------------------------------------------------------------
// Digests
// ---------------------------------------------------------------------------------------------

/** 8 field elements packed in a bytes32, element i in bits [32 i, 32 i + 32) (privacy/contracts/src/Notes.sol). */
export type Digest = Hex;

export function packDigest(elements: readonly (string | number | bigint)[]): Digest {
  if (elements.length !== 8) throw new Error("a digest has 8 field elements");
  let v = 0n;
  elements.forEach((e, i) => {
    const x = BigInt(e);
    if (x < 0n || x >= FIELD_P) throw new Error("a digest element is not below P");
    v |= x << BigInt(32 * i);
  });
  return toHex(v, { size: 32 });
}

/** The 8 elements of a digest, as the decimal strings ostra-prove takes. */
export function unpackDigest(d: Digest): string[] {
  if (!/^0x[0-9a-fA-F]{64}$/.test(d)) throw new Error("a digest is 32 bytes");
  const v = BigInt(d);
  return Array.from({ length: 8 }, (_, i) => {
    const x = (v >> BigInt(32 * i)) & 0xffffffffn;
    if (x >= FIELD_P) throw new Error("a digest element is not below P");
    return x.toString();
  });
}

// ---------------------------------------------------------------------------------------------
// The prover
// ---------------------------------------------------------------------------------------------

/** One ostra-prove command: its JSON request (none for `secret`) and its JSON answer. */
export type Prover = (command: "secret" | "note" | "path" | "prove", request?: unknown) => Promise<unknown>;

function digestOf(v: unknown, what: string): Digest {
  if (!Array.isArray(v)) throw new Error(`ostra-prove gave no ${what}`);
  return packDigest(v as string[]);
}

/** A fresh random digest from the operating system: the agent's sk (once), or a note's rho (once per note). */
export async function newSecret(prover: Prover): Promise<Digest> {
  return digestOf(((await prover("secret")) as { digest?: unknown }).digest, "digest");
}

export type NoteKeys = { tag: Digest; commitment: Digest; nullifier: Digest };

/** The tag, commitment and nullifier of the note of `amount` of `asset` under sk and rho. */
export async function noteKeys(prover: Prover, sk: Digest, rho: Digest, asset: Address, amount: bigint): Promise<NoteKeys> {
  if (amount < 0n || amount >= MAX_AMOUNT) throw new Error("an amount is below 2^128");
  const r = (await prover("note", { sk: unpackDigest(sk), rho: unpackDigest(rho), asset: getAddress(asset), amount: amount.toString() })) as Record<string, unknown>;
  return { tag: digestOf(r.tag, "tag"), commitment: digestOf(r.commitment, "commitment"), nullifier: digestOf(r.nullifier, "nullifier") };
}

/** The tag of sk and rho (a tag does not depend on the token or the amount): what shield and a swap's output take. */
export async function tagOf(prover: Prover, sk: Digest, rho: Digest): Promise<Digest> {
  return (await noteKeys(prover, sk, rho, ZERO, 0n)).tag;
}

// ---------------------------------------------------------------------------------------------
// Notes and the pool's trees
// ---------------------------------------------------------------------------------------------

/** A note the agent holds; its rho is what (with sk) spends it. */
export type PrivateNote = { asset: Address; amount: bigint; rho: Digest; commitment: Digest; tree: number; index: number };

type TreeRecord = { leaves: Digest[]; roots: Digest[] };
export type PoolTreesData = { version: 1; pool: Address; searchedTo: string; trees: TreeRecord[] };

const noteAddedEvent = getAbiItem({ abi: ostraPrivatePoolAbi, name: "NoteAdded" });

/**
 * The pool's commitment trees as its NoteAdded events build them. data() and the constructor hand the trees to a
 * file, so the logs are read from the start only once.
 */
export class PoolTrees {
  #data: PoolTreesData;
  /** The sync running now: syncs run one at a time (each one's rollback assumes no other changes the trees). */
  #syncing: Promise<void> = Promise.resolve();

  /** `fromBlock`: the block the pool was deployed at (no note before it). */
  constructor(pool: Address, fromBlock: bigint, data?: PoolTreesData) {
    if (data !== undefined) {
      if (data.version !== 1) throw new Error("unknown trees version");
      if (getAddress(data.pool) !== getAddress(pool)) throw new Error("these trees are another pool's");
    }
    this.#data = data ?? { version: 1, pool: getAddress(pool), searchedTo: (fromBlock - 1n).toString(), trees: [] };
  }

  data(): PoolTreesData {
    return this.#data;
  }

  /**
   * Reads the NoteAdded events up to `confirmations` blocks below the latest one with `logsClient` (an RPC serving
   * LOG_WINDOW_BLOCKS), then checks the result against the pool itself at that block: its current tree's size and
   * root. A sync that fails changes nothing (independent review, 21 Oct 2026: an RPC may answer eth_getLogs only up
   * to its own head, which can lag the block number another node gave). Keep `confirmations` small: the public RPC
   * serves state only some thousand blocks back.
   */
  sync(logsClient: PublicClient, confirmations = 0n): Promise<void> {
    const run = this.#syncing.then(() => this.#sync(logsClient, confirmations));
    this.#syncing = run.catch(() => {});
    return run;
  }

  async #sync(logsClient: PublicClient, confirmations: bigint): Promise<void> {
    // Not viem's cached block number (cacheTime): a block number seconds old would leave the last notes out.
    const latest = await logsClient.getBlockNumber({ cacheTime: 0 });
    const head = latest - confirmations;
    // Nothing new: a node behind the last sync has nothing to add, and the trees stay as they are.
    if (head <= BigInt(this.#data.searchedTo)) return;
    const trees = this.#data.trees;
    const kept = { searchedTo: this.#data.searchedTo, trees: trees.length, leaves: trees[trees.length - 1]?.leaves.length ?? 0 };
    try {
      let from = BigInt(this.#data.searchedTo) + 1n;
      while (from <= head) {
        const to = from + LOG_WINDOW_BLOCKS - 1n < head ? from + LOG_WINDOW_BLOCKS - 1n : head;
        const logs = await noteLogs(logsClient, this.#data.pool, from, to);
        logs.sort((a, b) => (a.blockNumber === b.blockNumber ? a.logIndex - b.logIndex : a.blockNumber < b.blockNumber ? -1 : 1));
        for (const l of logs) this.#add(l.tree, l.index, l.commitment, l.root);
        this.#data.searchedTo = to.toString();
        from = to + 1n;
      }
      const read = (functionName: "currentTree" | "treeSize" | "currentRoot", args: readonly bigint[] = []) =>
        logsClient.readContract({ address: this.#data.pool, abi: ostraPrivatePoolAbi, functionName, args: args as never, blockNumber: head } as never) as Promise<unknown>;
      const current = Number(await read("currentTree"));
      const size = BigInt((await read("treeSize", [BigInt(current)])) as bigint);
      const have = BigInt(this.#data.trees[current]?.leaves.length ?? 0);
      if (size !== have || this.#data.trees.length > current + 1) throw new Error(`the pool's tree ${current} holds ${size} notes at block ${head}, the logs gave ${have}`);
      if (size > 0n && ((await read("currentRoot")) as Hex).toLowerCase() !== this.root(current).toLowerCase()) throw new Error(`the pool's root at block ${head} is not the one the logs give`);
    } catch (err) {
      this.#data.searchedTo = kept.searchedTo;
      trees.length = kept.trees;
      const last = trees[kept.trees - 1];
      if (last !== undefined) {
        last.leaves.length = kept.leaves;
        last.roots.length = kept.leaves;
      }
      throw err;
    }
  }

  #add(tree: bigint, index: bigint, commitment: Digest, root: Digest): void {
    const t = Number(tree);
    const trees = this.#data.trees;
    // The same log twice (an RPC may repeat one): skipped when it is exactly a note already in place.
    const seen = trees[t]?.leaves[Number(index)];
    if (seen !== undefined && seen.toLowerCase() === commitment.toLowerCase()) return;
    if (t === trees.length) {
      if (t > 0 && (trees[t - 1] as TreeRecord).leaves.length !== 2 ** TREE_DEPTH) throw new Error(`tree ${t} starts before tree ${t - 1} is full`);
      trees.push({ leaves: [], roots: [] });
    }
    const r = trees[t];
    if (r === undefined || t !== trees.length - 1) throw new Error(`a note for tree ${t} out of order`);
    if (Number(index) !== r.leaves.length) throw new Error(`tree ${t}: note ${index} came after ${r.leaves.length} notes`);
    r.leaves.push(commitment);
    r.roots.push(root);
  }

  /** The leaves of tree `tree`, in index order. */
  leaves(tree: number): readonly Digest[] {
    return this.#data.trees[tree]?.leaves ?? [];
  }

  /** The root of tree `tree` after its last note. */
  root(tree: number): Digest {
    const roots = this.#data.trees[tree]?.roots;
    const root = roots?.[roots.length - 1];
    if (root === undefined) throw new Error(`no tree ${tree}`);
    return root;
  }

  /** Where `commitment` is, or null. */
  find(commitment: Digest): { tree: number; index: number } | null {
    const c = commitment.toLowerCase();
    for (let t = 0; t < this.#data.trees.length; t++) {
      const i = (this.#data.trees[t] as TreeRecord).leaves.findIndex((l) => l.toLowerCase() === c);
      if (i >= 0) return { tree: t, index: i };
    }
    return null;
  }
}

type NoteLog = { tree: bigint; index: bigint; commitment: Digest; root: Digest; blockNumber: bigint; logIndex: number };

/** NoteAdded logs of `pool` in [from, to]; a range the RPC refuses as too many logs is split in halves. */
async function noteLogs(client: PublicClient, pool: Address, from: bigint, to: bigint): Promise<NoteLog[]> {
  try {
    const logs = await client.getLogs({ address: pool, event: noteAddedEvent, fromBlock: from, toBlock: to, strict: true });
    return logs.map((l) => {
      if (l.blockNumber === null || l.logIndex === null) throw new Error("a pending NoteAdded log");
      return { tree: l.args.tree, index: l.args.index, commitment: l.args.commitment, root: l.args.root, blockNumber: l.blockNumber, logIndex: l.logIndex };
    });
  } catch (err) {
    if (from >= to || !/exceeds limit|too many|query returned more than/i.test(String((err as Error).message ?? err))) throw err;
    const mid = from + (to - from) / 2n;
    return [...(await noteLogs(client, pool, from, mid)), ...(await noteLogs(client, pool, mid + 1n, to))];
  }
}

/** The Merkle path of `note` in `trees`, checked to lead to the root the pool recorded for its tree. */
export async function notePath(prover: Prover, trees: PoolTrees, note: PrivateNote): Promise<{ root: Digest; path: string[][] }> {
  const leaves = trees.leaves(note.tree);
  if (leaves[note.index]?.toLowerCase() !== note.commitment.toLowerCase()) throw new Error("the note is not at its place in the pool's tree (sync the trees)");
  const r = (await prover("path", { leaves: leaves.map(unpackDigest), index: note.index })) as { root?: unknown; path?: unknown };
  const root = digestOf(r.root, "root");
  if (root.toLowerCase() !== trees.root(note.tree).toLowerCase()) throw new Error("the tree rebuilt here does not lead to the root the pool recorded");
  if (!Array.isArray(r.path) || r.path.length !== TREE_DEPTH) throw new Error("ostra-prove gave no path");
  return { root, path: r.path as string[][] };
}

// ---------------------------------------------------------------------------------------------
// Bind hashes and public values
// ---------------------------------------------------------------------------------------------

/** What a private swap pays for (OstraPrivatePool.SwapTerms): the route is OstraRouter's. */
export type PrivateSwapTerms = { tokenOut: Address; minOut: bigint; outTag: Digest; hub: Address; legIn: Leg; legOut: Leg };

/** OstraPrivatePool.unshieldHash. */
export function unshieldHash(chainId: number, pool: Address, relayer: Address, deadline: bigint, recipient: Address): Hex {
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "uint256" }, { type: "address" }, { type: "address" }, { type: "uint64" }, { type: "address" }],
      [UNSHIELD_DOMAIN, BigInt(chainId), getAddress(pool), getAddress(relayer), deadline, getAddress(recipient)],
    ),
  );
}

/** OstraPrivatePool.swapHash. */
export function swapHash(chainId: number, pool: Address, relayer: Address, deadline: bigint, t: PrivateSwapTerms): Hex {
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "uint256" },
        { type: "address" },
        { type: "address" },
        { type: "uint64" },
        { type: "address" },
        { type: "uint256" },
        { type: "bytes32" },
        { type: "bytes32" },
      ],
      [SWAP_DOMAIN, BigInt(chainId), getAddress(pool), getAddress(relayer), deadline, getAddress(t.tokenOut), t.minOut, t.outTag, routeHash(t.hub, t.legIn, t.legOut)],
    ),
  );
}

/** Notes.publicValues: the 48 public values the pool hands the verifier for a spend. */
export function publicValues(asset: Address, v: bigint, fee: bigint, nullifier: Digest, root: Digest, changeCommitment: Digest, bindHash: Hex): bigint[] {
  const limbs = (x: bigint, n: number, bits: number) => Array.from({ length: n }, (_, i) => (x >> BigInt(bits * i)) & ((1n << BigInt(bits)) - 1n));
  if (v >= MAX_AMOUNT || fee >= MAX_AMOUNT) throw new Error("an amount is below 2^128");
  const words = (d: Digest) => unpackDigest(d).map((x) => BigInt(x));
  const h = BigInt(bindHash);
  return [
    ...limbs(BigInt(getAddress(asset)), 6, 27),
    ...limbs(v, 5, 26),
    ...limbs(fee, 5, 26),
    ...words(nullifier),
    ...words(root),
    ...words(changeCommitment),
    ...Array.from({ length: 8 }, (_, i) => (h >> BigInt(32 * i)) & 0x3fffffffn),
  ];
}

// ---------------------------------------------------------------------------------------------
// Spends
// ---------------------------------------------------------------------------------------------

/** OstraPrivatePool.SpendTerms. */
export type SpendTerms = {
  asset: Address;
  v: bigint;
  fee: bigint;
  nullifier: Digest;
  root: Digest;
  changeCommitment: Digest;
  relayer: Address;
  deadline: bigint;
};

/**
 * A spend ready to send, and the change note it makes (amount zero: nothing to spend). `recipient`: an unshield's
 * (null for a private swap).
 */
export type Spend = { terms: SpendTerms; proof: Hex; recipient: Address | null; change: { rho: Digest; amount: bigint; commitment: Digest } };

export type SpendRequest = {
  prover: Prover;
  sk: Digest;
  note: PrivateNote;
  trees: PoolTrees;
  chainId: number;
  pool: Address;
  /** Paid in the note's token to `relayer` (anyone may send the call; zero fee: relayer may be zero). */
  fee: bigint;
  relayer: Address;
  /** The spend is valid until this time (unix seconds), inclusive. */
  deadline: bigint;
  /**
   * The change note's nonce: draw it with newSecret and keep it before proving, and prove again for the same note
   * with the same one, so that whichever proof lands, its change note is known (none given: the prover draws one,
   * returned in Spend.change).
   */
  changeRho?: Digest;
};

async function prove(r: SpendRequest, v: bigint, bindHash: Hex, recipient: Address | null): Promise<Spend> {
  const n = r.note;
  if (r.changeRho !== undefined && r.changeRho.toLowerCase() === n.rho.toLowerCase()) throw new Error("changeRho must be a fresh secret, not the note's rho");
  if (v < 0n || r.fee < 0n || v + r.fee > n.amount) throw new Error(`the note holds ${n.amount}, less than ${v} + ${r.fee}`);
  if (r.fee !== 0n && getAddress(r.relayer) === ZERO) throw new Error("a fee needs a relayer");
  if (r.deadline < 0n || r.deadline > MAX_UINT64) throw new Error("the deadline is uint64 unix seconds");
  const keys = await noteKeys(r.prover, r.sk, n.rho, n.asset, n.amount);
  if (keys.commitment.toLowerCase() !== n.commitment.toLowerCase()) throw new Error("the note is not this sk's (or its rho, token or amount is wrong)");
  const { root, path } = await notePath(r.prover, r.trees, n);
  const out = (await r.prover("prove", {
    sk: unpackDigest(r.sk),
    rho: unpackDigest(n.rho),
    asset: getAddress(n.asset),
    amount: n.amount.toString(),
    index: n.index,
    path,
    v: v.toString(),
    fee: r.fee.toString(),
    bind_hash: bindHash,
    root: unpackDigest(root),
    ...(r.changeRho === undefined ? {} : { change_rho: unpackDigest(r.changeRho) }),
  })) as { proof?: unknown; public_values?: unknown; change_rho?: unknown };
  if (typeof out.proof !== "string" || !/^0x[0-9a-f]*$/.test(out.proof) || !Array.isArray(out.public_values) || out.public_values.length !== 48) throw new Error("ostra-prove gave no proof");
  const pv = (out.public_values as string[]).map((x) => BigInt(x));
  const changeCommitment = packDigest(pv.slice(32, 40));
  const terms: SpendTerms = { asset: getAddress(n.asset), v, fee: r.fee, nullifier: keys.nullifier, root, changeCommitment, relayer: getAddress(r.relayer), deadline: r.deadline };
  // The proof's public values are the ones the pool will hand the verifier.
  const want = publicValues(terms.asset, v, r.fee, terms.nullifier, root, changeCommitment, bindHash);
  if (want.some((x, i) => x !== pv[i])) throw new Error("the proof's public values are not the spend's");
  const changeRho = digestOf(out.change_rho, "change_rho");
  if (r.changeRho !== undefined && changeRho.toLowerCase() !== r.changeRho.toLowerCase()) throw new Error("the prover used another change nonce");
  const change = n.amount - v - r.fee;
  // The change note is sk's: its commitment is the one the proof makes.
  if ((await noteKeys(r.prover, r.sk, changeRho, n.asset, change)).commitment.toLowerCase() !== changeCommitment.toLowerCase()) throw new Error("the change note is not this sk's");
  return { terms, proof: out.proof as Hex, recipient, change: { rho: changeRho, amount: change, commitment: changeCommitment } };
}

/** Proves spending `v` of the note to `recipient` (OstraPrivatePool.unshield). */
export async function proveUnshield(r: SpendRequest & { v: bigint; recipient: Address }): Promise<Spend> {
  if (getAddress(r.recipient) === ZERO) throw new Error("an unshield needs a recipient");
  return prove(r, r.v, unshieldHash(r.chainId, r.pool, r.relayer, r.deadline, r.recipient), getAddress(r.recipient));
}

/**
 * Proves swapping route.amountIn of the note along `route` (found with feeBps PRIVATE_SWAP_FEE_BPS, from the note's
 * token), its output a new note for sk under `outRho` (a fresh secret). Returns the spend and the swap's terms.
 */
export async function provePrivateSwap(r: SpendRequest & { route: Route; outRho: Digest }): Promise<{ spend: Spend; swap: PrivateSwapTerms }> {
  const route = r.route;
  if (route.feeBps !== PRIVATE_SWAP_FEE_BPS) throw new Error(`a private swap pays the base fee: find its route with feeBps ${PRIVATE_SWAP_FEE_BPS}`);
  if (route.tokenIn === ETH || route.tokenOut === ETH) throw new Error("notes hold ERC-20 tokens: WETH, not native ETH");
  if (getAddress(route.tokenIn) !== getAddress(r.note.asset)) throw new Error(`the route swaps ${route.tokenIn}, the note holds ${r.note.asset}`);
  if (r.outRho.toLowerCase() === r.note.rho.toLowerCase()) throw new Error("outRho must be a fresh secret");
  const { legIn, legOut } = routeLegs(route);
  const swap: PrivateSwapTerms = { tokenOut: getAddress(route.tokenOut), minOut: route.minOut, outTag: await tagOf(r.prover, r.sk, r.outRho), hub: getAddress(route.hub), legIn, legOut };
  if (r.changeRho !== undefined && r.changeRho.toLowerCase() === r.outRho.toLowerCase()) throw new Error("the change and the output share a rho");
  const spend = await prove(r, route.amountIn, swapHash(r.chainId, r.pool, r.relayer, r.deadline, swap), null);
  if (spend.change.rho.toLowerCase() === r.outRho.toLowerCase()) throw new Error("the change and the output share a rho");
  return { spend, swap };
}

// ---------------------------------------------------------------------------------------------
// Calls and receipts
// ---------------------------------------------------------------------------------------------

/** OstraPrivatePool.shield calldata: needs an allowance of `amount` of `token` for the pool first. */
export function shieldCall(pool: Address, token: Address, amount: bigint, tag: Digest): { to: Address; data: Hex } {
  if (amount <= 0n || amount >= MAX_AMOUNT) throw new Error("shield an amount above 0 and below 2^128");
  return { to: getAddress(pool), data: encodeFunctionData({ abi: ostraPrivatePoolAbi, functionName: "shield", args: [getAddress(token), amount, tag] }) };
}

/**
 * Where a sender that can only transfer (an Ostra vault) sends `token` to shield it for `tag`
 * (OstraPrivatePool.shieldEscrowAddress, computed here as the pool does: CREATE2 of OstraShieldEscrow from the pool,
 * salted with keccak256(abi.encode(token, tag))). Use a fresh tag (a fresh rho) for every shield.
 */
export function shieldEscrowAddress(pool: Address, token: Address, tag: Digest): Address {
  const salt = keccak256(encodeAbiParameters([{ type: "address" }, { type: "bytes32" }], [getAddress(token), tag]));
  return getContractAddress({ opcode: "CREATE2", from: getAddress(pool), salt, bytecode: OSTRA_SHIELD_ESCROW_CREATION_CODE });
}

/** OstraPrivatePool.shieldFromEscrow(token, tag): anyone may send it once the escrow holds the tokens; the note is the tag's owner's. */
export function shieldFromEscrowCall(pool: Address, token: Address, tag: Digest): { to: Address; data: Hex } {
  return { to: getAddress(pool), data: encodeFunctionData({ abi: ostraPrivatePoolAbi, functionName: "shieldFromEscrow", args: [getAddress(token), tag] }) };
}

export function unshieldCall(pool: Address, spend: Spend, recipient: Address): { to: Address; data: Hex } {
  if (spend.recipient === null || spend.recipient !== getAddress(recipient)) throw new Error("this spend was proved for another recipient (or is a swap)");
  return { to: getAddress(pool), data: encodeFunctionData({ abi: ostraPrivatePoolAbi, functionName: "unshield", args: [spend.terms, getAddress(recipient), spend.proof] }) };
}

export function privateSwapCall(pool: Address, spend: Spend, swap: PrivateSwapTerms): { to: Address; data: Hex } {
  if (spend.recipient !== null) throw new Error("this spend was proved for an unshield");
  return { to: getAddress(pool), data: encodeFunctionData({ abi: ostraPrivatePoolAbi, functionName: "privateSwap", args: [spend.terms, swap, spend.proof] }) };
}

function poolEvents(receipt: TransactionReceipt, pool: Address) {
  if (receipt.status !== "success") throw new Error("the transaction reverted");
  return parseEventLogs({ abi: ostraPrivatePoolAbi, logs: receipt.logs.filter((l) => getAddress(l.address) === getAddress(pool)) });
}

function placed(receipt: TransactionReceipt, pool: Address, commitment: Digest): { tree: number; index: number } {
  for (const e of poolEvents(receipt, pool)) {
    if (e.eventName === "NoteAdded" && e.args.commitment.toLowerCase() === commitment.toLowerCase()) return { tree: Number(e.args.tree), index: Number(e.args.index) };
  }
  throw new Error(`no NoteAdded for ${commitment}`);
}

/** The note a shield of the agent's (tag from sk and `rho`) made. */
export async function shieldedNote(prover: Prover, sk: Digest, rho: Digest, receipt: TransactionReceipt, pool: Address): Promise<PrivateNote> {
  const tag = (await tagOf(prover, sk, rho)).toLowerCase();
  for (const e of poolEvents(receipt, pool)) {
    if (e.eventName !== "Shielded" || e.args.tag.toLowerCase() !== tag) continue;
    const asset = getAddress(e.args.token);
    const keys = await noteKeys(prover, sk, rho, asset, e.args.amount);
    if (keys.commitment.toLowerCase() !== e.args.commitment.toLowerCase()) throw new Error("the shielded commitment is not this note's");
    return { asset, amount: e.args.amount, rho, commitment: e.args.commitment, ...placed(receipt, pool, e.args.commitment) };
  }
  throw new Error("no Shielded event for this tag");
}

/** The change note of a spend that landed (null when the change is zero). */
export function changeNote(spend: Spend, receipt: TransactionReceipt, pool: Address): PrivateNote | null {
  const where = placed(receipt, pool, spend.change.commitment);
  if (spend.change.amount === 0n) return null;
  return { asset: spend.terms.asset, amount: spend.change.amount, rho: spend.change.rho, commitment: spend.change.commitment, ...where };
}

/** The output note of a private swap that landed, checked to be sk's under `outRho`. */
export async function swapOutputNote(prover: Prover, sk: Digest, outRho: Digest, spend: Spend, swap: PrivateSwapTerms, receipt: TransactionReceipt, pool: Address): Promise<PrivateNote> {
  for (const e of poolEvents(receipt, pool)) {
    if (e.eventName !== "PrivateSwapped" || e.args.nullifier.toLowerCase() !== spend.terms.nullifier.toLowerCase()) continue;
    if (e.args.outTag.toLowerCase() !== swap.outTag.toLowerCase()) throw new Error("the swap paid another tag");
    const keys = await noteKeys(prover, sk, outRho, swap.tokenOut, e.args.amountOut);
    if (keys.commitment.toLowerCase() !== e.args.outCommitment.toLowerCase()) throw new Error("the output note is not this sk's under outRho");
    return { asset: swap.tokenOut, amount: e.args.amountOut, rho: outRho, commitment: e.args.outCommitment, ...placed(receipt, pool, e.args.outCommitment) };
  }
  throw new Error("no PrivateSwapped event for this spend");
}
