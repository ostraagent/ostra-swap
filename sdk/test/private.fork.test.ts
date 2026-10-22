// Private balances through the SDK, on a fork of Robinhood Chain mainnet (anvil, OSTRA_FORK_RPC or the public
// RPC): OstraRouter, SpendVerifier and OstraPrivatePool are deployed from the Foundry build, every proof is made by
// ostra-prove (privacy/target/release/ostra-prove, operating-system randomness) from the trees the SDK rebuilds out
// of the pool's events, and the SDK's bind hashes must be the pool's own. Needs `forge build`, the prover built
// (cd privacy && cargo build --release --locked --bin ostra-prove) and anvil on PATH.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, encodeFunctionData, getAddress, http, parseEther, parseUnits, type Address, type Hex, type PublicClient, type TransactionReceipt } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  ETH,
  OSTRA,
  OSTRA_PONS_CURVE,
  PONS_HOOK,
  PRIVATE_SWAP_FEE_BPS,
  PoolIndex,
  PoolTrees,
  ROBINHOOD_PUBLIC_RPC,
  TREASURY,
  UNIVERSAL_ROUTER,
  USDG,
  WETH,
  changeNote,
  erc20Abi,
  findRoute,
  newSecret,
  noteKeys,
  ostraPrivatePoolAbi,
  privateSwapCall,
  proveUnshield,
  provePrivateSwap,
  shieldCall,
  shieldEscrowAddress,
  shieldFromEscrowCall,
  shieldedNote,
  swapHash,
  swapOutputNote,
  tagOf,
  unshieldCall,
  unshieldHash,
  walletSwapCall,
  type Digest,
  type PrivateNote,
} from "../src/index.ts";
import { cliProver } from "../src/cli-prover.ts";

const NVDA: Address = "0xd0601CE157Db5bdC3162BbaC2a2C8aF5320D9EEC";
const PORT = 8_746;
const FORK_URL = `http://127.0.0.1:${PORT}`;
const CHAIN_ID = 4663;
/** anvil's default accounts: a deployer that also relays, the agent's funding wallet, and another shielder. */
const DEPLOYER = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const AGENT = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a7c43dea1e1be8b3e3a");
const OTHER = privateKeyToAccount("0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a");
const RECIPIENT = getAddress("0x00000000000000000000000000000000000D0D0D");
const ZERO: Address = "0x0000000000000000000000000000000000000000";

const prover = cliProver(fileURLToPath(new URL("../../privacy/target/release/ostra-prove", import.meta.url)));
let anvil: ChildProcess;
let client: PublicClient;
const logsClient = createPublicClient({ transport: http(ROBINHOOD_PUBLIC_RPC, { retryCount: 6, retryDelay: 2_000 }) }) as PublicClient;
const wallet = (account: typeof DEPLOYER) => createWalletClient({ account, transport: http(FORK_URL) });
const index = new PoolIndex();
let router: Address;
let pool: Address;
let trees: PoolTrees;
let sk: Digest;
/** The agent's notes, as it keeps them. */
const notes: PrivateNote[] = [];

function artifact(file: string, name: string): { abi: unknown[]; bytecode: Hex } {
  const a = JSON.parse(readFileSync(new URL(`../../out/${file}/${name}.json`, import.meta.url), "utf8")) as { abi: unknown[]; bytecode: { object: Hex } };
  return { abi: a.abi, bytecode: a.bytecode.object };
}

async function deploy(file: string, name: string, args: unknown[]): Promise<Address> {
  const a = artifact(file, name);
  const hash = await wallet(DEPLOYER).deployContract({ abi: a.abi, bytecode: a.bytecode, args, chain: null, gas: 15_000_000n });
  const r = await client.waitForTransactionReceipt({ hash });
  assert.equal(r.status, "success");
  assert.ok(r.contractAddress);
  console.log(`deployed ${name}: ${r.gasUsed} gas`);
  return getAddress(r.contractAddress);
}

async function send(account: typeof DEPLOYER, call: { to: Address; data: Hex; value?: bigint }, gas = 3_000_000n): Promise<TransactionReceipt> {
  const hash = await wallet(account).sendTransaction({ ...call, chain: null, gas, gasPrice: 0n });
  const r = await client.waitForTransactionReceipt({ hash });
  assert.equal(r.status, "success", `transaction to ${call.to} reverted`);
  return r;
}

const balance = (token: Address, who: Address) => client.readContract({ address: token, abi: erc20Abi, functionName: "balanceOf", args: [who] }) as Promise<bigint>;
const poolRead = (functionName: string, args: unknown[] = []) => client.readContract({ address: pool, abi: ostraPrivatePoolAbi, functionName: functionName as never, args: args as never });

/** USDG for `account`, bought with ETH through OstraRouter along the SDK's route. */
async function buyUsdg(account: typeof DEPLOYER, eth: bigint): Promise<void> {
  const route = await findRoute({ client, logsClient, index, tokenIn: ETH, tokenOut: USDG, amountIn: eth, feeBps: 20, slippageBps: 0 });
  await send(account, walletSwapCall(router, route, account.address));
}

/** Shields `amount` of USDG from `account` for sk under a fresh rho; returns the note. */
async function shield(account: typeof DEPLOYER, owner: Digest, amount: bigint): Promise<PrivateNote> {
  const rho = await newSecret(prover);
  await send(account, { to: USDG, data: encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [pool, amount] }) });
  const r = await send(account, shieldCall(pool, USDG, amount, await tagOf(prover, owner, rho)), 5_000_000n);
  return shieldedNote(prover, owner, rho, r, pool);
}

/** The SDK's trees agree with the pool: same leaf count and the pool's current root. */
async function assertTreesMatch(): Promise<void> {
  await trees.sync(client);
  const tree = Number(await poolRead("currentTree"));
  assert.equal(BigInt(trees.leaves(tree).length), await poolRead("treeSize", [BigInt(tree)]));
  assert.equal(trees.root(tree), await poolRead("currentRoot"));
}

before(async () => {
  const fork = process.env.OSTRA_FORK_RPC || ROBINHOOD_PUBLIC_RPC;
  anvil = spawn("anvil", ["--fork-url", fork, "--port", String(PORT), "--base-fee", "0", "--gas-price", "0", "--gas-limit", "60000000"], { stdio: ["ignore", "ignore", "pipe"] });
  let anvilErr = "";
  anvil.stderr?.on("data", (b: Buffer) => {
    anvilErr = (anvilErr + b.toString()).slice(-2_000);
  });
  const probe = createPublicClient({ transport: http(FORK_URL, { retryCount: 0, timeout: 2_000 }) }) as PublicClient;
  for (let i = 0; ; i++) {
    if (anvil.exitCode !== null) throw new Error(`anvil exited (${anvil.exitCode}): ${anvilErr.replace(/https?:\/\/\S+/g, "<url>")}`);
    try {
      if ((await probe.getChainId()) === CHAIN_ID) break;
    } catch {}
    if (i > 120) throw new Error("anvil did not answer within 2 minutes");
    await new Promise((r) => setTimeout(r, 1_000));
  }
  client = createPublicClient({ transport: http(FORK_URL, { retryCount: 3, retryDelay: 1_000, timeout: 180_000 }) }) as PublicClient;
  for (const a of [DEPLOYER, AGENT, OTHER]) await client.request({ method: "anvil_setBalance" as never, params: [a.address, "0x56BC75E2D63100000"] as never });
  const stake = await deploy("OstraStake.sol", "OstraStake", [OSTRA]);
  const buyback = await deploy("OstraBuyback.sol", "OstraBuyback", [OSTRA, USDG, WETH, UNIVERSAL_ROUTER, OSTRA_PONS_CURVE, PONS_HOOK, DEPLOYER.address, DEPLOYER.address]);
  router = await deploy("OstraRouter.sol", "OstraRouter", [UNIVERSAL_ROUTER, USDG, WETH, stake, buyback, TREASURY]);
  const verifier = await deploy("SpendVerifier.sol", "SpendVerifier", []);
  const fromBlock = (await client.getBlockNumber()) + 1n;
  pool = await deploy("OstraPrivatePool.sol", "OstraPrivatePool", [verifier, router]);
  trees = new PoolTrees(pool, fromBlock);
  sk = await newSecret(prover);
  await buyUsdg(AGENT, parseEther("0.2"));
  await buyUsdg(OTHER, parseEther("0.02"));
});

after(() => {
  anvil?.kill();
});

test("shield: the note is the agent's and the SDK's trees are the pool's", { timeout: 600_000 }, async () => {
  notes.push(await shield(AGENT, sk, parseUnits("200", 6)));
  // Another owner's note, so that the agent's is not the only leaf.
  await shield(OTHER, await newSecret(prover), parseUnits("5", 6));
  const n = notes[0] as PrivateNote;
  assert.equal(n.amount, parseUnits("200", 6));
  assert.equal(n.tree, 0);
  assert.equal(n.index, 0);
  assert.equal(await poolRead("isNote", [n.commitment]), true);
  await assertTreesMatch();
  assert.deepEqual(trees.find(n.commitment), { tree: 0, index: 0 });
  // The same data, reloaded, is the same trees.
  const again = new PoolTrees(pool, 0n, JSON.parse(JSON.stringify(trees.data())));
  assert.equal(again.root(0), trees.root(0));
});

test("shield from an escrow, as a vault does: the SDK's escrow address is the pool's, and the note is the tag's owner's", { timeout: 600_000 }, async () => {
  const rho = await newSecret(prover);
  const tag = await tagOf(prover, sk, rho);
  const escrow = shieldEscrowAddress(pool, USDG, tag);
  assert.equal(escrow, getAddress((await poolRead("shieldEscrowAddress", [USDG, tag])) as Address));
  // The sender only transfers; someone else (a relayer) has the pool take it.
  await send(OTHER, { to: USDG, data: encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [escrow, parseUnits("3", 6)] }) });
  const r = await send(DEPLOYER, shieldFromEscrowCall(pool, USDG, tag), 5_000_000n);
  const n = await shieldedNote(prover, sk, rho, r, pool);
  assert.equal(n.amount, parseUnits("3", 6));
  assert.equal(n.asset, USDG);
  assert.equal(await balance(USDG, escrow), 0n);
  await assertTreesMatch();
});

test("private swap USDG to NVDA through a relayer: the quote is paid into a note, the change stays private", { timeout: 900_000 }, async () => {
  const n = notes.shift() as PrivateNote;
  const v = parseUnits("120", 6);
  const fee = parseUnits("1", 6);
  const route = await findRoute({ client, logsClient, index, tokenIn: USDG, tokenOut: NVDA, amountIn: v, feeBps: PRIVATE_SWAP_FEE_BPS, slippageBps: 0 });
  const deadline = (await client.getBlock()).timestamp + 3_600n;
  const outRho = await newSecret(prover);
  await assert.rejects(provePrivateSwap({ prover, sk, note: n, trees, chainId: CHAIN_ID, pool, fee, relayer: DEPLOYER.address, deadline, route: { ...route, feeBps: 0 }, outRho }));
  await assert.rejects(provePrivateSwap({ prover, sk: await newSecret(prover), note: n, trees, chainId: CHAIN_ID, pool, fee, relayer: DEPLOYER.address, deadline, route, outRho }));
  // The change nonce is drawn and kept first: a second proof of the same spend makes the same change note.
  const changeRho = await newSecret(prover);
  const { spend, swap } = await provePrivateSwap({ prover, sk, note: n, trees, chainId: CHAIN_ID, pool, fee, relayer: DEPLOYER.address, deadline, route, outRho, changeRho });
  const retry = await provePrivateSwap({ prover, sk, note: n, trees, chainId: CHAIN_ID, pool, fee, relayer: DEPLOYER.address, deadline, route, outRho, changeRho });
  assert.equal(retry.spend.change.commitment, spend.change.commitment);
  assert.equal(spend.change.rho, changeRho);
  assert.notEqual(retry.spend.proof, spend.proof);
  assert.equal(swapHash(CHAIN_ID, pool, DEPLOYER.address, deadline, swap), await poolRead("swapHash", [DEPLOYER.address, deadline, swap]));
  const call = privateSwapCall(pool, spend, swap);
  console.log(`privateSwap calldata ${(call.data.length - 2) / 2} bytes, proof ${(spend.proof.length - 2) / 2} bytes`);

  // With another relayer: refused (anyone may send the call; the fee goes to the relayer the proof names).
  const otherRelayer = privateSwapCall(pool, { ...spend, terms: { ...spend.terms, relayer: OTHER.address } }, swap);
  await assert.rejects(client.call({ account: OTHER.address, to: otherRelayer.to, data: otherRelayer.data, gas: 30_000_000n }));

  const relayerBefore = await balance(USDG, DEPLOYER.address);
  const r = await send(DEPLOYER, call, 30_000_000n);
  console.log(`privateSwap gas ${r.gasUsed}`);
  assert.equal(await balance(USDG, DEPLOYER.address) - relayerBefore, fee);
  assert.equal(await poolRead("isSpent", [spend.terms.nullifier]), true);

  const out = await swapOutputNote(prover, sk, outRho, spend, swap, r, pool);
  assert.equal(out.amount, route.expectedOut);
  assert.equal(out.asset, NVDA);
  const change = changeNote(spend, r, pool);
  assert.ok(change);
  assert.equal(change.amount, parseUnits("79", 6));
  assert.equal((await noteKeys(prover, sk, change.rho, USDG, change.amount)).commitment, change.commitment);
  notes.push(out, change);
  await assertTreesMatch();
  assert.equal(await balance(NVDA, pool), out.amount);
});

test("unshield: the NVDA note in full, then part of the change through a relayer, then the rest", { timeout: 900_000 }, async () => {
  const [nvda, usdg] = notes.splice(0, 2) as [PrivateNote, PrivateNote];
  const deadline = (await client.getBlock()).timestamp + 3_600n;

  const s1 = await proveUnshield({ prover, sk, note: nvda, trees, chainId: CHAIN_ID, pool, fee: 0n, relayer: ZERO, deadline, v: nvda.amount, recipient: RECIPIENT });
  assert.equal(unshieldHash(CHAIN_ID, pool, ZERO, deadline, RECIPIENT), await poolRead("unshieldHash", [ZERO, deadline, RECIPIENT]));
  const r1 = await send(OTHER, unshieldCall(pool, s1, RECIPIENT), 20_000_000n);
  assert.equal(await balance(NVDA, RECIPIENT), nvda.amount);
  assert.equal(changeNote(s1, r1, pool), null);
  await assertTreesMatch();

  // The proof names its recipient: the SDK refuses another one, and so does the pool.
  const s2 = await proveUnshield({ prover, sk, note: usdg, trees, chainId: CHAIN_ID, pool, fee: parseUnits("0.5", 6), relayer: DEPLOYER.address, deadline, v: parseUnits("30", 6), recipient: RECIPIENT });
  assert.throws(() => unshieldCall(pool, s2, OTHER.address));
  const elsewhere = encodeFunctionData({ abi: ostraPrivatePoolAbi, functionName: "unshield", args: [s2.terms, OTHER.address, s2.proof] });
  await assert.rejects(client.call({ account: DEPLOYER.address, to: pool, data: elsewhere, gas: 30_000_000n }));
  const r2 = await send(DEPLOYER, unshieldCall(pool, s2, RECIPIENT), 20_000_000n);
  assert.equal(await balance(USDG, RECIPIENT), parseUnits("30", 6));
  const rest = changeNote(s2, r2, pool);
  assert.ok(rest);
  assert.equal(rest.amount, parseUnits("48.5", 6));
  await assertTreesMatch();

  const s3 = await proveUnshield({ prover, sk, note: rest, trees, chainId: CHAIN_ID, pool, fee: 0n, relayer: ZERO, deadline, v: rest.amount, recipient: RECIPIENT });
  await send(OTHER, unshieldCall(pool, s3, RECIPIENT), 20_000_000n);
  assert.equal(await balance(USDG, RECIPIENT), parseUnits("78.5", 6));
  // What is left in the pool is the other owner's note and the note shielded from an escrow.
  assert.equal(await balance(USDG, pool), parseUnits("8", 6));
  await assertTreesMatch();
});
