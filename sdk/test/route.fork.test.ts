// Routes found by the SDK, run on a fork of Robinhood Chain mainnet (anvil, OSTRA_FORK_RPC or the public RPC):
// the three contracts are deployed from the Foundry build, and every route the SDK picks is sent through
// OstraRouter and must pay exactly what it quoted (same state, no other transaction in between). Pools are found
// with the public RPC's logs, as in production. Needs `forge build` first and anvil on PATH.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { createPublicClient, createWalletClient, encodeFunctionData, getAddress, http, parseEther, parseUnits, type Address, type Hex, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  ETH,
  OSTRA,
  OSTRA_PONS_CURVE,
  PONS_HOOK,
  PoolIndex,
  ROBINHOOD_PUBLIC_RPC,
  TREASURY,
  UNIVERSAL_ROUTER,
  USDG,
  WETH,
  erc20Abi,
  escrowAddress,
  executeEscrowData,
  findRoute,
  NO_LEG,
  announceData,
  closeEscrowData,
  orderFor,
  orderHash,
  ostraRouterAbi,
  ostraStakeAbi,
  randomSalt,
  standingOrderFor,
  trancheTerms,
  walletSwapCall,
  type Route,
  type SwapDeployment,
} from "../src/index.ts";

const NVDA: Address = "0xd0601CE157Db5bdC3162BbaC2a2C8aF5320D9EEC";
const TSLA: Address = "0x322F0929c4625eD5bAd873c95208D54E1c003b2d";
/** The first token the Ostra launchpad launched (paired with USDG). */
const OSTRA_LAUNCHED: Address = "0x8f11Ce6A5c28c2064f69540C7C8471127683d3aA";

const PORT = 8_745;
const FORK_URL = `http://127.0.0.1:${PORT}`;
/** anvil's first default account. */
const DEPLOYER = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const TRADER = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a7c43dea1e1be8b3e3a");

let anvil: ChildProcess;
let client: PublicClient;
const logsClient = createPublicClient({ transport: http(ROBINHOOD_PUBLIC_RPC, { retryCount: 6, retryDelay: 2_000 }) }) as PublicClient;
const wallet = (account: typeof DEPLOYER) => createWalletClient({ account, transport: http(FORK_URL) });
const index = new PoolIndex();
let d: SwapDeployment;

function artifact(file: string, name: string): { abi: unknown[]; bytecode: Hex } {
  const a = JSON.parse(readFileSync(new URL(`../../out/${file}/${name}.json`, import.meta.url), "utf8")) as { abi: unknown[]; bytecode: { object: Hex } };
  return { abi: a.abi, bytecode: a.bytecode.object };
}

async function deploy(file: string, name: string, args: unknown[]): Promise<Address> {
  const a = artifact(file, name);
  const hash = await wallet(DEPLOYER).deployContract({ abi: a.abi, bytecode: a.bytecode, args, chain: null });
  const r = await client.waitForTransactionReceipt({ hash });
  assert.equal(r.status, "success");
  assert.ok(r.contractAddress);
  console.log(`deployed ${name}: ${r.gasUsed} gas`);
  return getAddress(r.contractAddress);
}

async function send(account: typeof DEPLOYER, to: Address, data: Hex, value = 0n): Promise<void> {
  const hash = await wallet(account).sendTransaction({ to, data, value, chain: null, gas: 3_000_000n });
  const r = await client.waitForTransactionReceipt({ hash });
  assert.equal(r.status, "success", `transaction to ${to} reverted`);
}

const balance = (token: Address, who: Address) => client.readContract({ address: token, abi: erc20Abi, functionName: "balanceOf", args: [who] }) as Promise<bigint>;

async function approve(token: Address, amount: bigint): Promise<void> {
  await send(TRADER, token, encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [d.router, amount] }));
}

/** Finds the route for the trader (its fee from OstraStake) and runs it; asserts the quote was paid exactly. */
async function swap(tokenIn: Address, tokenOut: Address, amountIn: bigint): Promise<Route> {
  const feeBps = Number(await client.readContract({ address: d.stake, abi: ostraStakeAbi, functionName: "feeBps", args: [TRADER.address] }));
  const route = await findRoute({ client, logsClient, index, tokenIn, tokenOut, amountIn, feeBps, slippageBps: 0 });
  if (tokenIn !== ETH) await approve(tokenIn, amountIn);
  const before = tokenOut === ETH ? await client.getBalance({ address: TRADER.address }) : await balance(tokenOut, TRADER.address);
  const call = walletSwapCall(d.router, route, TRADER.address);
  const hash = await wallet(TRADER).sendTransaction({ ...call, chain: null, gas: 3_000_000n, gasPrice: 0n });
  const r = await client.waitForTransactionReceipt({ hash });
  assert.equal(r.status, "success", `swap ${tokenIn} -> ${tokenOut} reverted`);
  const afterBal = tokenOut === ETH ? await client.getBalance({ address: TRADER.address }) : await balance(tokenOut, TRADER.address);
  assert.equal(afterBal - before, route.expectedOut, `swap ${tokenIn} -> ${tokenOut} paid what it quoted`);
  return route;
}

before(async () => {
  const fork = process.env.OSTRA_FORK_RPC || ROBINHOOD_PUBLIC_RPC;
  anvil = spawn("anvil", ["--fork-url", fork, "--port", String(PORT), "--base-fee", "0", "--gas-price", "0"], { stdio: ["ignore", "ignore", "pipe"] });
  let anvilErr = "";
  anvil.stderr?.on("data", (b: Buffer) => {
    anvilErr = (anvilErr + b.toString()).slice(-2_000);
  });
  // Wait for anvil with single, short requests (no retries), and stop at once if it exited.
  const probe = createPublicClient({ transport: http(FORK_URL, { retryCount: 0, timeout: 2_000 }) }) as PublicClient;
  for (let i = 0; ; i++) {
    if (anvil.exitCode !== null) throw new Error(`anvil exited (${anvil.exitCode}): ${anvilErr.replace(/https?:\/\/\S+/g, "<url>")}`);
    try {
      if ((await probe.getChainId()) === 4663) break;
    } catch {}
    if (i > 120) throw new Error("anvil did not answer within 2 minutes");
    await new Promise((r) => setTimeout(r, 1_000));
  }
  // anvil fetches every slot a call touches from the chain the first time: a route's first quotes can take tens of
  // seconds there (measured: up to 24 s), far longer than viem's default 10 s request timeout.
  client = createPublicClient({ transport: http(FORK_URL, { retryCount: 3, retryDelay: 1_000, timeout: 180_000 }) }) as PublicClient;
  await client.request({ method: "anvil_setBalance" as never, params: [TRADER.address, "0x56BC75E2D63100000"] as never });
  await client.request({ method: "anvil_setBalance" as never, params: [DEPLOYER.address, "0x56BC75E2D63100000"] as never });
  const stake = await deploy("OstraStake.sol", "OstraStake", [OSTRA]);
  const buyback = await deploy("OstraBuyback.sol", "OstraBuyback", [OSTRA, USDG, WETH, UNIVERSAL_ROUTER, OSTRA_PONS_CURVE, PONS_HOOK, DEPLOYER.address, DEPLOYER.address]);
  const router = await deploy("OstraRouter.sol", "OstraRouter", [UNIVERSAL_ROUTER, USDG, WETH, stake, buyback, TREASURY]);
  d = { chainId: 4663, fromBlock: (await client.getBlockNumber()).toString(), router, stake, buyback };
});

after(() => {
  anvil?.kill();
});

test("ETH to USDG, USDG to NVDA (v3), NVDA to TSLA (v3 then v4), TSLA to ETH: each pays its quote", { timeout: 900_000 }, async () => {
  const r1 = await swap(ETH, USDG, parseEther("1"));
  assert.equal(r1.hub, WETH);
  assert.equal(r1.legIn, null);
  const usdg = await balance(USDG, TRADER.address);
  assert.ok(usdg > parseUnits("100", 6));

  const r2 = await swap(USDG, NVDA, parseUnits("500", 6));
  assert.equal(r2.hub, USDG);
  assert.equal(r2.legOut?.pool.kind, "v3");

  const nvda = await balance(NVDA, TRADER.address);
  const r3 = await swap(NVDA, TSLA, nvda);
  assert.equal(r3.fee, (r3.hubAmount * 20n) / 10_000n);

  const tsla = await balance(TSLA, TRADER.address);
  await swap(TSLA, ETH, tsla);
  assert.equal(await balance(TSLA, TRADER.address), 0n);
});

test("a large order: the deepest pool is quoted with more gas, and a pool that would run dry is never picked", { timeout: 600_000 }, async () => {
  // Independent review, 20 Oct 2026: 1,000,000 USDG to NVDA needs 1,357,854 gas to quote on the 0.05% v3 pool, and
  // the 1% pool runs dry (it would swap only part of the input).
  const route = await findRoute({ client, logsClient, index, tokenIn: USDG, tokenOut: NVDA, amountIn: parseUnits("1000000", 6), feeBps: 20, slippageBps: 50 });
  assert.equal(route.legOut?.pool.kind, "v3");
  assert.notEqual(route.legOut?.pool.kind === "v3" ? route.legOut.pool.fee : 0, 10_000);
});

test("a token the Ostra launchpad launched: bought and sold through its Ostra hook pool", { timeout: 600_000 }, async () => {
  await swap(ETH, USDG, parseEther("0.05"));
  const r = await swap(USDG, OSTRA_LAUNCHED, parseUnits("20", 6));
  assert.equal(r.legOut?.pool.kind, "v4");
  const got = await balance(OSTRA_LAUNCHED, TRADER.address);
  await swap(OSTRA_LAUNCHED, USDG, got);
});

test("an escrow order: the SDK's escrow address is the router's, and executeEscrow pays the route's quote", { timeout: 600_000 }, async () => {
  await swap(ETH, USDG, parseEther("0.2"));
  const amountIn = parseUnits("100", 6);
  const feeBps = 20;
  const route = await findRoute({ client, logsClient, index, tokenIn: USDG, tokenOut: NVDA, amountIn, feeBps, slippageBps: 50 });
  const recipient = getAddress("0x00000000000000000000000000000000000B0B0B");
  const now = (await client.getBlock()).timestamp;
  // The trader stands in for a USDG vault: its Transfer to the escrow is what a vault's Transfer spend does. The
  // recipient holds no lock: the fee is 20 bps.
  const order = orderFor(route, TRADER.address, USDG, recipient, now, randomSalt());
  assert.throws(() => orderFor(route, TRADER.address, NVDA, recipient, now, randomSalt()));
  assert.equal(order.route, await client.readContract({ address: d.router, abi: ostraRouterAbi, functionName: "routeHash", args: [route.hub, route.legIn?.leg ?? NO_LEG, route.legOut?.leg ?? NO_LEG] }));
  const escrow = escrowAddress(d.router, order);
  assert.equal(escrow, getAddress((await client.readContract({ address: d.router, abi: ostraRouterAbi, functionName: "escrowAddress", args: [order] })) as Address));
  assert.equal(orderHash(order), await client.readContract({ address: d.router, abi: ostraRouterAbi, functionName: "orderHash", args: [order] }));
  await send(TRADER, USDG, encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [escrow, amountIn] }));
  await send(DEPLOYER, d.router, executeEscrowData(order, route));
  assert.equal(await balance(NVDA, recipient), route.expectedOut);
  assert.equal(await balance(USDG, escrow), 0n);
});

test("a standing order: the vault's Transfer places it, its executor runs a tranche, its canceller returns the rest", { timeout: 600_000 }, async () => {
  await swap(ETH, USDG, parseEther("0.2"));
  const amountIn = parseUnits("100", 6);
  const route = await findRoute({ client, logsClient, index, tokenIn: USDG, tokenOut: NVDA, amountIn, feeBps: 20, slippageBps: 50 });
  const recipient = getAddress("0x0000000000000000000000000000000000C0C0C0");
  const now = (await client.getBlock()).timestamp;
  // The trader stands in for a USDG vault (refundTo) and holds the canceller key; the deployer is the executor.
  const order = standingOrderFor({
    tokenIn: USDG,
    tokenOut: NVDA,
    amountIn,
    minOut: route.minOut,
    vault: TRADER.address,
    vaultToken: USDG,
    recipient,
    now,
    notBefore: now,
    deadline: now + 3_600n,
    tranches: 2,
    intervalSeconds: 600,
    executor: DEPLOYER.address,
    canceller: TRADER.address,
    route,
    salt: randomSalt(),
  });
  assert.throws(() => standingOrderFor({ ...termsOf(order, route, now), canceller: "0x0000000000000000000000000000000000000000" }));
  assert.throws(() => standingOrderFor({ ...termsOf(order, route, now), minOut: 0n }));
  assert.throws(() => standingOrderFor({ ...termsOf(order, route, now), deadline: now }));
  assert.deepEqual(standingOrderFor(termsOf(order, route, now)), order);
  const escrow = escrowAddress(d.router, order);
  assert.equal(escrow, getAddress((await client.readContract({ address: d.router, abi: ostraRouterAbi, functionName: "escrowAddress", args: [order] })) as Address));
  assert.equal(orderHash(order), await client.readContract({ address: d.router, abi: ostraRouterAbi, functionName: "orderHash", args: [order] }));

  const before = await balance(USDG, TRADER.address);
  await send(TRADER, USDG, encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [escrow, amountIn] }));
  await send(DEPLOYER, d.router, announceData(order));
  const t0 = trancheTerms(order, 0);
  assert.equal(t0.amountIn, amountIn / 2n);
  await send(DEPLOYER, d.router, executeEscrowData(order, route));
  assert.ok((await balance(NVDA, recipient)) >= t0.minOut);
  assert.equal(await balance(USDG, escrow), amountIn - t0.amountIn);
  assert.equal(await client.readContract({ address: d.router, abi: ostraRouterAbi, functionName: "tranchesDone", args: [orderHash(order)] }), 1);

  await send(TRADER, d.router, closeEscrowData(order));
  assert.equal(await balance(USDG, escrow), 0n);
  assert.equal(await balance(USDG, TRADER.address), before - t0.amountIn);
  assert.equal(await client.readContract({ address: d.router, abi: ostraRouterAbi, functionName: "closed", args: [orderHash(order)] }), true);
});

/** The terms an order was made from, for building variants of it. */
function termsOf(order: ReturnType<typeof standingOrderFor>, route: Route, now: bigint) {
  return {
    now,
    tokenIn: order.tokenIn,
    tokenOut: order.tokenOut,
    amountIn: order.amountIn,
    minOut: order.minOut,
    vault: order.refundTo,
    vaultToken: order.tokenIn,
    recipient: order.recipient,
    notBefore: order.notBefore,
    deadline: order.deadline,
    tranches: order.tranches,
    intervalSeconds: order.interval,
    executor: order.executor,
    canceller: order.canceller,
    route,
    salt: order.salt,
  };
}
