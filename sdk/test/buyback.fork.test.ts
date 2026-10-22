// scripts/buyback.ts after OSTRA graduated (22 Oct 2026), on a fork of mainnet with the live contracts: Ostra's
// deployer (impersonated) as OstraBuyback's keeper and OstraDispatcher's owner claims the launchpad's buyback part to
// OstraBuyback, keeps what is under the dust limits for later, and buys OSTRA with OstraBuyback's WETH in the pool Pons
// graduated OSTRA to (burnOnRouter), sending all of it to the burn address.
// Needs anvil on PATH (OSTRA_FORK_RPC or the public RPC).

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { createPublicClient, createWalletClient, encodeFunctionData, getAddress, http, parseAbi, parseEther, type Address, type Hex, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { runBuyback, MIN_USDG } from "../scripts/buyback.ts";
import { BURN_ADDRESS, OSTRA, OSTRA_PONS_CURVE, PONS_HOOK, ROBINHOOD_PUBLIC_RPC, TREASURY, UNISWAP_V4_QUOTER, USDG, WETH, erc20Abi, ostraBuybackAbi, type SwapDeployment } from "../src/index.ts";

const PORT = 8_747;
const FORK_URL = `http://127.0.0.1:${PORT}`;
/** A trader the test funds on the fork. */
const TRADER = privateKeyToAccount("0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a7c43dea1e1be8b3e3a");
const WETH_IN = parseEther("0.01");

const swapRecord = JSON.parse(readFileSync(new URL("../../deployments/robinhood-mainnet.json", import.meta.url), "utf8")) as SwapDeployment;
const BUYBACK = getAddress(swapRecord.buyback);
/** The Ostra deployment record, from the ostra-robinhood checkout next to this repository (as on the VPS); without it the test is skipped. */
const OSTRA_RECORD_FILE = new URL("../../../ostra-robinhood/deployments/robinhood-mainnet.json", import.meta.url);
const OSTRA_RECORD = existsSync(OSTRA_RECORD_FILE)
  ? (JSON.parse(readFileSync(OSTRA_RECORD_FILE, "utf8")) as { fromBlock: string; launchpad: { launchpad: Address; dispatcher: Address } })
  : null;

const dispatcherAbi = parseAbi(["function buybackOwed(address currency) view returns (uint256)", "function owner() view returns (address)"]);
const curveAbi = parseAbi(["function graduated() view returns (bool)"]);
const wethAbi = parseAbi(["function deposit() payable", "function transfer(address to, uint256 amount) returns (bool)"]);
const quoterAbi = [
  {
    type: "function",
    name: "quoteExactInputSingle",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "params",
        type: "tuple",
        components: [
          { name: "poolKey", type: "tuple", components: [{ name: "currency0", type: "address" }, { name: "currency1", type: "address" }, { name: "fee", type: "uint24" }, { name: "tickSpacing", type: "int24" }, { name: "hooks", type: "address" }] },
          { name: "zeroForOne", type: "bool" },
          { name: "exactAmount", type: "uint128" },
          { name: "hookData", type: "bytes" },
        ],
      },
    ],
    outputs: [{ name: "amountOut", type: "uint256" }, { name: "gasEstimate", type: "uint256" }],
  },
] as const;

let anvil: ChildProcess;
let client: PublicClient;
const logsClient = createPublicClient({ transport: http(ROBINHOOD_PUBLIC_RPC, { retryCount: 6, retryDelay: 2_000 }) }) as PublicClient;
const balance = (token: Address, who: Address) => client.readContract({ address: token, abi: erc20Abi, functionName: "balanceOf", args: [who] }) as Promise<bigint>;
const rpc = (method: string, params: unknown[]) => client.request({ method: method as never, params: params as never });

async function send(to: Address, data: Hex, value = 0n): Promise<void> {
  const hash = await createWalletClient({ account: TRADER, transport: http(FORK_URL) }).sendTransaction({ to, data, value, chain: null, gas: 1_000_000n });
  assert.equal((await client.waitForTransactionReceipt({ hash })).status, "success");
}

before(async () => {
  if (OSTRA_RECORD === null) return;
  const fork = process.env.OSTRA_FORK_RPC || ROBINHOOD_PUBLIC_RPC;
  anvil = spawn("anvil", ["--fork-url", fork, "--port", String(PORT), "--base-fee", "0", "--gas-price", "0"], { stdio: ["ignore", "ignore", "pipe"] });
  let anvilErr = "";
  anvil.stderr?.on("data", (b: Buffer) => {
    anvilErr = (anvilErr + b.toString()).slice(-2_000);
  });
  const probe = createPublicClient({ transport: http(FORK_URL, { retryCount: 0, timeout: 2_000 }) }) as PublicClient;
  for (let i = 0; ; i++) {
    if (anvil.exitCode !== null) throw new Error(`anvil exited (${anvil.exitCode}): ${anvilErr.replace(/https?:\/\/\S+/g, "<url>")}`);
    try {
      if ((await probe.getChainId()) === 4663) break;
    } catch {}
    if (i > 120) throw new Error("anvil did not answer within 2 minutes");
    await new Promise((r) => setTimeout(r, 1_000));
  }
  client = createPublicClient({ transport: http(FORK_URL, { timeout: 120_000 }) }) as PublicClient;
});

after(() => {
  anvil?.kill();
});

test("after graduation: the launchpad's part is claimed to OstraBuyback, dust waits, and the WETH buys OSTRA in its v4 pool and burns it", { timeout: 900_000, skip: OSTRA_RECORD === null ? "no ostra-robinhood checkout next to this repository" : false }, async () => {
  if (OSTRA_RECORD === null) return;
  assert.equal(await client.readContract({ address: OSTRA_PONS_CURVE, abi: curveAbi, functionName: "graduated" }), true, "OSTRA has graduated");
  assert.equal(getAddress(await client.readContract({ address: OSTRA_RECORD.launchpad.dispatcher, abi: dispatcherAbi, functionName: "owner" })), getAddress(TREASURY));
  assert.equal(getAddress((await client.readContract({ address: BUYBACK, abi: ostraBuybackAbi, functionName: "keeper" })) as Address), getAddress(TREASURY));

  // OstraBuyback gets 0.01 WETH, as from Ostra Swap's fees.
  await rpc("anvil_setBalance", [TRADER.address, "0xde0b6b3a7640000"]);
  await send(WETH, encodeFunctionData({ abi: wethAbi, functionName: "deposit" }), WETH_IN);
  await send(WETH, encodeFunctionData({ abi: wethAbi, functionName: "transfer", args: [BUYBACK, WETH_IN] }));

  const owedUsdg = await client.readContract({ address: OSTRA_RECORD.launchpad.dispatcher, abi: dispatcherAbi, functionName: "buybackOwed", args: [USDG] });
  const usdgBefore = await balance(USDG, BUYBACK);
  const wethBefore = await balance(WETH, BUYBACK);
  const deadBefore = await balance(OSTRA, BURN_ADDRESS);
  const { result: quoted } = await client.simulateContract({
    address: UNISWAP_V4_QUOTER,
    abi: quoterAbi,
    functionName: "quoteExactInputSingle",
    args: [{ poolKey: { currency0: "0x0000000000000000000000000000000000000000", currency1: OSTRA, fee: 0, tickSpacing: 200, hooks: PONS_HOOK }, zeroForOne: true, exactAmount: wethBefore, hookData: "0x" }],
  });

  await rpc("anvil_impersonateAccount", [TREASURY]);
  await rpc("anvil_setBalance", [TREASURY, "0xde0b6b3a7640000"]);
  const events: { event: string; fields: Record<string, unknown> }[] = [];
  const wallet = createWalletClient({ account: getAddress(TREASURY), transport: http(FORK_URL) });
  await runBuyback({ client, logsClient, wallet, buyback: BUYBACK, ostra: OSTRA_RECORD, log: (event, fields = {}) => events.push({ event, fields }) });
  for (const e of events) console.log(JSON.stringify(e, (_, v) => (typeof v === "bigint" ? v.toString() : v)));

  // 1. The launchpad's USDG part is OstraBuyback's now; together with what it held it is under 1 USDG, so it waits.
  assert.equal(await client.readContract({ address: OSTRA_RECORD.launchpad.dispatcher, abi: dispatcherAbi, functionName: "buybackOwed", args: [USDG] }), 0n);
  assert.equal(await balance(USDG, BUYBACK), usdgBefore + owedUsdg);
  if (usdgBefore + owedUsdg < MIN_USDG) assert.ok(!events.some((e) => e.event === "sent" && String(e.fields.what).startsWith("toWeth")), "USDG under 1 is not traded");
  // 2. The curve takes no buy: the WETH bought OSTRA in the v4 pool, all of it sent to the burn address.
  const burn = events.find((e) => e.event === "sent" && String(e.fields.what).startsWith("burnOnRouter"));
  assert.ok(burn !== undefined, "burnOnRouter was sent");
  assert.ok(!events.some((e) => String(e.fields.what ?? "").startsWith("burnOnCurve")), "nothing was tried on the graduated curve");
  assert.equal(await balance(WETH, BUYBACK), 0n);
  assert.equal(await balance(OSTRA, BUYBACK), 0n);
  const burned = (await balance(OSTRA, BURN_ADDRESS)) - deadBefore;
  // With 1 USDG or more waiting, the run also turned it into WETH before the burn: more was bought than quoted.
  if (usdgBefore + owedUsdg < MIN_USDG) assert.equal(burned, quoted[0], "the OSTRA burned is what the V4Quoter quoted for the WETH");
  else assert.ok(burned > quoted[0], "the OSTRA burned is at least what the WETH alone buys");
  console.log(`burned ${burned} OSTRA for ${wethBefore} wei of WETH`);
});
