// Ostra Swap's token check (tokencheck.ts) on a fork of Robinhood Chain mainnet pinned at FORK_BLOCK (anvil,
// OSTRA_FORK_RPC or the public RPC; the block must be served, so an archive RPC), against the live OstraRouter
// (deployments/robinhood-mainnet.json) and real tokens, each verdict as that block's pools give it:
//   * $OSTRA, NVDA (a stock token) and a token whose only pool is a hookless native ETH / token pool of Uniswap v4
//     that held only the token before anyone bought (a sale quoted before the buy finds no liquidity: the check
//     quotes it after the buy, in the same pools) pass, bought and sold through OstraRouter escrow orders by a holder
//     with code, each step paid exactly its quote, nothing taken when it moved;
//   * a token whose pools that hold liquidity take 85.563% (native ETH) and 99.0099% (USDG) of every swap has no
//     route: its ETH pool quotes a buy, but hubPools leaves out a hookless v4 pool above MAX_HOOKLESS_V4_FEE;
//   * a token whose hookless ETH pool holds no liquidity in range, and a token whose pool trades thousands of times a
//     day but holds no liquidity between them (none quotes even 0.000001 ETH), have no route;
//   * two tokens whose native ETH pools (hookless, 0.3%) deliver 2% less than quoted on a buy, while a transfer and a
//     sale move whole, are refused as buy_tax;
//   * TokenChecks keeps a pass a minute and a refusal ten minutes, and runs two checks of one token at once once.
// The pool index is searched from the public RPC (its logs), as in production.

import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { after, before, test } from "node:test";
import { createPublicClient, http, zeroAddress, type Address, type PublicClient } from "viem";
import {
  CHECK_ETH,
  CHECK_OK_TTL_MS,
  CHECK_REFUSED_TTL_MS,
  ETH,
  bestLeg,
  CHECK_PROBE_BPS,
  MAX_HOOKLESS_V4_FEE,
  OSTRA,
  PoolIndex,
  ROBINHOOD_PUBLIC_RPC,
  TokenChecks,
  USDG,
  WETH,
  checkSwapToken,
  hubPools,
  parseSwapDeployment,
  type TokenVerdict,
} from "../src/index.ts";

/** The block the fork is pinned at (5 Nov 2026), where the verdicts below were read. */
const FORK_BLOCK = 106_774_787n;
const NVDA: Address = "0xd0601CE157Db5bdC3162BbaC2a2C8aF5320D9EEC";
/** Its one pool: native ETH / token, hookless, 1% fee, tick spacing 200. */
const ETH_POOL_TOKEN: Address = "0xf858011999Dfb3c82Dd7b11e65b1b73579b1F515";
/** Among its hookless pools: USDG / token at 990099 (99.0099%) and native ETH / token at 855630 (85.563%). */
const TRAP_FEE_TOKEN: Address = "0x85EA47E3B981279E237BdD5953e91E4e79ECB909";
/** A hookless native ETH / token pool, 1% fee, with no liquidity in range. */
const DRY_POOL_TOKEN: Address = "0x6f869d08cA7b5E5CE6ba330df04Cf0200160cf1E";
/** A hookless native ETH / token pool, fee 100, tick spacing 1, swapped thousands of times a day, no liquidity between swaps. */
const NO_STANDING_LIQUIDITY_TOKEN: Address = "0x5C1710197a9890FCa4D3BBaeD088fC053b1cbFb8";

/** Tokens that deliver 98% of a buy's quote (found among Robinhood Chain's most traded tokens on 5 Nov 2026). */
const BUY_TAX_TOKENS: Address[] = ["0x75d874378AE31b33Ab9e7a40B4dCA96134221111", "0x000050E18ffa3F8F7aD170Eb9CeF160eb3Ed1111"];

const PORT = 8_747;
const FORK_URL = `http://127.0.0.1:${PORT}`;

let anvil: ChildProcess;
let client: PublicClient;
const logsClient = createPublicClient({ transport: http(ROBINHOOD_PUBLIC_RPC, { retryCount: 6, retryDelay: 2_000 }) }) as PublicClient;
const index = new PoolIndex();
const router = parseSwapDeployment(JSON.parse(readFileSync(new URL("../../deployments/robinhood-mainnet.json", import.meta.url), "utf8"))).router;

before(async () => {
  const fork = process.env.OSTRA_FORK_RPC || ROBINHOOD_PUBLIC_RPC;
  anvil = spawn("anvil", ["--fork-url", fork, "--fork-block-number", FORK_BLOCK.toString(), "--port", String(PORT), "--base-fee", "0", "--gas-price", "0"], { stdio: ["ignore", "ignore", "pipe"] });
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
  // anvil fetches every slot a call touches from the chain the first time: a check can take tens of seconds there.
  client = createPublicClient({ transport: http(FORK_URL, { retryCount: 3, retryDelay: 1_000, timeout: 300_000 }) }) as PublicClient;
  assert.equal(await client.getBlockNumber(), FORK_BLOCK);
});

after(() => {
  anvil?.kill();
});

const check = (token: Address) => checkSwapToken({ client, logsClient, index, router, token });

/** A verdict that passed: each step exactly its quote, the move whole, the sale of what was left. */
function passedExactly(v: TokenVerdict): void {
  assert.equal(v.kind, "ok", `${v.token}: ${v.reason}`);
  assert.equal(v.ok, true);
  assert.equal(v.reason, null);
  const f = v.figures;
  assert.ok(BigInt(f.buyQuoted as string) > 0n);
  assert.equal(f.buyHeld, f.buyQuoted, "the buy delivered its quote exactly");
  assert.equal(BigInt(f.moveSent as string), (BigInt(f.buyHeld as string) * CHECK_PROBE_BPS) / 10_000n);
  assert.equal(f.moveArrived, f.moveSent);
  assert.equal(f.moveLeft, f.moveSent);
  assert.equal(BigInt(f.sellAmount as string), BigInt(f.buyHeld as string) - BigInt(f.moveSent as string));
  assert.equal(f.sellArrived, f.sellAmount, "the sale's Transfer to its escrow moved whole");
  assert.ok(BigInt(f.sellQuoted as string) > 0n);
  assert.equal(f.sellWeth, f.sellQuoted, "the sale paid its quote exactly");
}

test("$OSTRA, NVDA and a token of a one-sided hookless ETH pool pass, each step exactly its quote", { timeout: 1_800_000 }, async () => {
  const ostra = await check(OSTRA);
  passedExactly(ostra);
  // Which hub NVDA's route takes is the market's at the block.
  passedExactly(await check(NVDA));
  const meme = await check(ETH_POOL_TOKEN);
  passedExactly(meme);
  assert.equal(meme.figures.hub, WETH);
  // USDG, WETH and native ETH need no check.
  for (const t of [USDG, WETH, ETH]) assert.equal((await check(t)).kind, "ok");
});

test("pools above the fee cap are left out; dry pools give no route", { timeout: 1_800_000 }, async () => {
  const ethPools = await index.v4PoolsOfPair(logsClient, TRAP_FEE_TOKEN, ETH);
  const usdgPools = await index.v4PoolsOfPair(logsClient, TRAP_FEE_TOKEN, USDG);
  assert.ok(usdgPools.some((p) => p.key.fee === 990_099), "the trap token's USDG pool is found");
  const trap = ethPools.find((p) => p.key.fee === 855_630);
  assert.ok(trap !== undefined, "the trap token's ETH pool is found");
  assert.ok(trap.key.fee > MAX_HOOKLESS_V4_FEE && trap.key.hooks === zeroAddress);
  // The pool holds liquidity: it quotes a buy.
  const leg = await bestLeg(client, [{ kind: "v4", id: trap.id, key: trap.key }], WETH, TRAP_FEE_TOKEN, CHECK_ETH);
  assert.ok(leg !== null, "the 85.563% pool quotes a buy");
  for (const hub of [USDG, WETH]) assert.deepEqual(await hubPools(client, logsClient, index, TRAP_FEE_TOKEN, hub), [], "no pool of it is routed");
  for (const t of [TRAP_FEE_TOKEN, DRY_POOL_TOKEN, NO_STANDING_LIQUIDITY_TOKEN]) {
    const v = await check(t);
    assert.equal(v.kind, "no_route", `${t}: ${v.kind}`);
    assert.equal(v.ok, false);
    assert.match(v.reason as string, /no Uniswap v3 or v4 pool/);
  }
});

test("tokens that take 2% when bought are refused as buy_tax; what they do after the buy is measured all the same", { timeout: 1_800_000 }, async () => {
  for (const t of BUY_TAX_TOKENS) {
    const v = await check(t);
    assert.equal(v.kind, "buy_tax", `${t}: ${v.kind} ${v.reason}`);
    assert.equal(v.ok, false);
    assert.match(v.reason as string, /takes a cut when bought/);
    const f = v.figures;
    const held = BigInt(f.buyHeld as string);
    const quoted = BigInt(f.buyQuoted as string);
    // 98% of the quote, within a basis point.
    assert.ok(held * 10_000n >= quoted * 9_799n && held * 10_000n <= quoted * 9_801n, `${t}: ${held} of ${quoted}`);
    assert.equal(f.moveArrived, f.moveSent);
    assert.equal(f.sellArrived, f.sellAmount);
    assert.equal(f.sellWeth, f.sellQuoted);
  }
});

test("TokenChecks keeps a pass a minute and a refusal ten minutes, and runs two checks of one token at once once", { timeout: 1_800_000 }, async () => {
  let now = 1_000_000;
  const checks = new TokenChecks({ client, logsClient, index, router, now: () => now });
  const [a, b] = await Promise.all([checks.check(OSTRA), checks.check(OSTRA.toLowerCase() as Address)]);
  assert.equal(a, b, "two checks at once: one verdict");
  assert.equal(a.kind, "ok");
  const refused = await checks.check(TRAP_FEE_TOKEN);
  assert.equal(refused.kind, "no_route");
  now += CHECK_OK_TTL_MS - 1;
  assert.equal(await checks.check(OSTRA), a, "a pass kept within its minute");
  now += 2;
  const c = await checks.check(OSTRA);
  assert.notEqual(c, a, "checked again after its minute");
  assert.equal(c.kind, "ok");
  assert.equal(c.figures.buyQuoted, a.figures.buyQuoted, "the same block, the same quote");
  assert.equal(await checks.check(TRAP_FEE_TOKEN), refused, "a refusal kept longer");
  now = refused.at + CHECK_REFUSED_TTL_MS;
  assert.notEqual(await checks.check(TRAP_FEE_TOKEN), refused, "checked again after its ten minutes");
});
