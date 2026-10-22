// The deploy script (scripts/deploy.ts) on a fork of Robinhood Chain mainnet (anvil, OSTRA_FORK_RPC or the public
// RPC), at the chain's own gas price: the five contracts are deployed from the Foundry build by Ostra's deployer
// account (impersonated: its key never leaves the VPS), within the gas budget; a deployment stopped midway goes on from
// what its progress kept; the record's check accepts them and refuses a record that names the wrong contract, and a
// record missing a field is refused by name. Needs `forge build` first and anvil on PATH.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, getAddress, http, type PublicClient } from "viem";
import { ROBINHOOD_PUBLIC_RPC, TREASURY, parseSwapDeployment, type SwapDeployment } from "../src/index.ts";
import { DEPLOY_GAS_BUDGET, checkSwapDeployment, deploySwap, parseDeployProgress, type DeployProgress } from "../scripts/deploy.ts";

const PORT = 8_744;
const FORK_URL = `http://127.0.0.1:${PORT}`;
const OUT_DIR = fileURLToPath(new URL("../../out", import.meta.url));
const OTHER = getAddress("0x00000000000000000000000000000000000D0D0D");

let anvil: ChildProcess;
let client: PublicClient;
let d: SwapDeployment;

before(async () => {
  const fork = process.env.OSTRA_FORK_RPC || ROBINHOOD_PUBLIC_RPC;
  anvil = spawn("anvil", ["--fork-url", fork, "--port", String(PORT), "--auto-impersonate"], { stdio: ["ignore", "ignore", "pipe"] });
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
  client = createPublicClient({ transport: http(FORK_URL, { retryCount: 3, retryDelay: 1_000, timeout: 180_000 }) }) as PublicClient;
  assert.ok((await client.getGasPrice()) > 0n, "the fork keeps the chain's gas price");
  await client.request({ method: "anvil_setBalance" as never, params: [TREASURY, "0x56BC75E2D63100000"] as never });
});

after(() => {
  anvil?.kill();
});

test("the five contracts are deployed by Ostra's deployer within the gas budget, and the record checks", { timeout: 300_000 }, async () => {
  const wallet = createWalletClient({ account: TREASURY, transport: http(FORK_URL) });
  const lines: Record<string, unknown>[] = [];
  const r = await deploySwap(client, wallet, OUT_DIR, { log: (event, fields = {}) => lines.push({ event, ...fields }) });
  d = r.deployment;
  for (const l of lines) console.log(`deployed ${String(l.contract)}: ${String(l.gasUsed)} gas`);
  console.log(`deploy gas ${r.gasUsed} of ${DEPLOY_GAS_BUDGET}`);
  assert.deepEqual(lines.map((l) => l.contract), ["OstraStake", "OstraBuyback", "OstraRouter", "SpendVerifier", "OstraPrivatePool"]);
  assert.ok(r.gasUsed <= DEPLOY_GAS_BUDGET, `${r.gasUsed} gas is over the budget ${DEPLOY_GAS_BUDGET}`);
  assert.equal(d.chainId, 4663);
  // Read back from its JSON, as the relayer and the agents read it.
  await checkSwapDeployment(client, parseSwapDeployment(JSON.parse(JSON.stringify(d))), TREASURY, OUT_DIR);
});

test("a deployment stopped after the router goes on from its progress: only the verifier and the pool are deployed", { timeout: 300_000 }, async () => {
  const wallet = createWalletClient({ account: TREASURY, transport: http(FORK_URL) });
  let kept: DeployProgress = {};
  await assert.rejects(
    deploySwap(client, wallet, OUT_DIR, {
      save: (p) => {
        kept = p;
        if (p.OstraRouter?.block !== undefined) throw new Error("stopped");
      },
    }),
    /stopped/,
  );
  assert.deepEqual(Object.keys(kept), ["OstraStake", "OstraBuyback", "OstraRouter"]);
  const events: string[] = [];
  // The progress as it was while the verifier's transaction was out: its address and hash, no block yet.
  let inFlight: DeployProgress | null = null;
  const r = await deploySwap(client, wallet, OUT_DIR, {
    done: parseDeployProgress(JSON.parse(JSON.stringify(kept))),
    log: (event, f = {}) => events.push(`${event} ${String(f.contract)}`),
    save: (p) => {
      if (p.SpendVerifier?.tx !== undefined && p.SpendVerifier.block === undefined) inFlight = p;
    },
  });
  assert.deepEqual(events, ["kept OstraStake", "kept OstraBuyback", "kept OstraRouter", "deployed SpendVerifier", "deployed OstraPrivatePool"]);
  assert.equal(r.deployment.router, kept.OstraRouter?.address);
  assert.equal(r.deployment.fromBlock, kept.OstraStake?.block);
  await checkSwapDeployment(client, r.deployment, TREASURY, OUT_DIR);
  // A progress naming a landed contract with no code is refused, not deployed around.
  await assert.rejects(deploySwap(client, wallet, OUT_DIR, { done: { OstraStake: { address: OTHER, block: "1" } } }), /no code/);
  // A kept verifier that is not this build's code is refused before any record is written.
  await assert.rejects(deploySwap(client, wallet, OUT_DIR, { done: { ...kept, SpendVerifier: { address: r.deployment.router, block: "1" } } }), /not this build's code/);
  // A run that stopped while the verifier's transaction was out goes on from its kept address and transaction.
  assert.ok(inFlight !== null);
  const resumed: string[] = [];
  const again = await deploySwap(client, wallet, OUT_DIR, { done: inFlight, log: (event, f = {}) => resumed.push(`${event} ${String(f.contract)}`) });
  assert.deepEqual(resumed.slice(0, 4), ["kept OstraStake", "kept OstraBuyback", "kept OstraRouter", "kept SpendVerifier"]);
  assert.equal(again.deployment.spendVerifier, r.deployment.spendVerifier);
  await checkSwapDeployment(client, again.deployment, TREASURY, OUT_DIR);
  assert.throws(() => parseDeployProgress({ OstraRouter: { address: "nope" } }), /no address for OstraRouter/);
  assert.throws(() => parseDeployProgress({ Other: { address: OTHER } }), /unknown contract Other/);
});

test("a record missing a field is refused by name", () => {
  for (const field of ["chainId", "fromBlock", "router", "stake", "buyback", "spendVerifier", "privatePool"] as const) {
    const { [field]: _, ...rest } = d;
    assert.throws(() => parseSwapDeployment(rest), new RegExp(`no ${field}`), field);
  }
  assert.throws(() => parseSwapDeployment({ ...d, privatePool: "nope" }), /no privatePool address/);
});

test("a record naming the wrong contract or owner is refused", { timeout: 300_000 }, async () => {
  const refused = (record: SwapDeployment, owner: typeof TREASURY, why: RegExp) => assert.rejects(checkSwapDeployment(client, record, owner, OUT_DIR), why);
  await refused({ ...d, privatePool: OTHER }, TREASURY, /no code at the privatePool/);
  await refused({ ...d, privatePool: d.router }, TREASURY, /OstraPrivatePool|reverted|returned no data/i);
  await refused({ ...d, spendVerifier: d.router }, TREASURY, /SpendVerifier code hash/);
  await refused({ ...d, router: d.privatePool }, TREASURY, /OstraRouter|reverted|returned no data/i);
  await refused(d, OTHER, /OstraBuyback.owner/);
});
