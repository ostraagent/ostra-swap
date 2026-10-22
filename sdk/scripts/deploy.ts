// Deploys Ostra Swap to Robinhood Chain from the Foundry build (out/): OstraStake, OstraBuyback, OstraRouter,
// SpendVerifier and OstraPrivatePool (on that router and verifier), checks every immutable on chain, and writes the
// deployment record. The deployer is Ostra's deployer account
// (0x6569…50A2, the treasury and the launchpad's owner): it owns OstraBuyback and is its keeper, so the buyback
// run (scripts/buyback.ts) claims the launchpad's buyback part and burns with one key.
//
//   OSTRA_DEPLOYER_KEY_FILE   file (0600) with the deployer's 32-byte hex private key (default /etc/ostra/deployer.key);
//                             never printed
//   OSTRA_RPC_URL_FILE        file (0600) with the RPC URL (default /etc/ostra/robinhood-rpc.url); never printed
//   OSTRA_SWAP_DEPLOYMENT     where the record is written (default ../../deployments/robinhood-mainnet.json)
//   OSTRA_OUT_DIR             the Foundry build (default ../../out)
//
// Run again with a record in place, it only checks the record on chain. Each contract's address is kept in
// `<record>.partial` as soon as it is deployed, and the record is written as soon as all five are, before the check
// reads them back: a run that stops midway (an RPC failure, a deployment that fails) is run again and deploys only
// what is missing. Before anything is deployed it checks that the record can be written and that every contract fits
// the EIP-170 code size limit.

import { accessSync, constants as fsConstants, existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, encodeDeployData, formatEther, getAddress, getContractAddress, http, keccak256, type Abi, type Address, type Hex, type PublicClient, type WalletClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { ostraBuybackAbi, ostraPrivatePoolAbi, ostraRouterAbi, ostraStakeAbi } from "../src/abi.ts";
import { OSTRA, OSTRA_PONS_CURVE, PONS_HOOK, ROBINHOOD_CHAIN_ID, TREASURY, UNIVERSAL_ROUTER, USDG, WETH } from "../src/constants.ts";
import { NO_LEG } from "../src/legs.ts";
import { escrowAddress, orderHash, parseSwapDeployment, routeHash, type Order, type SwapDeployment } from "../src/orders.ts";
import { swapHash, unshieldHash, type PrivateSwapTerms } from "../src/private.ts";

/** Gas the five deployments may use: the fork test (test/deploy.fork.test.ts) logs what they use; this leaves room. */
export const DEPLOY_GAS_BUDGET = 18_000_000n;
/** EIP-170: the largest runtime code a contract may have (SpendVerifier is the largest, about 24,230 bytes). */
export const MAX_CODE_BYTES = 24_576;
/** The five contracts in deployment order: [Foundry file, contract]. */
export const SWAP_CONTRACTS = [
  ["OstraStake.sol", "OstraStake"],
  ["OstraBuyback.sol", "OstraBuyback"],
  ["OstraRouter.sol", "OstraRouter"],
  ["SpendVerifier.sol", "SpendVerifier"],
  ["OstraPrivatePool.sol", "OstraPrivatePool"],
] as const;
export type SwapContract = (typeof SWAP_CONTRACTS)[number][1];
/**
 * What is deployed so far: per contract, its address and the block it landed in, or, for one sent but not seen
 * landing yet, the address it lands at (from the sender's nonce) and its transaction.
 */
export type DeployProgress = Partial<Record<SwapContract, { address: Address; block?: string; tx?: Hex }>>;

/** Reads a progress file's JSON; throws naming what is wrong. */
export function parseDeployProgress(json: unknown): DeployProgress {
  if (json === null || typeof json !== "object") throw new Error("the progress file is not a JSON object");
  const names = new Set<string>(SWAP_CONTRACTS.map(([, n]) => n));
  const out: DeployProgress = {};
  for (const [name, v] of Object.entries(json as Record<string, unknown>)) {
    if (!names.has(name)) throw new Error(`the progress file names an unknown contract ${name}`);
    const e = v as { address?: unknown; block?: unknown; tx?: unknown } | null;
    if (e === null || typeof e !== "object" || typeof e.address !== "string" || !/^0x[0-9a-fA-F]{40}$/.test(e.address)) throw new Error(`the progress file has no address for ${name}`);
    if (e.block !== undefined && (typeof e.block !== "string" || !/^[0-9]+$/.test(e.block))) throw new Error(`the progress file has a bad block for ${name}`);
    if (e.tx !== undefined && (typeof e.tx !== "string" || !/^0x[0-9a-fA-F]{64}$/.test(e.tx))) throw new Error(`the progress file has a bad tx for ${name}`);
    out[name as SwapContract] = { address: getAddress(e.address), ...(e.block === undefined ? {} : { block: e.block as string }), ...(e.tx === undefined ? {} : { tx: e.tx as Hex }) };
  }
  return out;
}

function privateFile(path: string, what: string): string {
  const mode = statSync(path).mode & 0o777;
  if (mode !== 0o600) throw new Error(`${what} ${path} must have mode 0600 (it has ${mode.toString(8)})`);
  return readFileSync(path, "utf8").trim();
}

function redact(text: string, secret: string): string {
  return secret === "" ? text : text.split(secret).join("<rpc>");
}

function artifact(outDir: string, file: string, name: string): { abi: Abi; bytecode: Hex; deployed: Hex; immutables: number } {
  const a = JSON.parse(readFileSync(`${outDir}/${file}/${name}.json`, "utf8")) as { abi: Abi; bytecode: { object: Hex }; deployedBytecode: { object: Hex; immutableReferences?: Record<string, unknown> } };
  return { abi: a.abi, bytecode: a.bytecode.object, deployed: a.deployedBytecode.object, immutables: Object.keys(a.deployedBytecode.immutableReferences ?? {}).length };
}

/**
 * Checks a record against the chain: code at every address, every immutable as Ostra Swap needs it, and that the
 * router derives escrow addresses exactly as the SDK does (a vault sends its funds to the SDK's address).
 */
export async function checkSwapDeployment(c: PublicClient, d: SwapDeployment, owner: Address, outDir: string = defaultOutDir()): Promise<void> {
  for (const [name, a] of [["router", d.router], ["stake", d.stake], ["buyback", d.buyback], ["spendVerifier", d.spendVerifier], ["privatePool", d.privatePool]] as const) {
    const code = await c.getCode({ address: a });
    if (code === undefined || code === "0x") throw new Error(`no code at the ${name} ${a}`);
  }
  const eq = (what: string, got: unknown, want: unknown) => {
    if (String(got).toLowerCase() !== String(want).toLowerCase()) throw new Error(`${what} is ${String(got)}, not ${String(want)}`);
  };
  const r = (fn: string) => c.readContract({ address: d.router, abi: ostraRouterAbi, functionName: fn as never });
  eq("OstraRouter.UNIVERSAL_ROUTER", await r("UNIVERSAL_ROUTER"), UNIVERSAL_ROUTER);
  eq("OstraRouter.USDG", await r("USDG"), USDG);
  eq("OstraRouter.WETH", await r("WETH"), WETH);
  eq("OstraRouter.STAKE", await r("STAKE"), d.stake);
  eq("OstraRouter.BUYBACK", await r("BUYBACK"), d.buyback);
  eq("OstraRouter.TREASURY", await r("TREASURY"), TREASURY);
  eq("OstraStake.OSTRA", await c.readContract({ address: d.stake, abi: ostraStakeAbi, functionName: "OSTRA" }), OSTRA);
  const b = (fn: string) => c.readContract({ address: d.buyback, abi: ostraBuybackAbi, functionName: fn as never });
  eq("OstraBuyback.OSTRA", await b("OSTRA"), OSTRA);
  eq("OstraBuyback.USDG", await b("USDG"), USDG);
  eq("OstraBuyback.WETH", await b("WETH"), WETH);
  eq("OstraBuyback.PONS_HOOK", await b("PONS_HOOK"), PONS_HOOK);
  eq("OstraBuyback.UNIVERSAL_ROUTER", await b("UNIVERSAL_ROUTER"), UNIVERSAL_ROUTER);
  eq("OstraBuyback.CURVE", await b("CURVE"), OSTRA_PONS_CURVE);
  eq("OstraBuyback.owner", await b("owner"), owner);
  eq("OstraBuyback.keeper", await b("keeper"), owner);
  const sample: Order = {
    tokenIn: USDG,
    tokenOut: WETH,
    amountIn: 1n,
    minOut: 1n,
    recipient: owner,
    refundTo: owner,
    // Every field set, so that a field the SDK encodes differently from the contract shows here.
    notBefore: 2n,
    deadline: 3n,
    tranches: 2,
    interval: 1,
    executor: owner,
    canceller: TREASURY,
    route: routeHash(USDG, NO_LEG, NO_LEG),
    salt: "0x000000000000000000000000000000000000000000000000000000000000beef",
  };
  eq("OstraRouter.routeHash", await c.readContract({ address: d.router, abi: ostraRouterAbi, functionName: "routeHash", args: [USDG, NO_LEG, NO_LEG] }), sample.route);
  eq("OstraRouter.orderHash", await c.readContract({ address: d.router, abi: ostraRouterAbi, functionName: "orderHash", args: [sample] }), orderHash(sample));
  eq("OstraRouter.escrowAddress", await c.readContract({ address: d.router, abi: ostraRouterAbi, functionName: "escrowAddress", args: [sample] }), escrowAddress(d.router, sample));

  // The verifier has no immutables: its code is the build's, byte for byte.
  const v = artifact(outDir, "SpendVerifier.sol", "SpendVerifier");
  if (v.immutables !== 0) throw new Error("SpendVerifier in the build has immutables; its code cannot be compared");
  eq("SpendVerifier code hash", keccak256((await c.getCode({ address: d.spendVerifier })) ?? "0x"), keccak256(v.deployed));
  const p = (fn: string, args?: readonly unknown[]) => c.readContract({ address: d.privatePool, abi: ostraPrivatePoolAbi, functionName: fn as never, ...(args === undefined ? {} : { args: args as never }) });
  eq("OstraPrivatePool.VERIFIER", await p("VERIFIER"), d.spendVerifier);
  eq("OstraPrivatePool.ROUTER", await p("ROUTER"), d.router);
  // The SDK binds a proof to its call with the pool's own hashes (every field set, as for orders above).
  eq("OstraPrivatePool.unshieldHash", await p("unshieldHash", [owner, 7n, TREASURY]), unshieldHash(d.chainId, d.privatePool, owner, 7n, TREASURY));
  const t: PrivateSwapTerms = {
    tokenOut: WETH,
    minOut: 5n,
    outTag: "0x000000000000000000000000000000000000000000000000000000000000cafe",
    hub: USDG,
    legIn: { commands: "0x10", inputs: ["0x1234"] },
    legOut: { commands: "0x00", inputs: ["0x56", "0x78"] },
  };
  eq("OstraPrivatePool.swapHash", await p("swapHash", [owner, 9n, t]), swapHash(d.chainId, d.privatePool, owner, 9n, t));
}

function defaultOutDir(): string {
  return process.env.OSTRA_OUT_DIR || fileURLToPath(new URL("../../out", import.meta.url));
}

/** Throws unless every contract of the build fits MAX_CODE_BYTES (checked before anything is deployed). */
export function checkCodeSizes(outDir: string): void {
  for (const [file, name] of SWAP_CONTRACTS) {
    const size = (artifact(outDir, file, name).deployed.length - 2) / 2;
    if (size > MAX_CODE_BYTES) throw new Error(`${name} is ${size} bytes of code, over the ${MAX_CODE_BYTES}-byte limit: nothing was deployed`);
  }
}

/**
 * Deploys the contracts `done` does not hold yet from `wallet`'s account, which owns OstraBuyback and is its keeper,
 * in SWAP_CONTRACTS order, calling `save` with the progress after each one; returns the record. A contract in `done`
 * is reused when there is code at its address. It does not check the record: checkSwapDeployment does.
 */
export async function deploySwap(
  c: PublicClient,
  wallet: WalletClient,
  outDir: string,
  o: { log?: (event: string, fields?: Record<string, unknown>) => void; done?: DeployProgress; save?: (done: DeployProgress) => void } = {},
): Promise<{ deployment: SwapDeployment; gasUsed: bigint }> {
  const account = wallet.account;
  if (account === undefined) throw new Error("the wallet has no account");
  const log = o.log ?? (() => {});
  const done: DeployProgress = { ...(o.done ?? {}) };
  checkCodeSizes(outDir);
  const chainId = await c.getChainId();
  let gasUsed = 0n;
  const deploy = async (file: string, name: SwapContract, args: () => unknown[]): Promise<{ address: Address; block: bigint }> => {
    const a = artifact(outDir, file, name);
    const kept = done[name];
    if (kept !== undefined) {
      const code = await c.getCode({ address: kept.address });
      if (code !== undefined && code !== "0x") {
        // The verifier is compared with this build now, before a record is written with it.
        if (a.immutables === 0 && keccak256(code) !== keccak256(a.deployed)) {
          throw new Error(`the kept ${name} at ${kept.address} is not this build's code: remove the progress file to deploy anew`);
        }
        let block = kept.block;
        if (block === undefined) {
          if (kept.tx === undefined) throw new Error(`the progress names ${name} at ${kept.address} with neither its block nor its transaction`);
          block = (await c.getTransactionReceipt({ hash: kept.tx })).blockNumber.toString();
        }
        done[name] = { address: kept.address, block };
        o.save?.({ ...done });
        log("kept", { contract: name, address: kept.address });
        return { address: getAddress(kept.address), block: BigInt(block) };
      }
      if (kept.block !== undefined) throw new Error(`the progress names ${name} at ${kept.address}, where there is no code`);
      // Sent before and not landed: sent again (from the next nonce, so it lands at another address).
      log("resending", { contract: name, address: kept.address, tx: kept.tx });
    }
    // Its address is kept before it is sent: a run that stops before the receipt comes back finds it there.
    const nonce = await c.getTransactionCount({ address: account.address, blockTag: "pending" });
    const expected = getContractAddress({ from: account.address, nonce: BigInt(nonce) });
    const data = encodeDeployData({ abi: a.abi, bytecode: a.bytecode, args: args() });
    const signedTx = { account, chain: null, data, nonce } as const;
    done[name] = { address: expected };
    o.save?.({ ...done });
    const hash = await wallet.sendTransaction(signedTx);
    done[name] = { address: expected, tx: hash };
    o.save?.({ ...done });
    const receipt = await c.waitForTransactionReceipt({ hash, timeout: 120_000 });
    if (receipt.status !== "success" || receipt.contractAddress == null) throw new Error(`deploying ${name} failed (${hash})`);
    const address = getAddress(receipt.contractAddress);
    if (address !== expected) throw new Error(`${name} landed at ${address}, not at ${expected}`);
    gasUsed += receipt.gasUsed;
    done[name] = { address, block: receipt.blockNumber.toString() };
    o.save?.({ ...done });
    log("deployed", { contract: name, address, tx: hash, gasUsed: receipt.gasUsed });
    return { address, block: receipt.blockNumber };
  };
  const stake = await deploy("OstraStake.sol", "OstraStake", () => [OSTRA]);
  const buyback = await deploy("OstraBuyback.sol", "OstraBuyback", () => [OSTRA, USDG, WETH, UNIVERSAL_ROUTER, OSTRA_PONS_CURVE, PONS_HOOK, account.address, account.address]);
  const router = await deploy("OstraRouter.sol", "OstraRouter", () => [UNIVERSAL_ROUTER, USDG, WETH, stake.address, buyback.address, TREASURY]);
  const verifier = await deploy("SpendVerifier.sol", "SpendVerifier", () => []);
  const pool = await deploy("OstraPrivatePool.sol", "OstraPrivatePool", () => [verifier.address, router.address]);
  const d: SwapDeployment = {
    chainId,
    fromBlock: stake.block.toString(),
    router: router.address,
    stake: stake.address,
    buyback: buyback.address,
    spendVerifier: verifier.address,
    privatePool: pool.address,
  };
  return { deployment: d, gasUsed };
}

/** Writes `json` to `path` atomically (a new temporary file, then a rename). */
function writeAtomic(path: string, json: unknown): void {
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, `${JSON.stringify(json, null, 2)}\n`, { mode: 0o644, flag: "wx" });
  renameSync(tmp, path);
}

async function main(): Promise<void> {
  const keyFile = process.env.OSTRA_DEPLOYER_KEY_FILE || "/etc/ostra/deployer.key";
  const rpcFile = process.env.OSTRA_RPC_URL_FILE || "/etc/ostra/robinhood-rpc.url";
  const out = process.env.OSTRA_SWAP_DEPLOYMENT || fileURLToPath(new URL("../../deployments/robinhood-mainnet.json", import.meta.url));
  const outDir = defaultOutDir();
  const rpcUrl = privateFile(rpcFile, "the RPC URL file");
  const key = privateFile(keyFile, "the deployer key file");
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error(`${keyFile} does not hold a 32-byte hex private key`);
  const account = privateKeyToAccount(key as Hex);
  const log = (event: string, fields: Record<string, unknown> = {}) =>
    console.log(redact(JSON.stringify({ event, ...fields }, (_, v) => (typeof v === "bigint" ? v.toString() : v)), rpcUrl));
  try {
    const publicClient = createPublicClient({ transport: http(rpcUrl) }) as PublicClient;
    const walletClient = createWalletClient({ account, transport: http(rpcUrl) });
    const chainId = await publicClient.getChainId();
    if (chainId !== ROBINHOOD_CHAIN_ID) throw new Error(`the RPC is chain ${chainId}, not Robinhood Chain (${ROBINHOOD_CHAIN_ID})`);
    if (account.address !== getAddress(TREASURY)) throw new Error(`the deployer is ${account.address}, not Ostra's deployer ${TREASURY}`);
    const balance = await publicClient.getBalance({ address: account.address });
    const gasPrice = await publicClient.getGasPrice();
    log("deployer", { address: account.address, eth: formatEther(balance), gasPriceWei: gasPrice });

    if (existsSync(out)) {
      const d = parseSwapDeployment(JSON.parse(readFileSync(out, "utf8")));
      if (d.chainId !== chainId) throw new Error(`${out} is a deployment on chain ${d.chainId}`);
      await checkSwapDeployment(publicClient, d, account.address, outDir);
      log("checked", { deployment: d });
      console.log("SWAP_DEPLOYMENT_OK");
      return;
    }
    // Before anything is deployed: the record can be written, and every contract fits.
    mkdirSync(dirname(out), { recursive: true });
    accessSync(dirname(out), fsConstants.W_OK);
    checkCodeSizes(outDir);
    const partial = `${out}.partial`;
    const done = existsSync(partial) ? parseDeployProgress(JSON.parse(readFileSync(partial, "utf8"))) : {};
    if (Object.keys(done).length > 0) log("resuming", { partial, done });
    const need = DEPLOY_GAS_BUDGET * gasPrice;
    if (balance < need) throw new Error(`the deployer holds ${formatEther(balance)} ETH; the deployment needs up to ${formatEther(need)} ETH`);

    const { deployment: d, gasUsed } = await deploySwap(publicClient, walletClient, outDir, { log, done, save: (p) => writeAtomic(partial, p) });
    log("gas", { used: gasUsed, budget: DEPLOY_GAS_BUDGET });
    // The record first, then the check: a check that fails leaves the record, and a run again only checks.
    writeAtomic(out, d);
    rmSync(partial, { force: true });
    log("written", { record: out, deployment: d });
    await checkSwapDeployment(publicClient, d, account.address, outDir);
    log("checked", { deployment: d, ethLeft: formatEther(await publicClient.getBalance({ address: account.address })) });
    console.log("SWAP_DEPLOYMENT_OK");
  } catch (err) {
    throw new Error(redact(err instanceof Error ? err.message : String(err), rpcUrl));
  }
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err: unknown) => {
    console.error(`deploy failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
