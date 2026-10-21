// Deploys Ostra Swap to Robinhood Chain from the Foundry build (out/): OstraStake, OstraBuyback and OstraRouter,
// checks every immutable on chain, and writes the deployment record. The deployer is Ostra's deployer account
// (0x6569…50A2, the treasury and the launchpad's owner): it owns OstraBuyback and is its keeper, so the buyback
// run (scripts/buyback.ts) claims the launchpad's buyback part and burns with one key.
//
//   OSTRA_DEPLOYER_KEY_FILE   file (0600) with the deployer's 32-byte hex private key (default /etc/ostra/deployer.key);
//                             never printed
//   OSTRA_RPC_URL_FILE        file (0600) with the RPC URL (default /etc/ostra/robinhood-rpc.url); never printed
//   OSTRA_SWAP_DEPLOYMENT     where the record is written (default ../../deployments/robinhood-mainnet.json)
//   OSTRA_OUT_DIR             the Foundry build (default ../../out)
//
// Run again with a record in place, it only checks the record on chain.

import { existsSync, readFileSync, renameSync, statSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, formatEther, getAddress, http, type Abi, type Address, type Hex, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { ostraBuybackAbi, ostraRouterAbi, ostraStakeAbi } from "../src/abi.ts";
import { OSTRA, OSTRA_PONS_CURVE, PONS_HOOK, ROBINHOOD_CHAIN_ID, TREASURY, UNIVERSAL_ROUTER, USDG, WETH } from "../src/constants.ts";
import { NO_LEG } from "../src/legs.ts";
import { escrowAddress, orderHash, routeHash, type Order, type SwapDeployment } from "../src/orders.ts";

/** Gas the three deployments may use: the fork test (test/route.fork.test.ts) logs what they use; this leaves room. */
export const DEPLOY_GAS_BUDGET = 8_000_000n;

function privateFile(path: string, what: string): string {
  const mode = statSync(path).mode & 0o777;
  if (mode !== 0o600) throw new Error(`${what} ${path} must have mode 0600 (it has ${mode.toString(8)})`);
  return readFileSync(path, "utf8").trim();
}

function redact(text: string, secret: string): string {
  return secret === "" ? text : text.split(secret).join("<rpc>");
}

function artifact(outDir: string, file: string, name: string): { abi: Abi; bytecode: Hex } {
  const a = JSON.parse(readFileSync(`${outDir}/${file}/${name}.json`, "utf8")) as { abi: Abi; bytecode: { object: Hex } };
  return { abi: a.abi, bytecode: a.bytecode.object };
}

/**
 * Checks a record against the chain: code at every address, every immutable as Ostra Swap needs it, and that the
 * router derives escrow addresses exactly as the SDK does (a vault sends its funds to the SDK's address).
 */
export async function checkSwapDeployment(c: PublicClient, d: SwapDeployment, owner: Address): Promise<void> {
  for (const [name, a] of [["router", d.router], ["stake", d.stake], ["buyback", d.buyback]] as const) {
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
}

async function main(): Promise<void> {
  const keyFile = process.env.OSTRA_DEPLOYER_KEY_FILE || "/etc/ostra/deployer.key";
  const rpcFile = process.env.OSTRA_RPC_URL_FILE || "/etc/ostra/robinhood-rpc.url";
  const out = process.env.OSTRA_SWAP_DEPLOYMENT || fileURLToPath(new URL("../../deployments/robinhood-mainnet.json", import.meta.url));
  const outDir = process.env.OSTRA_OUT_DIR || fileURLToPath(new URL("../../out", import.meta.url));
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
      const d = JSON.parse(readFileSync(out, "utf8")) as SwapDeployment;
      if (d.chainId !== chainId) throw new Error(`${out} is a deployment on chain ${d.chainId}`);
      await checkSwapDeployment(publicClient, d, account.address);
      log("checked", { deployment: d });
      console.log("SWAP_DEPLOYMENT_OK");
      return;
    }
    const need = DEPLOY_GAS_BUDGET * gasPrice;
    if (balance < need) throw new Error(`the deployer holds ${formatEther(balance)} ETH; the deployment needs up to ${formatEther(need)} ETH`);

    const deploy = async (file: string, name: string, args: unknown[]): Promise<{ address: Address; block: bigint }> => {
      const a = artifact(outDir, file, name);
      const hash = await walletClient.deployContract({ abi: a.abi, bytecode: a.bytecode, args, chain: null });
      const receipt = await publicClient.waitForTransactionReceipt({ hash, timeout: 120_000 });
      if (receipt.status !== "success" || receipt.contractAddress == null) throw new Error(`deploying ${name} failed (${hash})`);
      log("deployed", { contract: name, address: receipt.contractAddress, tx: hash, gasUsed: receipt.gasUsed });
      return { address: getAddress(receipt.contractAddress), block: receipt.blockNumber };
    };
    const stake = await deploy("OstraStake.sol", "OstraStake", [OSTRA]);
    const buyback = await deploy("OstraBuyback.sol", "OstraBuyback", [OSTRA, USDG, WETH, UNIVERSAL_ROUTER, OSTRA_PONS_CURVE, PONS_HOOK, account.address, account.address]);
    const router = await deploy("OstraRouter.sol", "OstraRouter", [UNIVERSAL_ROUTER, USDG, WETH, stake.address, buyback.address, TREASURY]);
    const d: SwapDeployment = { chainId, fromBlock: stake.block.toString(), router: router.address, stake: stake.address, buyback: buyback.address };
    await checkSwapDeployment(publicClient, d, account.address);
    const tmp = `${out}.tmp-${process.pid}`;
    writeFileSync(tmp, `${JSON.stringify(d, null, 2)}\n`, { mode: 0o644, flag: "wx" });
    renameSync(tmp, out);
    log("written", { record: out, deployment: d, ethLeft: formatEther(await publicClient.getBalance({ address: account.address })) });
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
