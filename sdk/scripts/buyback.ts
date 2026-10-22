// One buyback-and-burn run (systemd timer ostra-buyback.timer, hourly). With Ostra's deployer key, OstraBuyback's
// owner and keeper:
//   1. claims the Ostra launchpad's buyback part (OstraDispatcher.claimBuyback, owner only) of every pool quote
//      currency the launchpad has launched with, to OstraBuyback; the part owed in OSTRA needs no buy and goes
//      straight to the burn address (OstraBuyback burns only the OSTRA it buys);
//   2. turns what OstraBuyback holds besides WETH (USDG, stock tokens) into WETH (toWeth) along the Uniswap v3 path
//      that simulates best: token to WETH, or token to USDG to WETH (the only paths OstraBuyback takes);
//   3. buys OSTRA with its WETH and burns it: on OSTRA's Pons bonding curve while it trades (burnOnCurve), else in
//      the Uniswap v4 pool Pons graduates OSTRA to (burnOnRouter; the pool is fixed in OstraBuyback).
// Each trade is simulated first from the keeper (eth_call) and sent with that result less MAX_SLIPPAGE_BPS as its
// minimum, so a trade that would fail is not sent, with a gas limit of its estimate + GAS_LIMIT_MARGIN_PERCENT.
// Amounts below the dust limits wait for the next run. The launches are read from the public RPC's logs; when that
// read fails, the run goes on with USDG, ETH and OSTRA.
//
//   OSTRA_DEPLOYER_KEY_FILE   (0600) default /etc/ostra/deployer.key; never printed
//   OSTRA_RPC_URL_FILE        (0600) default /etc/ostra/robinhood-rpc.url; never printed
//   OSTRA_SWAP_DEPLOYMENT     default ../../deployments/robinhood-mainnet.json
//   OSTRA_DEPLOYMENT          the Ostra deployment record with the launchpad (default
//                             /srv/apps/ostra-robinhood/deployments/robinhood-mainnet.json)

import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createPublicClient, createWalletClient, encodeFunctionData, encodePacked, formatEther, getAddress, http, parseAbi, parseAbiItem, zeroAddress, type Account, type Address, type Chain, type Hex, type PublicClient, type Transport, type WalletClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { ostraBuybackAbi } from "../src/abi.ts";
import { BURN_ADDRESS, ETH, OSTRA, ROBINHOOD_CHAIN_ID, ROBINHOOD_PUBLIC_RPC, TREASURY, UNISWAP_V3_FACTORY, USDG, V3_FEE_TIERS, WETH } from "../src/constants.ts";
import type { SwapDeployment } from "../src/orders.ts";
import { erc20Abi, v3FactoryAbi } from "../src/uniswap.ts";

/** The least the keeper accepts below what its own simulation of the trade gave. */
export const MAX_SLIPPAGE_BPS = 100n;
/** Below these, a balance waits for the next run: 1 USDG, 0.0002 WETH (about half a US dollar). */
export const MIN_USDG = 1_000_000n;
export const MIN_WETH = 200_000_000_000_000n;
/** Gas limit = estimate + 20% (decided 17 Oct 2026, as Ostra's relayer): the L1 part of an estimate moves with the L1 price. */
export const GAS_LIMIT_MARGIN_PERCENT = 20n;

const dispatcherAbi = parseAbi([
  "function buybackOwed(address currency) view returns (uint256)",
  "function claimBuyback(address currency, address to)",
]);
const launchedEvent = parseAbiItem("event Launched(bytes32 indexed poolId, address indexed token, address indexed creatorVault, address quote)");

function privateFile(path: string, what: string): string {
  const mode = statSync(path).mode & 0o777;
  if (mode !== 0o600) throw new Error(`${what} ${path} must have mode 0600 (it has ${mode.toString(8)})`);
  return readFileSync(path, "utf8").trim();
}

function less(amount: bigint): bigint {
  return (amount * (10_000n - MAX_SLIPPAGE_BPS)) / 10_000n;
}

/** What one run needs: the chain, the keeper (Ostra's deployer, owner of OstraDispatcher), OstraBuyback and the launchpad. */
export type BuybackRun = {
  client: PublicClient;
  logsClient: PublicClient;
  wallet: WalletClient<Transport, Chain | undefined, Account>;
  buyback: Address;
  ostra: { fromBlock: string; launchpad?: { launchpad: Address; dispatcher: Address } };
  log: (event: string, fields?: Record<string, unknown>) => void;
  redact?: (text: string) => string;
};

async function main(): Promise<void> {
  const keyFile = process.env.OSTRA_DEPLOYER_KEY_FILE || "/etc/ostra/deployer.key";
  const rpcUrl = privateFile(process.env.OSTRA_RPC_URL_FILE || "/etc/ostra/robinhood-rpc.url", "the RPC URL file");
  const swapPath = process.env.OSTRA_SWAP_DEPLOYMENT || fileURLToPath(new URL("../../deployments/robinhood-mainnet.json", import.meta.url));
  const ostraPath = process.env.OSTRA_DEPLOYMENT || "/srv/apps/ostra-robinhood/deployments/robinhood-mainnet.json";
  const key = privateFile(keyFile, "the deployer key file");
  if (!/^0x[0-9a-fA-F]{64}$/.test(key)) throw new Error(`${keyFile} does not hold a 32-byte hex private key`);
  const account = privateKeyToAccount(key as Hex);
  const redact = (t: string) => t.split(rpcUrl).join("<rpc>");
  const log = (event: string, fields: Record<string, unknown> = {}) => console.log(redact(JSON.stringify({ event, ...fields }, (_, v) => (typeof v === "bigint" ? v.toString() : v))));

  const client = createPublicClient({ transport: http(rpcUrl) }) as PublicClient;
  const logsClient = createPublicClient({ transport: http(ROBINHOOD_PUBLIC_RPC, { retryCount: 6, retryDelay: 2_000 }) }) as PublicClient;
  const wallet = createWalletClient({ account, transport: http(rpcUrl) });
  if ((await client.getChainId()) !== ROBINHOOD_CHAIN_ID) throw new Error("the RPC is not Robinhood Chain");
  if (account.address !== getAddress(TREASURY)) throw new Error(`the key is ${account.address}, not Ostra's deployer`);
  const d = JSON.parse(readFileSync(swapPath, "utf8")) as SwapDeployment;
  const buyback = getAddress(d.buyback);
  const keeper = getAddress((await client.readContract({ address: buyback, abi: ostraBuybackAbi, functionName: "keeper" })) as Address);
  if (keeper !== account.address) throw new Error(`OstraBuyback's keeper is ${keeper}, not ${account.address}`);
  const ostra = JSON.parse(readFileSync(ostraPath, "utf8")) as BuybackRun["ostra"];
  await runBuyback({ client, logsClient, wallet, buyback, ostra, log, redact });
}

/** One run (steps 1 to 3 above) from `wallet`'s account, which must be OstraBuyback's keeper and the dispatcher's owner. */
export async function runBuyback(o: BuybackRun): Promise<void> {
  const { client, logsClient, wallet, buyback, ostra, log } = o;
  const redact = o.redact ?? ((t: string) => t);
  const account = wallet.account;

  const send = async (to: Address, data: Hex, what: string): Promise<boolean> => {
    let estimated: bigint;
    try {
      await client.call({ account: account.address, to, data });
      estimated = await client.estimateGas({ account: account.address, to, data });
    } catch (err) {
      log("skipped", { what, reason: redact((err as Error).message.split("\n")[0] ?? "") });
      return false;
    }
    const hash = await wallet.sendTransaction({ to, data, chain: null, gas: estimated + (estimated * GAS_LIMIT_MARGIN_PERCENT) / 100n });
    const r = await client.waitForTransactionReceipt({ hash, timeout: 120_000 });
    log(r.status === "success" ? "sent" : "reverted", { what, tx: hash, gasUsed: r.gasUsed });
    return r.status === "success";
  };
  const simulate = async (data: Hex): Promise<bigint | null> => {
    try {
      const { data: ret } = await client.call({ account: account.address, to: buyback, data });
      return ret === undefined ? null : BigInt(ret.slice(0, 66));
    } catch {
      return null;
    }
  };
  const balanceOf = (token: Address) => client.readContract({ address: token, abi: erc20Abi, functionName: "balanceOf", args: [buyback] }) as Promise<bigint>;
  const v3PoolExists = async (a: Address, b: Address, fee: number): Promise<boolean> =>
    ((await client.readContract({ address: UNISWAP_V3_FACTORY, abi: v3FactoryAbi, functionName: "getPool", args: [a, b, fee] })) as Address) !== zeroAddress;

  // 1. The launchpad's buyback part, per quote currency it launched with: OSTRA straight to the burn address.
  const currencies = new Set<Address>([USDG, ETH, OSTRA]);
  if (ostra.launchpad !== undefined) {
    try {
      const head = await logsClient.getBlockNumber();
      for (let from = BigInt(ostra.fromBlock); from <= head; from += 10_000_000n) {
        const to = from + 9_999_999n < head ? from + 9_999_999n : head;
        for (const l of await logsClient.getLogs({ address: ostra.launchpad.launchpad, event: launchedEvent, fromBlock: from, toBlock: to })) {
          if (l.args.quote !== undefined) currencies.add(getAddress(l.args.quote));
        }
      }
    } catch (err) {
      log("launches_unread", { reason: redact((err as Error).message.split("\n")[0] ?? ""), currencies: [...currencies] });
    }
    for (const c of currencies) {
      const owed = (await client.readContract({ address: ostra.launchpad.dispatcher, abi: dispatcherAbi, functionName: "buybackOwed", args: [c] })) as bigint;
      if (owed === 0n) continue;
      const to = c === OSTRA ? BURN_ADDRESS : buyback;
      await send(ostra.launchpad.dispatcher, encodeFunctionData({ abi: dispatcherAbi, functionName: "claimBuyback", args: [c, to] }), c === OSTRA ? `burn launchpad buyback OSTRA ${owed}` : `claim launchpad buyback ${c} ${owed}`);
    }
  }

  // 2. Everything but WETH into WETH (ETH arrives from the launchpad as WETH), along the Uniswap v3 path that
  //    simulates best: token to WETH directly, or through USDG.
  for (const token of [...currencies].filter((c) => c !== ETH && c !== WETH && c !== OSTRA && c !== zeroAddress)) {
    const amount = await balanceOf(token);
    if (amount === 0n || (token === USDG && amount < MIN_USDG)) continue;
    const paths: Hex[] = [];
    for (const fee of V3_FEE_TIERS) {
      if (await v3PoolExists(token, WETH, fee)) paths.push(encodePacked(["address", "uint24", "address"], [token, fee, WETH]));
    }
    if (token !== USDG) {
      for (const f1 of V3_FEE_TIERS) {
        if (!(await v3PoolExists(token, USDG, f1))) continue;
        for (const f2 of V3_FEE_TIERS) {
          if (await v3PoolExists(USDG, WETH, f2)) paths.push(encodePacked(["address", "uint24", "address", "uint24", "address"], [token, f1, USDG, f2, WETH]));
        }
      }
    }
    const data = (path: Hex, min: bigint) => encodeFunctionData({ abi: ostraBuybackAbi, functionName: "toWeth", args: [token, amount, min, path] });
    let best: { path: Hex; out: bigint } | null = null;
    for (const path of paths) {
      const out = await simulate(data(path, 0n));
      if (out !== null && (best === null || out > best.out)) best = { path, out };
    }
    if (best === null || best.out < MIN_WETH) {
      log("waiting", { token, amount, wethQuote: best?.out ?? 0n });
      continue;
    }
    await send(buyback, data(best.path, less(best.out)), `toWeth ${token} ${amount}`);
  }

  // 3. Burn: on the curve while OSTRA trades there, else in the pool Pons graduated it to.
  const weth = await balanceOf(WETH);
  if (weth < MIN_WETH) {
    log("waiting", { weth: formatEther(weth) });
  } else {
    const onCurve = (min: bigint) => encodeFunctionData({ abi: ostraBuybackAbi, functionName: "burnOnCurve", args: [weth, min] });
    const onRouter = (min: bigint) => encodeFunctionData({ abi: ostraBuybackAbi, functionName: "burnOnRouter", args: [weth, min] });
    const curveOut = await simulate(onCurve(1n));
    if (curveOut !== null) {
      await send(buyback, onCurve(less(curveOut)), `burnOnCurve ${formatEther(weth)} WETH`);
    } else {
      const routerOut = await simulate(onRouter(1n));
      if (routerOut === null) log("waiting", { weth: formatEther(weth), reason: "neither the curve nor OSTRA's v4 pool takes the buy now" });
      else await send(buyback, onRouter(less(routerOut)), `burnOnRouter ${formatEther(weth)} WETH`);
    }
  }

  log("done", { eth: formatEther(await client.getBalance({ address: account.address })) });
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().catch((err: unknown) => {
    console.error(`buyback failed: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}
