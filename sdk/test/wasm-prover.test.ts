// The WebAssembly prover (privacy/wasm, built by privacy/wasm/build.sh into privacy/wasm/pkg) against the native one
// (privacy/target/release/ostra-prove): the same answers for note and path, the same public values for a proof of the
// prover's own test request, every WebAssembly proof checked by the Solidity SpendVerifier on a local anvil (no fork;
// eth_call gets anvil's block gas limit), fresh randomness, the prover's errors, and the SHA-256 check before
// instantiating, the same error for every bad request, and an index of 2^32 refused (usize is 32 bits in
// WebAssembly). Prints the mean time of three proofs each. Needs both builds, `forge build` (out/SpendVerifier.sol)
// and anvil on PATH.

import { after, before, test } from "node:test";
import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import { createPublicClient, createWalletClient, getAddress, http, type Address, type Hex, type PublicClient } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { cliProver } from "../src/cli-prover.ts";
import type { Prover } from "../src/private.ts";
import { sha256Hex, wasmProver, type ProverWasmGlue } from "../src/wasm-prover.ts";

const ROOT = new URL("../../", import.meta.url);
const PKG = new URL("privacy/wasm/pkg/", ROOT);
const REQUEST = JSON.parse(readFileSync(new URL("privacy/contracts/test/data/cli_request.json", ROOT), "utf8")) as Record<string, unknown>;
const PORT = 8_762;
const RPC = `http://127.0.0.1:${PORT}`;
const DEPLOYER = privateKeyToAccount("0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");
const VERIFY_ABI = [{ type: "function", name: "verify", stateMutability: "view", inputs: [{ name: "proof", type: "bytes" }, { name: "publicValues", type: "uint256[48]" }], outputs: [{ type: "bool" }] }] as const;
const P = 2_130_706_433n;

const native = cliProver(fileURLToPath(new URL("privacy/target/release/ostra-prove", ROOT)));
let glue: ProverWasmGlue;
let bytes: Uint8Array;
let wasm: Prover;
let anvil: ChildProcess;
let client: PublicClient;
let verifier: Address;

type Proved = { proof: Hex; public_values: string[]; change_rho: string[]; change_tag: string[] };

before(async () => {
  glue = (await import(new URL("ostra_prove.js", PKG).href)) as ProverWasmGlue;
  bytes = new Uint8Array(readFileSync(new URL("ostra_prove_bg.wasm", PKG)));
  wasm = await wasmProver(glue, bytes, null);
  anvil = spawn("anvil", ["--port", String(PORT), "--gas-limit", "100000000", "--code-size-limit", "50000"], { stdio: "ignore" });
  client = createPublicClient({ transport: http(RPC) }) as PublicClient;
  for (let i = 0; ; i++) {
    try {
      await client.getChainId();
      break;
    } catch {
      if (i > 60) throw new Error("anvil did not start");
      await new Promise((r) => setTimeout(r, 500));
    }
  }
  const art = JSON.parse(readFileSync(new URL("out/SpendVerifier.sol/SpendVerifier.json", ROOT), "utf8")) as { abi: unknown[]; bytecode: { object: Hex } };
  const hash = await createWalletClient({ account: DEPLOYER, transport: http(RPC) }).deployContract({ abi: art.abi, bytecode: art.bytecode.object, chain: null, gas: 30_000_000n });
  const r = await client.waitForTransactionReceipt({ hash });
  assert.equal(r.status, "success");
  verifier = getAddress(r.contractAddress as Address);
});

after(() => {
  anvil?.kill();
});

const verified = (p: Proved) =>
  client.readContract({ address: verifier, abi: VERIFY_ABI, functionName: "verify", args: [p.proof, p.public_values.map((x) => BigInt(x)) as never] });

test("note and path: the same answers as the native prover", async () => {
  const note = { sk: REQUEST.sk, rho: REQUEST.rho, asset: REQUEST.asset, amount: REQUEST.amount };
  assert.deepEqual(await wasm("note", note), await native("note", note));
  // Field elements as numbers rather than strings.
  const numeric = { ...note, sk: (REQUEST.sk as string[]).map(Number), rho: (REQUEST.rho as string[]).map(Number) };
  assert.deepEqual(await wasm("note", numeric), await native("note", note));
  const digests = [REQUEST.rho, REQUEST.sk, REQUEST.change_rho, ...(REQUEST.path as unknown[]).slice(0, 14)];
  assert.equal(digests.length, 17);
  for (const index of [0, 1, 2, 15, 16]) assert.deepEqual(await wasm("path", { leaves: digests, index }), await native("path", { leaves: digests, index }));
});

test("bad requests: the native prover's errors, word for word (an index of 2^32 too, which a 32-bit usize must not cut)", async () => {
  const leaves = [REQUEST.rho, REQUEST.sk, REQUEST.change_rho];
  const bad: [Parameters<Prover>[0], unknown][] = [
    ["note", { sk: [1] }],
    ["note", { ...REQUEST, amount: "340282366920938463463374607431768211456" }],
    ["note", { ...REQUEST, asset: "0x1234" }],
    ["note", { ...REQUEST, sk: [...(REQUEST.sk as string[]).slice(0, 7), "2130706433"] }],
    ["path", { leaves, index: 3 }],
    ["path", { leaves, index: 4_294_967_296 }],
    ["prove", { ...REQUEST, index: 4_294_967_296 }],
    ["prove", { ...REQUEST, change_rho: REQUEST.rho }],
    ["prove", { ...REQUEST, path: (REQUEST.path as unknown[]).slice(1) }],
    ["prove", { ...REQUEST, root: REQUEST.sk }],
    ["prove", { ...REQUEST, v: "2000000000" }],
  ];
  const message = (err: unknown) => {
    const m = (err as Error).message;
    return m.slice(m.indexOf("ostra-prove: ") + "ostra-prove: ".length).trim();
  };
  for (const [command, request] of bad) {
    const n = await native(command, request).then(() => null, message);
    const w = await wasm(command, request).then(() => null, message);
    assert.ok(n !== null, `native accepted ${command} ${JSON.stringify(request).slice(0, 80)}`);
    assert.equal(w, n, `${command}: ${n}`);
  }
});

test("prove: the native prover's public values, a fresh proof each time, every one accepted by SpendVerifier", async () => {
  const times: Record<string, number[]> = { native: [], wasm: [] };
  const outs: Record<string, Proved[]> = { native: [], wasm: [] };
  for (const [name, prover] of [["native", native], ["wasm", wasm]] as const) {
    for (let i = 0; i < 3; i++) {
      const t = performance.now();
      outs[name]!.push((await prover("prove", REQUEST)) as Proved);
      times[name]!.push(performance.now() - t);
    }
  }
  const reference = outs.native![0]!;
  for (const o of outs.wasm!) {
    assert.deepEqual(o.public_values, reference.public_values);
    assert.deepEqual(o.change_tag, reference.change_tag);
    assert.equal(await verified(o), true);
  }
  assert.equal(await verified(reference), true);
  assert.equal(new Set(outs.wasm!.map((o) => o.proof)).size, 3, "a fresh proof each time");
  for (const name of ["native", "wasm"]) console.log(`# ${name}: mean ${(times[name]!.reduce((a, b) => a + b, 0) / 3 / 1000).toFixed(2)} s per proof`);
});

test("secret: 8 field elements below P, fresh each time; prove draws change_rho when not given", async () => {
  const a = ((await wasm("secret")) as { digest: string[] }).digest;
  const b = ((await wasm("secret")) as { digest: string[] }).digest;
  assert.equal(a.length, 8);
  assert.ok(a.every((x) => BigInt(x) < P));
  assert.notDeepEqual(a, b);
  const { change_rho: _, ...noChange } = REQUEST;
  const p = (await wasm("prove", noChange)) as Proved;
  assert.notDeepEqual(p.change_rho, REQUEST.change_rho);
  assert.equal(await verified(p), true);
});

test("bytes with another SHA-256 are refused, and a glue set up once runs no other build", async () => {
  await assert.rejects(wasm("nonsense" as never, {}), /usage/);
  const hash = await sha256Hex(bytes);
  const again = await wasmProver(glue, bytes, hash);
  assert.equal(((await again("secret")) as { digest: string[] }).digest.length, 8);
  await assert.rejects(wasmProver(glue, bytes, `0x${"00".repeat(32)}`), /SHA-256 is 0x/);
  const other = bytes.slice();
  other[other.length - 1] = (other[other.length - 1] as number) ^ 1;
  await assert.rejects(wasmProver(glue, other, null), /import the glue again for another build/);
});
