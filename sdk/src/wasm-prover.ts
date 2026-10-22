// The Prover of private.ts running ostra-prove's WebAssembly build (privacy/wasm: wasm-bindgen, --target web) in this
// process, on Node or in a browser: no child process, no file access, the same commands and JSON as the binary
// (cli-prover.ts). Its randomness comes from crypto.getRandomValues. The caller loads the build's JS glue and .wasm
// bytes (how depends on where it runs); the bytes are checked against the SHA-256 the caller expects before they are
// instantiated. A proof takes about half a second and runs on the calling thread.
//
// A glue module holds one instance: it is set up once, with one build (a second wasmProver on the same glue must name
// the same bytes). A trap (out of memory, a stack overflow, a panic: anything but the prover's own "ostra-prove: "
// errors) leaves that instance unusable, and a JavaScript engine never frees an imported module, so the Prover refuses
// every later command with WasmProverTrapped: the process is to be restarted.

import { bytesToHex, type Hex } from "viem";
import type { Prover } from "./private.ts";

/** What the wasm-bindgen glue of privacy/wasm exports (ostra_prove.js). */
export type ProverWasmGlue = {
  initSync: (options: { module: Uint8Array }) => unknown;
  prover: (command: string, request: string) => string;
};

/** The WebAssembly prover trapped (now, or in an earlier command): its instance is not used again. */
export class WasmProverTrapped extends Error {
  constructor(message: string) {
    super(message);
    this.name = "WasmProverTrapped";
  }
}

/** The SHA-256 of `bytes`, 0x-prefixed. */
export async function sha256Hex(bytes: Uint8Array): Promise<Hex> {
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>)));
}

/** The SHA-256 of the build each glue module was set up with. */
const initialized = new WeakMap<ProverWasmGlue, Hex>();
/** Glue modules whose instance trapped, with the trap's message. */
const trapped = new WeakMap<ProverWasmGlue, string>();

/**
 * A Prover running the WebAssembly prover `bytes` through its glue. `sha256`: the hash the bytes must have (the one a
 * release records); null skips that check (a build of this repository, in development and tests).
 */
export async function wasmProver(glue: ProverWasmGlue, bytes: Uint8Array, sha256: Hex | null): Promise<Prover> {
  const got = await sha256Hex(bytes);
  if (sha256 !== null && got.toLowerCase() !== sha256.toLowerCase()) throw new Error(`the WebAssembly prover's SHA-256 is ${got}, not ${sha256}`);
  const trap = trapped.get(glue);
  if (trap !== undefined) throw new WasmProverTrapped(`this glue's instance trapped (${trap}): restart the process to prove again`);
  const before = initialized.get(glue);
  if (before === undefined) {
    glue.initSync({ module: bytes });
    initialized.set(glue, got);
  } else if (before !== got) throw new Error(`this glue runs the WebAssembly prover ${before}, not ${got}: import the glue again for another build`);
  return async (command, request) => {
    const earlier = trapped.get(glue);
    if (earlier !== undefined) throw new WasmProverTrapped(`the WebAssembly prover trapped earlier (${earlier}): restart the process to prove again`);
    let answer: string;
    try {
      answer = glue.prover(command, request === undefined ? "" : JSON.stringify(request));
    } catch (err) {
      // The prover's own errors (JsError) say "ostra-prove: ..."; anything else is a trap (a WebAssembly.RuntimeError,
      // or a RangeError for a stack overflow).
      const message = err instanceof Error ? err.message : String(err);
      if (err instanceof Error && err.name === "Error" && message.startsWith("ostra-prove: ")) throw err;
      trapped.set(glue, message);
      throw new WasmProverTrapped(`the WebAssembly prover trapped (${message}): restart the process to prove again`);
    }
    try {
      return JSON.parse(answer) as unknown;
    } catch {
      throw new Error(`ostra-prove ${command} did not answer JSON`);
    }
  };
}
