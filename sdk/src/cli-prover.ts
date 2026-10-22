// Runs the ostra-prove binary (privacy/circuit) as a child process, one per command: the Prover of private.ts on
// Node. sk and rho go to it on stdin, never on its command line. Kept apart from private.ts, which imports nothing
// of Node's, so that a browser build of this package never meets node:child_process (import it as
// @ostraagent/swap/cli-prover).

import { spawn } from "node:child_process";
import type { Prover } from "./private.ts";

/** How long one ostra-prove command may run before it is killed. */
export const PROVER_TIMEOUT_MS = 120_000;

/** Runs the ostra-prove binary at `binary`, one process per command. */
export function cliProver(binary: string, timeoutMs = PROVER_TIMEOUT_MS): Prover {
  return (command, request) =>
    new Promise((resolve, reject) => {
      const child = spawn(binary, [command], { stdio: ["pipe", "pipe", "pipe"] });
      let settled = false;
      const settle = (f: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        f();
      };
      // Unref'd, and cleared once settled: a binary that fails to start leaves no timer keeping the process up.
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        settle(() => reject(new Error(`ostra-prove ${command} ran longer than ${timeoutMs} ms`)));
      }, timeoutMs);
      timer.unref();
      let out = "";
      let err = "";
      child.stdout.on("data", (b: Buffer) => (out += b.toString()));
      child.stderr.on("data", (b: Buffer) => (err += b.toString()));
      child.on("error", (e) => settle(() => reject(e)));
      // A prover that exits before reading its request (`secret` never reads it) closes the pipe: the exit code and
      // stderr decide the answer, not the write (independent review, 21 Oct 2026: an unhandled EPIPE killed the process).
      child.stdin.on("error", () => {});
      child.on("close", (code, signal) =>
        settle(() => {
          if (code !== 0) return reject(new Error(`ostra-prove ${command} failed (${signal ?? code}): ${err.trim().slice(0, 300)}`));
          try {
            resolve(JSON.parse(out));
          } catch {
            reject(new Error(`ostra-prove ${command} did not answer JSON`));
          }
        }),
      );
      if (request === undefined) child.stdin.end();
      else child.stdin.end(JSON.stringify(request));
    });
}
