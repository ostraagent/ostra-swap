//! `ostra-prove` as WebAssembly (wasm32-unknown-unknown, wasm-bindgen): `prover(command, request)` runs one command
//! of `ostra_swap_circuit::api` on one JSON request and returns its JSON answer, or throws the prover's error. Its
//! randomness (secrets, nonces, the proof's salts) comes from `crypto.getRandomValues` (getrandom's wasm_js backend),
//! which Node and browsers provide. Built by privacy/wasm/build.sh.

use wasm_bindgen::prelude::*;

/// Runs `command` ("secret", "note", "path" or "prove") on `request` (JSON; ignored by "secret").
#[wasm_bindgen]
pub fn prover(command: &str, request: &str) -> Result<String, JsError> {
    ostra_swap_circuit::api::run(command, request).map_err(|e| JsError::new(&format!("ostra-prove: {e}")))
}
