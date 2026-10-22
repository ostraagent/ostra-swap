#!/usr/bin/env bash
# Builds ostra-prove as WebAssembly (wasm32-unknown-unknown with SIMD, wasm-bindgen --target web) into
# privacy/wasm/pkg: ostra_prove.js (the glue, an ES module: initSync and prover), ostra_prove_bg.wasm and their
# types. Needs the wasm32-unknown-unknown target (rustup target add wasm32-unknown-unknown) and wasm-bindgen-cli at
# the version of the wasm-bindgen crate (cargo install wasm-bindgen-cli --version 0.2.129 --locked). Paths are
# remapped so that the build does not carry this machine's directories. Prints the SHA-256 of the .wasm and the glue.
set -euo pipefail
WASM_BINDGEN_VERSION=0.2.129
cd "$(dirname "$0")/.."
command -v wasm-bindgen > /dev/null || { echo "wasm-bindgen-cli $WASM_BINDGEN_VERSION is missing"; exit 1; }
[ "$(wasm-bindgen --version)" = "wasm-bindgen $WASM_BINDGEN_VERSION" ] || { echo "wasm-bindgen-cli must be $WASM_BINDGEN_VERSION, not $(wasm-bindgen --version)"; exit 1; }
rustup target list --installed | grep -x wasm32-unknown-unknown > /dev/null || { echo "the wasm32-unknown-unknown target is missing"; exit 1; }
here=$(pwd)
target_dir=${CARGO_TARGET_DIR:-$here/target}
# CARGO_ENCODED_RUSTFLAGS (flags separated by 0x1f), so that a path with a space stays one flag. With --target, cargo
# applies them to the WebAssembly artifact only, not to build scripts or procedural macros.
flags=("-C" "target-feature=+simd128" "--remap-path-prefix=$here=/ostra-swap/privacy" "--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo" "--remap-path-prefix=$(rustc --print sysroot)=/rust")
CARGO_ENCODED_RUSTFLAGS=$(IFS=$'\x1f'; echo "${flags[*]}") cargo build --release --locked --target wasm32-unknown-unknown -p ostra-swap-prover-wasm
rm -rf wasm/pkg
wasm-bindgen --target web --out-dir wasm/pkg --out-name ostra_prove "$target_dir/wasm32-unknown-unknown/release/ostra_swap_prover_wasm.wasm"
# The glue is an ES module.
printf '{ "type": "module" }\n' > wasm/pkg/package.json
rustc --version
if command -v sha256sum > /dev/null; then sha256sum wasm/pkg/ostra_prove_bg.wasm wasm/pkg/ostra_prove.js; else shasum -a 256 wasm/pkg/ostra_prove_bg.wasm wasm/pkg/ostra_prove.js; fi
