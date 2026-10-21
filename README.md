<p align="center">
  <a href="https://ostraagent.xyz"><img src="https://ostraagent.xyz/favicon.svg" width="72" height="72" alt="Ostra"></a>
</p>

<h1 align="center">Ostra Swap</h1>

<p align="center">
  Swaps for every token on Robinhood Chain with a Uniswap v3 or v4 pool, from a wallet, from an Ostra vault<br>
  that only post-quantum one-time signatures can spend, or from a private balance that hides whose swap it is.<br>
  Holders who lock OSTRA pay less; half of every fee buys OSTRA and burns it.
</p>

<p align="center">
  <a href="https://ostraagent.xyz"><img src="https://img.shields.io/badge/website-ostraagent.xyz-15171A" alt="Website"></a>
  <a href="https://docs.ostraagent.xyz"><img src="https://img.shields.io/badge/docs-docs.ostraagent.xyz-15171A" alt="Documentation"></a>
  <a href="https://x.com/ostraagent"><img src="https://img.shields.io/badge/X-@ostraagent-15171A?logo=x&logoColor=white" alt="Ostra Agent on X"></a>
  <a href="https://robinhoodchain.blockscout.com"><img src="https://img.shields.io/badge/Robinhood%20Chain-4663-D9381E" alt="Robinhood Chain 4663"></a>
  <a href="foundry.toml"><img src="https://img.shields.io/badge/Solidity-0.8.30-3E4248" alt="Solidity 0.8.30"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-3E4248" alt="MIT license"></a>
</p>

## What is in this repository

| Path | What it is |
| --- | --- |
| `src/OstraRouter.sol` | The swap router: tokenIn to a hub (USDG or WETH) to tokenOut through Uniswap's Universal Router, the Ostra fee taken on the hub amount between the two legs. `swap` for wallets (`swapAtBaseFee`, the same at the base fee, for the private pool); `executeEscrow` for Ostra vaults, immediate or standing (limit, take-profit, DCA). No owner, no upgrade. |
| `src/OstraStake.sol` | Locks OSTRA for at least 7 days; a lock lowers the Ostra fee of up to 8 accounts its owner names (while locked the list can only grow). No owner, no upgrade. |
| `src/OstraQuoteBatch.sol` | Never deployed: the SDK runs its creation code in an `eth_call` to quote many pools at once, each quote with its own gas bound. |
| `src/OstraBuyback.sol` | Turns its share of the fees into WETH, buys OSTRA (on its Pons bonding curve, or in the pool Pons graduates it to) and sends it to the burn address `0x…dEaD`. Every Universal Router command is built by the contract itself. |
| `src/OstraPrivatePool.sol` | Private balances: `shield` turns a token into a note; `unshield` and `privateSwap` spend one with a STARK proof that hides which note it is and whose. No owner, no upgrade. |
| `privacy/` | The spend circuit (Plonky3), the `ostra-prove` command-line prover and the Solidity verifier: [privacy/README.md](privacy/README.md). |
| `test/` | Forge tests on a fork of Robinhood Chain mainnet: the real Universal Router, Uniswap v3 and v4 pools, USDG, WETH, stock tokens, OSTRA's curve and the live Ostra vault factory. The private pool's proofs are made during the tests by `ostra-prove`. |
| `sdk/` | `@ostraagent/swap`: finds pools, quotes routes, builds the legs, orders, escrow addresses and calldata. Private balances (`src/private.ts`): notes, the pool's trees rebuilt from its events, proofs through `ostra-prove`, the bind hashes and the pool's calls. Also the deploy script (OstraStake, OstraBuyback, OstraRouter) and the hourly buyback run. |
| `ops/systemd/` | The buyback service and timer. |

## Fees

| OSTRA locked for the account | Ostra fee |
| --- | --- |
| less than 100,000 | 0.20% |
| 100,000 or more | 0.15% |
| 250,000 or more | 0.10% |
| 500,000 or more | 0% |

The fee is taken in the hub (USDG or WETH), on top of what the pools charge. Half goes to `OstraBuyback`, which buys
OSTRA and burns it; the other half goes to Ostra's treasury. For a wallet swap the account is the sender; for a vault
swap it is the account that gets the output.

A private swap always pays 0.20%. The private pool swaps for every note owner as one account, and a discount would
need the owner's identity; a lock naming the pool would lower every owner's fee at once, so the pool swaps through
`swapAtBaseFee`.

## How a vault swaps

An Ostra vault holds one token and moves it only with a Winternitz one-time signature (WOTS over Keccak-256), and
every spend replaces its key. It needs no new code to use Ostra Swap:

1. The swap is an order: tokens, amount, minimum output, recipient, refund address, deadline, the route (hub and
   both legs) and a salt (and, for a standing order, its schedule, executor and canceller).
2. `OstraRouter.escrowAddress(order)` is a CREATE2 address derived from the whole order. The vault's WOTS key signs a
   Transfer of the amount to it, so the post-quantum signature binds every term of the swap, the route included.
3. In the same transaction, `executeEscrow` takes what the escrow holds and runs the order. Whoever sends it chooses
   nothing.
4. `executeEscrow` never reverts once the order has a refund address. A swap that fails, misses its minimum, comes
   after its deadline or runs out of gas sends the input back to the vault in the same transaction, so the vault's
   spend always lands and its key always moves on. A failed swap's revert data is copied up to 256 bytes only, so no
   pool can exhaust the refund's gas.

## Standing orders: limit, take-profit, DCA

A trading bot usually holds a key that can move its funds, and that key is not post-quantum. An Ostra vault signs a
standing order once, with its WOTS key, and the input then waits in the order's escrow, which nobody holds a key to:

- The vault's Transfer to the escrow places the order on its own (with `announce`, which publishes the terms).
- A limit or take-profit order is one tranche whose minimum output is the price asked: it fills at that price or
  better, never below. A DCA is several tranches, tranche k from `notBefore + k * interval`, each with its share of the
  amount and of the minimum; a late order catches up at most two tranches per interval, never all at once.
- The executor (the Ostra keeper, or anyone) chooses only when a tranche runs. Every tranche takes the route the order
  binds, so even a stolen executor key can send the funds nowhere but the recipient, the fee and the vault.
- The order's canceller can send what is left back to the vault at any time, and nowhere else; after the deadline
  anyone can.
- The minimum output is the only price an order is held to. A stop below the market needs a price feed, which the
  router does not read.

## Private swaps

An agent that trades in public shows every position it holds and every move it makes. `OstraPrivatePool` keeps
ERC-20 balances as notes: a note is a Poseidon2 commitment to a token, an amount and a tag derived from its owner's
secret key, kept in a commitment tree. Spending a note takes a hash-only STARK (Plonky3, no elliptic curve, no trusted
setup) proving that the note is in the tree, that its nullifier is the one published (each note spends once) and that
its amount is what leaves the note plus the relayer's fee plus a change note; `SpendVerifier` checks it on chain.

- `shield(token, amount, tag)`: anyone deposits a token for a tag; the pool counts what arrived and adds the note.
- `unshield`: spends a note; the amount goes to the recipient the proof names.
- `privateSwap`: spends a note and swaps the amount through `OstraRouter` along the route the proof names, for at
  least its minimum; what the swap pays becomes a new note for the owner.
- The agent pays its gas from its private balance: the relayer the proof names is paid from the note, in the note's
  token, so none of the agent's wallets shows.
- Every proof is bound to its exact call (its token, amount, relayer fee, nullifier, root and change note, and through
  a hash of the call the chain, the pool, the relayer, the deadline and the recipient, or the swap's output token,
  minimum, output tag and route), so a relayer or a front-runner can only send it as it is.

What stays public: the token, the amounts in and out, the pair, the relayer and its fee, the time, and for an
unshield the recipient; Uniswap's pools need the swap in clear. A shield shows the depositor and the amount. What is
hidden: the owner, and which note was spent. The anonymity set starts empty and counts per token, among the notes
under the root a proof uses; amounts are public, so spending exactly an amount just shielded points to that deposit.

Notes go into trees of 2^20 leaves; when one is full the next one starts, and every root any tree has had stays
valid. Tokens whose balances change by themselves (rebasing, fees on transfer) are not supported. A swap's output tag
is public before the swap lands, so anyone can make that swap revert by shielding exactly the note it would add, at
the cost of giving its owner at least the minimum output.

Measured on a mainnet fork: a shield about 2.6M to 3.1M gas, an unshield about 12.7M, a private swap about 15.7M,
each spend plus about 1.2M gas of calldata for its proof.

## Routes

The SDK looks for Uniswap v3 pools at every fee tier and Uniswap v4 pools (from the PoolManager's `Initialize`
events) between each token and each hub, quotes them with Uniswap's QuoterV2 and V4Quoter, and takes the hub whose
route pays the most. A v4 pool is used only with no hook, the Ostra launchpad's hook or the Pons V2 meme hook: an
unknown hook can quote one thing and swap another. Venues other than Uniswap are not routed.

Quotes run in one `eth_call` of `OstraQuoteBatch`'s creation code (nothing is deployed), which gives each quote its
own gas bound: a nearly empty v4 pool burns every bit of gas its quote gets, and in a plain Multicall3 one such pool
took the gas of the whole batch. A quote that fails is tried once more with more gas, as the deepest pools need more
to quote very large sizes, and a v3 quote that stops at the price limit (a pool running dry) is skipped. The router
refuses such a leg too: a leg must spend all of its input, none of it may stay in the Universal Router.

## Build and test

```sh
forge build
(cd privacy && cargo build --release --locked --bin ostra-prove)   # the prover the private pool's tests call
forge test --ffi                # fork tests on Robinhood Chain mainnet (public RPC)
python3 sdk/scripts/abi.py      # sdk/src/abi.ts from the build
cd sdk && npm ci && npm run typecheck
OSTRA_FORK_RPC=<rpc url> node --test test/route.fork.test.ts   # needs anvil
node --test test/private.fork.test.ts                           # needs anvil and the prover built
```

## Security

The contracts were reviewed independently before deployment (two rounds for swaps, three for standing orders), with
every finding proved or disproved on a mainnet fork; the attacks found (a hook's oversized revert data, a fee discount
taken through someone else's account or lent around by changing a lock's accounts, commands chosen by the keeper or by
whoever executes an order, ETH forced into the router, overdue DCA tranches run at once, a pool running dry leaving
input in the Universal Router) are tests in `test/Swap.fork.t.sol` now. The private pool was reviewed independently too
(a full commitment tree freezing every note, now trees that roll over; a lock naming the pool lowering every owner's
fee, now `swapAtBaseFee`), and so were the spend circuit and its verifier ([privacy/README.md](privacy/README.md)).
There has been no paid audit, and nothing in this repository is deployed yet.

## License

MIT
