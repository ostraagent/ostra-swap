// Robinhood Chain facts Ostra Swap relies on (design v0.4, "Ostra Swap", decided 20 Oct 2026). Every address was
// read on chain 4663 on 20 Oct 2026: the Uniswap ones from Uniswap's Robinhood Chain deployments page and the
// Universal Router's own immutables (its v3 factory), OSTRA and its Pons bonding curve from OSTRA's transfers and
// buy transactions. The fork tests check them again on every run.

import type { Address } from "viem";

export const ROBINHOOD_CHAIN_ID = 4663;
/** The public RPC: it serves eth_getLogs over up to 10,000,000 blocks per request (rate limited). */
export const ROBINHOOD_PUBLIC_RPC = "https://rpc.mainnet.chain.robinhood.com";
/** Blocks one eth_getLogs request spans on the public RPC. */
export const LOG_WINDOW_BLOCKS = 10_000_000n;

export const USDG: Address = "0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168";
export const WETH: Address = "0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73";
/** The hubs a swap goes through: the Ostra fee is taken in the hub, between the two legs. */
export const HUBS = [USDG, WETH] as const;
/** Native ETH, as a currency (Uniswap v4) and as tokenIn/tokenOut of a wallet swap. */
export const ETH: Address = "0x0000000000000000000000000000000000000000";

export const UNIVERSAL_ROUTER: Address = "0x8876789976dEcBfCbBbe364623C63652db8C0904";
export const UNISWAP_V3_FACTORY: Address = "0x1f7d7550B1b028f7571E69A784071F0205FD2EfA";
export const UNISWAP_V3_QUOTER_V2: Address = "0x33e885eD0Ec9bF04EcfB19341582aADCb4c8A9E7";
/** The fee tiers a Uniswap v3 pool is looked up at (hundredths of a bip). */
export const V3_FEE_TIERS = [100, 500, 3_000, 10_000] as const;
export const UNISWAP_V4_POOL_MANAGER: Address = "0x8366a39CC670B4001A1121B8F6A443A643e40951";
export const UNISWAP_V4_QUOTER: Address = "0x8Dc178eFB8111BB0973Dd9d722ebeFF267c98F94";
export const MULTICALL3: Address = "0xcA11bde05977b3631167028862bE2a173976CA11";

/**
 * The v4 hooks a route may go through (independent review, 20 Oct 2026): none, the Ostra launchpad's hook, and
 * the Pons V2 meme hook (Pons graduates its tokens to native ETH / token pools with it, fee 0, tick spacing 200).
 * A pool with any other hook is left out: an unknown hook can quote one thing and swap another.
 */
export const OSTRA_HOOK: Address = "0x63A784afb8905452aDceC471a45E555F5caE68cC";
export const PONS_HOOK: Address = "0xE5e702641Ea86F4ae6cC3cDaeD2B886f976Be044";
export const ROUTABLE_HOOKS: readonly Address[] = ["0x0000000000000000000000000000000000000000", OSTRA_HOOK, PONS_HOOK];

/** $OSTRA (Ostra Agent, 18 decimals, 1,000,000,000 supply). */
export const OSTRA: Address = "0x68Ff81dFFF6eccefb74706fE1e0a86320CB2Eb96";
/** OSTRA's Pons V2 bonding curve (one per token): buy(ethIn, minOut, recipient) payable, until OSTRA graduates. */
export const OSTRA_PONS_CURVE: Address = "0xef89C3a9832Ae6f8Dc5F785484b1B5cb1120F372";
/** Where Ostra's burns go. */
export const BURN_ADDRESS: Address = "0x000000000000000000000000000000000000dEaD";
/** The treasury the other half of every Ostra Swap fee goes to (the same as OstraPool's). */
export const TREASURY: Address = "0x6569E27A95a6A3E92A311B4Cc6600fed56aA50A2";

/**
 * OstraStake's fee tiers (src/OstraStake.sol): the Ostra fee in bps of the hub amount by the OSTRA locked for
 * an account, locked LOCK_DAYS days from the last lock.
 */
export const FEE_TIERS = [
  { minLocked: 500_000n * 10n ** 18n, bps: 0 },
  { minLocked: 250_000n * 10n ** 18n, bps: 10 },
  { minLocked: 100_000n * 10n ** 18n, bps: 15 },
  { minLocked: 0n, bps: 20 },
] as const;
export const LOCK_DAYS = 7;

/** Universal Router commands (Commands.sol) and v4-periphery actions (Actions.sol) the legs use. */
export const COMMAND = { V3_SWAP_EXACT_IN: 0x00, UNWRAP_WETH: 0x0c, V4_SWAP: 0x10 } as const;
export const V4_ACTION = { SWAP_EXACT_IN_SINGLE: 0x06, SETTLE: 0x0b, TAKE: 0x0e } as const;
/** ActionConstants: spend the router's whole balance; pay the router's caller; the router itself; the full delta. */
export const CONTRACT_BALANCE = 1n << 255n;
export const MSG_SENDER: Address = "0x0000000000000000000000000000000000000001";
export const ADDRESS_THIS: Address = "0x0000000000000000000000000000000000000002";
export const OPEN_DELTA = 0n;

/**
 * The gas one quote gets (OstraQuoteBatch), in two passes. Measured on chain 4663 on 20 Oct 2026: nearly empty v4
 * pools burn all the gas they get (one used 5,219,895 gas to quote 45,365 USDG units for 1 ETH), while real quotes
 * used 69,000 to 371,000 gas up to 50 ETH or 100,000 USDG, and the deepest pools need more for very large sizes
 * (1,357,854 gas for 1,000,000 USDG to NVDA on v3, 2,446,000 for 1,000,000 USDG to TSLA on v4; independent
 * review). Every pool is quoted with QUOTE_GAS_LIMIT first, QUOTES_PER_CALL per eth_call; the ones that failed are
 * quoted again with QUOTE_GAS_LIMIT_RETRY, QUOTES_PER_RETRY_CALL per eth_call. Each eth_call (at most 26,000,000
 * gas) stays below the RPC's eth_call gas cap (50,000,000 on the public RPC).
 */
export const QUOTE_GAS_LIMIT = 500_000n;
export const QUOTES_PER_CALL = 16;
export const QUOTE_GAS_LIMIT_RETRY = 3_000_000n;
export const QUOTES_PER_RETRY_CALL = 8;
/** Gas an OstraQuoteBatch eth_call gets on top of its calls' (its loop, memory and the answer it returns). */
export const QUOTE_BATCH_OVERHEAD_GAS = 2_000_000n;
/** Uniswap v3 TickMath.MIN_SQRT_RATIO + 1 and MAX_SQRT_RATIO - 1: the price QuoterV2 stops at when a pool runs dry. */
export const V3_MIN_SQRT_PRICE_LIMIT = 4295128740n;
export const V3_MAX_SQRT_PRICE_LIMIT = 1461446703485210103287273052203988822378723970341n;

/** OstraRouter.REFUND_GAS_RESERVE: gas an escrow keeps back for its refund. */
export const REFUND_GAS_RESERVE = 120_000n;
/** OstraStake.MAX_BENEFICIARIES: the most accounts one lock counts for. */
export const MAX_LOCK_BENEFICIARIES = 8;
/** Default slippage of a quote, and the largest allowed, in bps. */
export const DEFAULT_SLIPPAGE_BPS = 100;
export const MAX_SLIPPAGE_BPS = 1_000;
/** How long an escrow order stays executable by default: 10 minutes. */
export const DEFAULT_ORDER_TTL_SECONDS = 600;
