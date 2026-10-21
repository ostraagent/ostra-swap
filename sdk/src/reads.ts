// Reads of OstraStake: the fee an account pays and the lock that sets it.

import { getAddress, type Address, type PublicClient } from "viem";
import { ostraStakeAbi } from "./abi.ts";
import type { SwapDeployment } from "./orders.ts";

export type LockInfo = {
  /** OSTRA locked for the account, summed over the positions naming it (18 decimals). */
  lockedFor: bigint;
  /** The Ostra fee it pays now, in bps of the hub amount. */
  feeBps: number;
};

export type Position = { amount: bigint; unlockAt: bigint; beneficiaries: Address[] };

export async function lockInfo(client: PublicClient, d: SwapDeployment, account: Address): Promise<LockInfo> {
  const a = getAddress(account);
  const [lockedFor, feeBps] = await Promise.all([
    client.readContract({ address: d.stake, abi: ostraStakeAbi, functionName: "lockedFor", args: [a] }) as Promise<bigint>,
    client.readContract({ address: d.stake, abi: ostraStakeAbi, functionName: "feeBps", args: [a] }) as Promise<number>,
  ]);
  return { lockedFor, feeBps: Number(feeBps) };
}

/** The position `locker` holds in OstraStake (amount 0: none). */
export async function positionOf(client: PublicClient, d: SwapDeployment, locker: Address): Promise<Position> {
  const [amount, unlockAt, beneficiaries] = (await client.readContract({ address: d.stake, abi: ostraStakeAbi, functionName: "positionOf", args: [getAddress(locker)] })) as readonly [bigint, number, readonly Address[]];
  return { amount, unlockAt: BigInt(unlockAt), beneficiaries: beneficiaries.map((b) => getAddress(b)) };
}
