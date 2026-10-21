// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

/// @title OstraQuoteBatch
/// @notice Never deployed. The SDK runs its creation code in an eth_call without a `to`, and what the constructor
///         returns is the answer: abi.encode(Result[]), one per call. Each call gets at most `gasPerCall` gas, so a
///         quote through a pool that burns all the gas it is given (a nearly empty Uniswap v4 pool, crossing tick
///         after tick) fails cheaply on its own. With Multicall3, which forwards all its gas, one such quote took
///         the gas of the whole batch: 39 quotes of ETH to USDG needed more than the RPC's 50,000,000 gas cap
///         (measured on chain 4663, 20 Oct 2026). At most MAX_RETURN bytes of each answer are kept, so the answer
///         stays far below the 24,576-byte code size limit.
contract OstraQuoteBatch {
    /// @notice The most bytes kept of a call's return data: a QuoterV2 quote returns 128, a V4Quoter quote 64.
    uint256 public constant MAX_RETURN = 128;

    struct Result {
        bool success;
        bytes returnData;
    }

    error LengthMismatch();

    constructor(address[] memory targets, bytes[] memory data, uint256 gasPerCall) {
        uint256 n = targets.length;
        if (data.length != n) revert LengthMismatch();
        Result[] memory results = new Result[](n);
        for (uint256 i; i < n; i++) {
            address target = targets[i];
            bytes memory callData = data[i];
            bool ok;
            bytes memory ret;
            assembly ("memory-safe") {
                ok := call(gasPerCall, target, 0, add(callData, 0x20), mload(callData), 0, 0)
                let size := returndatasize()
                if gt(size, 128) { size := 128 }
                ret := mload(0x40)
                mstore(ret, size)
                returndatacopy(add(ret, 0x20), 0, size)
                mstore(0x40, add(add(ret, 0x20), and(add(size, 31), not(31))))
            }
            results[i] = Result(ok, ret);
        }
        bytes memory out = abi.encode(results);
        assembly ("memory-safe") {
            return(add(out, 0x20), mload(out))
        }
    }
}
