// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {SpendVerifier} from "../src/SpendVerifier.sol";
import {Notes} from "../src/Notes.sol";

interface Vm {
    function readFileBinary(string calldata path) external view returns (bytes memory);
}

// End-to-end through the agent's prover: test/data/cli_proof.bin and cli_pub.bin are what
// `ostra-prove prove` returned for test/data/cli_request.json, salted from the operating system's
// randomness (a fresh proof every run). The verifier accepts it; its 48 public values are the ones
// the circuit's own functions give for the request (cli_expected_pub.bin: nullifier, root, change
// commitment...), and its binding values are the ones the pool derives from the request's bind_hash.
contract SpendCliTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function testCliProof() public {
        bytes memory p = vm.readFileBinary("test/data/cli_proof.bin");
        bytes memory b = vm.readFileBinary("test/data/cli_pub.bin");
        require(b.length == 192, "48 values");
        uint256[48] memory pv;
        for (uint256 i = 0; i < 48; i++) {
            pv[i] = (uint256(uint8(b[4 * i])) << 24) | (uint256(uint8(b[4 * i + 1])) << 16)
                | (uint256(uint8(b[4 * i + 2])) << 8) | uint256(uint8(b[4 * i + 3]));
        }
        bytes memory e = vm.readFileBinary("test/data/cli_expected_pub.bin");
        for (uint256 i = 0; i < 192; i++) require(b[i] == e[i], "public values differ from the request's");
        uint256[8] memory bind = Notes.bindOf(bytes32(0x5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a));
        for (uint256 i = 0; i < 8; i++) require(pv[40 + i] == bind[i], "binding values differ");
        require(new SpendVerifier().verify(p, pv), "prover output rejected");
    }
}
