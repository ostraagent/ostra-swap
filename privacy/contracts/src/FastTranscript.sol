// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// The Fiat-Shamir transcript of Transcript.sol (SerializingChallenger32 over HashChallenger<u8,
// Keccak256Hash, 32>, Plonky3 0.8.0) with word-wide copies instead of byte loops, for the verifier.
// Observed bytes accumulate in a fixed buffer; a sample hashes the buffer with KECCAK256, the digest
// becomes the buffer, and samples pop bytes from the end of the digest. Field elements are absorbed in
// Montgomery form (canonical * 2^32 mod P) as 4 little-endian bytes; samples are canonical.
// Extension elements are packed as in KB8 (coefficient i in bits [32 i, 32 i + 32)) and absorbed or
// sampled coefficient 0 first.
library FastTranscript {
    uint256 internal constant P = 2130706433;
    // Larger than any absorb run between two samples of the spend verifier: the PCS claims, 544
    // extension elements (17,408 bytes) after the PCS seed.
    uint256 internal constant CAPACITY = 24576;

    struct State {
        uint256 buf; // memory address of the first buffer byte
        uint256 len;
        uint256 out;
        uint256 rem;
    }

    function init() internal pure returns (State memory s) {
        // 32 bytes of slack: whole-word stores may write up to 31 bytes past the end of the data.
        bytes memory b = new bytes(CAPACITY + 32);
        uint256 p;
        assembly {
            p := add(b, 32)
        }
        s.buf = p;
    }

    function reserve(State memory s, uint256 n) private pure returns (uint256 dst) {
        require(s.len + n <= CAPACITY, "transcript buffer full");
        dst = s.buf + s.len;
        s.len += n;
        s.rem = 0;
    }

    function observeMemory(State memory s, bytes memory data) internal pure {
        uint256 n = data.length;
        if (n == 0) return;
        uint256 dst = reserve(s, n);
        assembly {
            let src := add(data, 32)
            for { let i := 0 } lt(i, n) { i := add(i, 32) } {
                mstore(add(dst, i), mload(add(src, i)))
            }
        }
    }

    function observeCalldata(State memory s, uint256 offset, uint256 n) internal pure {
        if (n == 0) return;
        uint256 dst = reserve(s, n);
        assembly {
            calldatacopy(dst, offset, n)
        }
    }

    // Montgomery form of a canonical element as a 4-byte little-endian word, left-aligned.
    function montWord(uint256 v) private pure returns (uint256 w) {
        assembly {
            let m := mulmod(v, 33554430, 2130706433)
            w := or(or(shl(248, and(m, 0xff)), shl(240, and(shr(8, m), 0xff))), or(shl(232, and(shr(16, m), 0xff)), shl(224, shr(24, m))))
        }
    }

    function observeField(State memory s, uint256 v) internal pure {
        require(v < P, "non-canonical field element");
        uint256 dst = reserve(s, 4);
        uint256 w = montWord(v);
        assembly {
            mstore(dst, w)
        }
    }

    // Coefficients 0..7 of a packed extension element, each as 4 Montgomery little-endian bytes: the
    // Montgomery form per lane, then the whole word byte-reversed (lane order and byte order at once).
    // False, absorbing nothing, when a coefficient is not canonical (lane >= P sets bit 32 of
    // lane + 2^32 - P in a 64-bit field).
    function observeExt(State memory s, uint256 e) internal pure returns (bool ok) {
        assembly {
            ok := iszero(and(or(add(and(e, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff), 0x0000000080ffffff0000000080ffffff0000000080ffffff0000000080ffffff), add(and(shr(32, e), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff), 0x0000000080ffffff0000000080ffffff0000000080ffffff0000000080ffffff)), 0x0000000100000000000000010000000000000001000000000000000100000000))
        }
        if (!ok) return false;
        uint256 dst = reserve(s, 32);
        assembly {
            let m := mulmod(and(e, 0xffffffff), 33554430, 2130706433)
            m := or(m, shl(32, mulmod(and(shr(32, e), 0xffffffff), 33554430, 2130706433)))
            m := or(m, shl(64, mulmod(and(shr(64, e), 0xffffffff), 33554430, 2130706433)))
            m := or(m, shl(96, mulmod(and(shr(96, e), 0xffffffff), 33554430, 2130706433)))
            m := or(m, shl(128, mulmod(and(shr(128, e), 0xffffffff), 33554430, 2130706433)))
            m := or(m, shl(160, mulmod(and(shr(160, e), 0xffffffff), 33554430, 2130706433)))
            m := or(m, shl(192, mulmod(and(shr(192, e), 0xffffffff), 33554430, 2130706433)))
            m := or(m, shl(224, mulmod(and(shr(224, e), 0xffffffff), 33554430, 2130706433)))
            m := or(shl(8, and(m, 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff)), and(shr(8, m), 0x00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff))
            m := or(shl(16, and(m, 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff)), and(shr(16, m), 0x0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff0000ffff))
            m := or(shl(32, and(m, 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff)), and(shr(32, m), 0x00000000ffffffff00000000ffffffff00000000ffffffff00000000ffffffff))
            m := or(shl(64, and(m, 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff)), and(shr(64, m), 0x0000000000000000ffffffffffffffff0000000000000000ffffffffffffffff))
            m := or(shl(128, m), shr(128, m))
            mstore(dst, m)
        }
    }

    function flush(State memory s) private pure {
        uint256 p = s.buf;
        uint256 n = s.len;
        uint256 d;
        assembly {
            d := keccak256(p, n)
            mstore(p, d)
        }
        s.len = 32;
        s.out = d;
        s.rem = 32;
    }

    function sampleByte(State memory s) internal pure returns (uint256 b) {
        if (s.rem == 0) flush(s);
        s.rem -= 1;
        uint256 r = s.rem;
        uint256 o = s.out;
        assembly {
            b := byte(r, o)
        }
    }

    function sampleU32(State memory s) internal pure returns (uint256 v) {
        v = sampleByte(s);
        v |= sampleByte(s) << 8;
        v |= sampleByte(s) << 16;
        v |= sampleByte(s) << 24;
    }

    function sampleBase(State memory s) internal pure returns (uint256 v) {
        do {
            v = sampleU32(s) & 0x7FFFFFFF;
        } while (v >= P);
    }

    function sampleExt(State memory s) internal pure returns (uint256 e) {
        for (uint256 i = 0; i < 8; i++) {
            e |= sampleBase(s) << (32 * i);
        }
    }

    function sampleBits(State memory s, uint256 bits) internal pure returns (uint256) {
        require(bits < 31, "bit count out of range");
        return sampleU32(s) & ((1 << bits) - 1);
    }

    // SerializingChallenger32::check_witness: squeeze one byte, observe the witness, then the next
    // `bits` sampled bits must be zero. Zero bits accepts without touching the transcript.
    function checkWitness(State memory s, uint256 bits, uint256 w) internal pure returns (bool) {
        if (bits == 0) return true;
        sampleByte(s);
        observeField(s, w);
        return sampleBits(s, bits) == 0;
    }
}
