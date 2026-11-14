# Cryptographic Analysis & Peer-Review Notes

This document outlines the cryptanalytic failures of the early Void Cipher iterations (v1.0 - v3.0) and the security audit fixes applied to the final v4.3 implementation.

## 1. Failure of Information-Theoretic Security (ITS)
**Iteration:** v1.0 & v2.0
**Observation:** The initial design falsely claimed Perfect Secrecy. Shannon's theorem dictates \(H(K) \ge H(M)\). A 64-bit key is insufficient for messages > 8 bytes.

## 2. The Mask Neutralization Flaw
**Iteration:** v1.0
**Observation:** The ciphertext explicitly contained coordinates \((x_i, y_i, z_i)\) and a mask \(m_i\). Under Kerckhoffs's principle, an attacker can compute \(V(x_i,y_i,z_i)\) and recover the plaintext. The spatial mapping provided zero protection.

## 3. The Decorative Q-Block & Entropy Collapse
**Iteration:** v3.0
**Observation:** The Q-Block was public. The implementation evaluated HMAC-SHA256 to extract a single byte per keystream position, discarding 96.875% of cryptographic material. The index reduced the state space to 20 bits.

## 4. Side-Channel Vulnerabilities (Cache-Timing)
**Iteration:** v3.0
**Observation:** The memory access `qBlock[idx]` was data-dependent, exposing the cipher to Prime+Probe attacks.

---

## 5. Security Audit Fixes (v4.0 -> v4.3)
The following 9 critical vulnerabilities were identified during peer review and fixed in v4.3:

1.  **Broken SHA-256 `final` loop:** Fixed the output loop to process all 8 state words correctly, avoiding Undefined Behavior (negative shifts).
2.  **Insecure Nonce:** Replaced `std::random_device` with OS-level CSPRNG (`BCryptGenRandom` / `getrandom`).
3.  **Timing Attack on MAC:** Replaced `==` with `constant_time_compare` using `std::atomic_signal_fence`.
4.  **Key Reuse:** Separated encryption and MAC keys using HMAC labels (`enc` and `mac`).
5.  **Counter Overflow:** Upgraded from 32-bit to 64-bit counter.
6.  **Endianness:** Forced Big-Endian formatting for the counter.
7.  **UB in Transform:** Cast `uint8_t` to `uint32_t` before bit-shifting to prevent signed integer overflow.
8.  **Missing Test Vectors:** Added NIST SHA-256 and RFC 4231 HMAC test vectors to `main`.
9.  **Memory Leaks:** Added `secure_clear()` to wipe keys from RAM after use.
