# Cryptographic Analysis & Peer-Review Notes

This document outlines the cryptanalytic failures of the early Void Cipher iterations (v1.0 - v3.0) and the mathematical proofs of their insecurity.

## 1. Failure of Information-Theoretic Security (ITS)
**Iteration:** v1.0 & v2.0
**Observation:** The initial design falsely claimed Perfect Secrecy.
**Proof:** Shannon's theorem dictates that \(H(K) \ge H(M)\). The v2.0 implementation utilized a 64-bit key. For any message exceeding 8 bytes, the key entropy is strictly less than the message entropy. Therefore, Information-Theoretic Security is mathematically impossible.

## 2. The Mask Neutralization Flaw (Coordinate Leakage)
**Iteration:** v1.0
**Observation:** The ciphertext explicitly contained coordinates \((x_i, y_i, z_i)\) and a mask \(m_i\).
**Proof:** Under Kerckhoffs's principle, the Void function \(V\) is public. An attacker intercepts \(C_i = (V(x_i,y_i,z_i) \oplus m_i, \; x_i, \; y_i, \; z_i)\). The attacker can instantly compute \(V(x_i,y_i,z_i)\) using the coordinates and recover the plaintext \(P_i\) via a single XOR operation. The spatial mapping provided zero cryptographic protection.

## 3. The Decorative Q-Block & Entropy Collapse
**Iteration:** v3.0
**Observation:** The Q-Block was publicly broadcast, meaning the security relied entirely on the HMAC.
**Proof:** 
- **Computational Waste:** The implementation evaluated HMAC-SHA256 (256-bit output) to extract a single byte per keystream position. It discarded 248 of 256 bits (96.875% waste).
- **Entropy Collapse:** The index \(idx = (x \oplus y \oplus z) \bmod blockSize\) reduced the spatial state space to 20 bits (for a 1MB block). By the data processing inequality, the effective entropy per byte was capped, discarding 236 bits of cryptographic randomness at every step.

## 4. Side-Channel Vulnerabilities (Cache-Timing)
**Iteration:** v3.0
**Observation:** The memory access `qBlock[idx]` was data-dependent.
**Proof:** Because `idx` is derived from the secret key and nonce, an attacker can execute a Prime+Probe attack. In an idealized model, each access leaks at most \(\log_2(512) = 9\) bits. Recovering the 20-bit index requires as few as \(\lceil 20/9 \rceil \approx 3\) traceable accesses.

## 5. IND-CPA Reduction Failure
**Iteration:** v3.0
**Observation:** The reduction proof failed because it implied the Q-Block is a public, deterministic table. The cipher is structurally equivalent to a simple counter-mode generator, rendering the positional architecture mathematically redundant.

---
## Conclusion
The positional architecture was formally abandoned. Future code (v4.0) strictly adheres to standardized AEAD primitives (e.g., BLAKE3 + Poly1305) with 256-bit keys and 128-bit nonces.
