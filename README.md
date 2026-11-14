# Void Cipher: A Cryptographic Retrospective

## Overview
This repository documents the complete lifecycle of the "Void Cipher" research project. What began as an attempt to build a post-quantum cipher using spatial mapping evolved through three major iterations. Through rigorous cryptanalysis, the spatial architecture was proven to be cryptographically vacuous and highly inefficient.

This repository contains the final technical report (LaTeX) and the redesigned v4.0 architecture (C++) that abandons the spatial metaphor in favor of standardized AEAD primitives.

## Repository Contents
*   **`Void_Cipher_Report.tex`**: The complete academic retrospective, including Shannon entropy analysis, IND-CPA reduction failures, and side-channel threat modeling.
*   **`void_cipher.cpp`**: The future v4.0 codebase, demonstrating a secure, standardized approach using 256-bit keys and 128-bit nonces.

## Lessons Learned
1.  **Spatial obfuscation is not encryption**: Masking data visually does not equate to mathematical confidentiality.
2.  **Entropy matters**: Discarding 248 out of 256 bits from a PRF output severely degrades security.
3.  **Side-channels are real**: Data-dependent memory access (e.g., `qBlock[idx]`) leaks secrets via cache-timing.
4.  **Use standards**: Algorithms like ChaCha20 and AES-GCM have survived decades of global cryptanalysis.

## Author
**Abdalmlk Abdalbaset Saleh**
*   Department of Information Technology, Sirte University
*   Contact: Abdulmalik55012@su.edu.ly
