# Void Cipher Chronicles: A Cryptographic Retrospective

## 📖 Overview
This repository documents the complete lifecycle of the "Void Cipher" project, an independent cryptographic research effort conducted at Sirte University. 

What began as a naive attempt to build a post-quantum cipher using spatial mapping evolved through multiple iterations. Through rigorous cryptanalysis—including Shannon entropy analysis, IND-CPA reduction failures, and side-channel threat modeling—the spatial architecture was proven to be cryptographically vacuous and highly inefficient.

This project serves as a pedagogical case study in cryptographic engineering, culminating in a formal self-critique and a redesigned, standardized AEAD architecture (**v4.3**) built entirely from scratch in C++.

## 🗂️ Repository Structure
*   **`Void_Cipher_Report.tex`**: The complete academic retrospective (LaTeX source), including mathematical proofs of failure and the final v4.3 architecture.
*   **`void_cipher_v4.3.cpp`**: The final hardened C++ implementation (Educational AEAD) featuring OS-level CSPRNG, constant-time MAC verification, and secure memory wiping.
*   **`Cryptanalysis_Notes.md`**: Detailed peer-review notes and the 9 critical vulnerabilities fixed during the audit of v4.0.

## 🧠 The Cryptographic Journey
1.  **v1.0 (Spatial Mapper)**: Failed due to "Mask Neutralization" (transmitting coordinates leaked the plaintext).
2.  **v2.0 (ITS Illusion)**: Failed due to invalid Shannon entropy bounds (64-bit key).
3.  **v3.0 (Q-Block Stream Cipher)**: Decorative architecture. Introduced side-channel vulnerabilities and massive computational waste (97%).
4.  **v4.3 (Final Educational AEAD)**: Abandoned spatial metaphors. Implemented standard primitives (HMAC-SHA256 in CTR mode) with Encrypt-then-MAC, OS CSPRNG, and constant-time operations.

## 🚀 How to Compile and Run
Navigate to the repository root and compile the C++ file using `g++` (or MSVC):
```bash
g++ -std=c++17 -O3 void_cipher_v4.3.cpp -o void_cipher
./void_cipher
