#include <iostream>
#include <vector>
#include <cstdint>

// ============================================================================
// LEGACY CODE: Void Cipher v1.0 (FLAWED ARCHITECTURE)
// ============================================================================
// WARNING: This code is mathematically insecure and is provided ONLY for 
// historical and educational purposes to demonstrate the "Mask Neutralization" 
// vulnerability.
// ============================================================================

uint8_t get_void_cell(uint32_t x, uint32_t y, uint32_t z) {
    // Simplified pseudo-hash for demonstration
    return (x ^ y ^ z) & 0xFF; 
}

void encrypt_v1_flawed(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& ciphertext) {
    uint64_t dfk = 0x12345678; // 64-bit key (Too short for ITS)
    
    for (size_t i = 0; i < plaintext.size(); ++i) {
        // 1. Generate coordinates
        uint32_t x = (dfk * 7 + i * 13) & 0xFFFFFF;
        uint32_t y = (dfk * 11 + i * 17) & 0xFFFFFF;
        uint32_t z = (dfk * 13 + i * 19) & 0xFFFFFF;
        
        uint8_t void_val = get_void_cell(x, y, z);
        uint8_t mask = void_val ^ plaintext[i];
        
        // 2. The Fatal Flaw: Transmitting the coordinates explicitly!
        // An attacker can compute get_void_cell(x,y,z) and recover the plaintext.
        ciphertext.push_back(x);
        ciphertext.push_back(y);
        ciphertext.push_back(z);
        ciphertext.push_back(mask);
    }
}

int main() {
    std::cout << "Legacy Void Cipher v1.0 (Flawed)\n";
    std::cout << "Warning: Coordinates are explicitly leaked.\n";
    
    std::vector<uint8_t> plaintext = {'T', 'E', 'S', 'T'};
    std::vector<uint8_t> ciphertext;
    
    encrypt_v1_flawed(plaintext, ciphertext);
    
    std::cout << "Ciphertext size (1000% expansion): " << ciphertext.size() << " bytes\n";
    return 0;
}
