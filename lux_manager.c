#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include "monocypher/src/monocypher.h"

// Helper to write bytes as hex
void print_hex(const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

// Generate 32 bytes of High-Entropy Noise using Monocypher's PRNG
// Seeded from /dev/urandom
void generate_volume_key() {
    uint8_t seed[32];
    uint8_t key[32];
    uint8_t zeros[32] = {0}; // Input to encrypt (zeros)
    
    // 1. Get TRNG seed from OS
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) { perror("open urandom"); exit(1); }
    if (read(fd, seed, 32) != 32) { perror("read urandom"); exit(1); }
    close(fd);

    // 2. Expand via ChaCha20 (DJB variant)
    // Encrypting 32 bytes of zeros produces 32 bytes of keystream
    uint8_t nonce[8] = {0};
    crypto_chacha20_djb(key, zeros, 32, seed, nonce, 0);

    // Output RAW bytes for cryptsetup
    fwrite(key, 1, 32, stdout);
}

// Elligator: Generate a "Hidden ID"
// Uses Monocypher's helper to create a keypair where the public key 
// is indistinguishable from random noise.
// If explicit_seed is NULL, uses /dev/urandom.
void generate_hidden_id(const uint8_t *explicit_seed) {
    uint8_t hidden[32];
    uint8_t secret_key[32];
    uint8_t seed[32];

    if (explicit_seed) {
        memcpy(seed, explicit_seed, 32);
    } else {
        // Get random seed
        int fd = open("/dev/urandom", O_RDONLY);
        if (fd < 0) { perror("open urandom"); exit(1); }
        if (read(fd, seed, 32) != 32) { perror("read urandom"); exit(1); }
        close(fd);
    }

    // Generate Keypair and Hidden Public Key (Elligator)
    crypto_elligator_key_pair(hidden, secret_key, seed);

    // Output the HIDDEN public key (looks like random noise)
    // We print Hex for usage in filenames
    print_hex(hidden, 32);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s [gen-key|gen-id|gen-id-from-seed]\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "gen-key") == 0) {
        generate_volume_key();
    } else if (strcmp(argv[1], "gen-id") == 0) {
        generate_hidden_id(NULL);
    } else if (strcmp(argv[1], "gen-id-from-seed") == 0) {
        uint8_t seed[32];
        if (fread(seed, 1, 32, stdin) != 32) {
            fprintf(stderr, "Error: specific seed requires 32 bytes on stdin\n");
            return 1;
        }
        generate_hidden_id(seed);
    } else {
        fprintf(stderr, "Unknown command\n");
        return 1;
    }

    return 0;
}