#ifndef KRYPTOHASH_H
#define KRYPTOHASH_H

#include "sha3/sha3.h"

#define KSHAKE320_L       (320)  // Length in bits
#define KPOW_MUL          (546)  // How many Keccak blocks the PoW contains
#define KRATE             (KSHAKE320_R / 8)  // Keccak rate in bytes
#define KPROOF_OF_WORK_SZ (KPOW_MUL*KRATE)  // KryptoHash Proof of Work Block Size in bytes

struct uint320
{
    unsigned char v[40];
};
typedef struct uint320 uint320;


#endif