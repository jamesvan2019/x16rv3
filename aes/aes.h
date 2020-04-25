
#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <string.h>


typedef uint8_t state_t[4][4];

#if defined __arm__ && __ARMEL__

#define ALIGN128 __attribute__ ((aligned(128)))
#define ALIGN16 __attribute__ ((aligned(16)))
#define ALIGN8 __attribute__ ((aligned(8)))
#define ALIGN4 __attribute__ ((aligned(4)))

#else
#define ALIGN128 
#define ALIGN16 
#define ALIGN8 
#define ALIGN4 
#endif


typedef struct _ur128 {
	uint64_t v0;
	uint64_t v1;
} ur128;

static inline ur128_5xor(ur128 *out, ur128*in0, ur128* in1, ur128* in2, ur128* in3, ur128* in4) {
	out->v0 = in0->v0 ^ in1->v0 ^ in2->v0 ^ in3->v0 ^ in4->v0;
	out->v1 = in0->v1 ^ in1->v1 ^ in2->v1 ^ in3->v1 ^ in4->v1;
}

#define HW_HASH_FUNC_COUNT 16

uint32_t ShiftRows(uint32_t state);
uint32_t SubBytes(uint32_t state);
void ShiftRows_a(uint8_t a[4][4]);
void SubBytes_a(uint8_t a[4][4]);
void MixCol(uint8_t a[4][4]);
//inline void aeskey_gen_soft(uint32_t *in, uint32_t *ou, uint32_t idx);
//inline void shuffle_soft(uint32_t *in, uint32_t *ou, uint8_t idx);
//inline void aes_256_assist1_soft(uint64_t* in1, uint64_t * in2);
//inline void aes_256_assist2_soft(uint64_t* in1, uint64_t * in2);
void aes_expand_key_soft(const uint64_t *key, uint64_t *expandedKey);
void aes_enc_soft(uint64_t *a, uint64_t *b, uint64_t *roundKey);
void aes_pseudo_round_soft(const uint64_t *in, uint64_t *out, uint64_t *expandedKey, int nblocks);
void aes_pseudo_round_xor_soft(const uint64_t *in, uint64_t *out, uint64_t *expandedKey, uint64_t* xor_b, int nblocks);


#endif
