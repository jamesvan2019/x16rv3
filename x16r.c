/**
 * x16rv3 algo implementation
 *
 */
#include "x16r.h"
#include "aes/aes.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "algo/sph_blake.h"
#include "algo/sph_bmw.h"
#include "algo/sph_groestl.h"
#include "algo/sph_jh.h"
#include "algo/sph_keccak.h"
#include "algo/sph_skein.h"
#include "algo/sph_luffa.h"
#include "algo/sph_cubehash.h"
#include "algo/sph_shavite.h"
#include "algo/sph_simd.h"
#include "algo/sph_echo.h"
#include "algo/sph_hamsi.h"
#include "algo/sph_fugue.h"
#include "algo/sph_shabal.h"
#include "algo/sph_whirlpool.h"
#include "algo/sph_sha2.h"


enum Algo {
	BLAKE = 0,
	BMW,
	GROESTL,
	JH,
	KECCAK,
	SKEIN,
	LUFFA,
	CUBEHASH,
	SHAVITE,
	SIMD,
	ECHO,
	HAMSI,
	FUGUE,
	SHABAL,
	WHIRLPOOL,
	SHA512,
	HASH_FUNC_COUNT
};

static  char x16rv3_hashOrder[HASH_FUNC_COUNT + 1] = { 0 };


static inline  void get_x16rv3_order(const void* input,  void* output_hash,void* output_order)
{
	uint64_t expandedKey[24];
	uint32_t  endiandata[32] = {0};
    uint32_t * r = (uint32_t *) input;
	memcpy(endiandata, input, 113);
	aes_expand_key_soft((uint64_t*)(endiandata+1), (uint64_t*)expandedKey);
	uint8_t* porder = (uint8_t*) output_order;
	ur128 *ek = expandedKey;
	ur128 *data_in = (ur128 *)endiandata;
	ur128 aesdata[12];
	ur128 xor_out;
	uint8_t* ptemp = (uint8_t*)&(aesdata[6]);

	aes_enc_soft(aesdata + 0, data_in + 0, ek + 0);
	aes_enc_soft(aesdata + 1, data_in + 1, ek + 1);
	aes_enc_soft(aesdata + 2, data_in + 2, ek + 2);
	aes_enc_soft(aesdata + 3, data_in + 3, ek + 3);
	aes_enc_soft(aesdata + 4, data_in + 4, ek + 4);
	aes_enc_soft(aesdata + 5, data_in + 5, ek + 5);
	aes_enc_soft(aesdata + 6, data_in + 6, ek + 6);
	aes_enc_soft(aesdata + 7, data_in + 7, ek + 7);

	ur128_5xor(&xor_out, aesdata+4, aesdata+5, aesdata+6, aesdata+7, aesdata+0);
	aes_enc_soft(aesdata + 8, &xor_out, ek + 8);
	ur128_5xor(&xor_out, aesdata+4, aesdata+5, aesdata+6, aesdata+7, aesdata+1);
	aes_enc_soft(aesdata + 9, &xor_out, ek + 9);
	ur128_5xor(&xor_out, aesdata+4, aesdata+5, aesdata+6, aesdata+7, aesdata+2);
	aes_enc_soft(aesdata + 10, &xor_out, ek + 10);
	ur128_5xor(&xor_out, aesdata+4, aesdata+5, aesdata+6, aesdata+7, aesdata+3);
	aes_enc_soft(aesdata + 11, &xor_out, ek + 11);
	memcpy(output_hash,&(aesdata[8]),64);

	for(int j=0;j<16;j++)
	{
		porder[j] = ptemp[j]&0x0f;
	}
}

void x16r_hash(const void* input, void* output)
{
	uint32_t  hash[64/4];

	sph_blake512_context     ctx_blake;
	sph_bmw512_context       ctx_bmw;
	sph_groestl512_context   ctx_groestl;
	sph_skein512_context     ctx_skein;
	sph_jh512_context        ctx_jh;
	sph_keccak512_context    ctx_keccak;
	sph_luffa512_context     ctx_luffa;
	sph_cubehash512_context  ctx_cubehash;
	sph_shavite512_context   ctx_shavite;
	sph_simd512_context      ctx_simd;
	sph_echo512_context      ctx_echo;
	sph_hamsi512_context     ctx_hamsi;
	sph_fugue512_context     ctx_fugue;
	sph_shabal512_context    ctx_shabal;
	sph_whirlpool_context    ctx_whirlpool;
	sph_sha512_context       ctx_sha512;
	int size;
	void *in = (void*) input;
	get_x16rv3_order(in,(void*)hash,(void*)x16rv3_hashOrder);

	in = (void*)hash;
	size = 64;

	for (int i = 0; i < 16; i++)
	{
		const uint8_t algo = x16rv3_hashOrder[i];
		switch (algo) {
		case BLAKE:
			sph_blake512_init(&ctx_blake);
			sph_blake512(&ctx_blake, in, size);
			sph_blake512_close(&ctx_blake, hash);

			break;
		case BMW:
			sph_bmw512_init(&ctx_bmw);
			sph_bmw512(&ctx_bmw, in, size);
			sph_bmw512_close(&ctx_bmw, hash);
			break;
		case GROESTL:
			sph_groestl512_init(&ctx_groestl);
			sph_groestl512(&ctx_groestl, in, size);
			sph_groestl512_close(&ctx_groestl, hash);
			break;
		case SKEIN:
			sph_skein512_init(&ctx_skein);
			sph_skein512(&ctx_skein, in, size);
			sph_skein512_close(&ctx_skein, hash);
			break;
		case JH:
			sph_jh512_init(&ctx_jh);
			sph_jh512(&ctx_jh, in, size);
			sph_jh512_close(&ctx_jh, hash);
			break;
		case KECCAK:
			sph_keccak512_init(&ctx_keccak);
			sph_keccak512(&ctx_keccak, (const void*) in, size);
			sph_keccak512_close(&ctx_keccak, hash);
			break;
		case LUFFA:
			sph_luffa512_init(&ctx_luffa);
			sph_luffa512(&ctx_luffa, in, size);
			sph_luffa512_close(&ctx_luffa, hash);
			break;
		case CUBEHASH:
			sph_cubehash512_init(&ctx_cubehash);
			sph_cubehash512(&ctx_cubehash, in, size);
			sph_cubehash512_close(&ctx_cubehash, hash);
			break;
		case SHAVITE:
			sph_shavite512_init(&ctx_shavite);
			sph_shavite512(&ctx_shavite, in, size);
			sph_shavite512_close(&ctx_shavite, hash);
			break;
		case SIMD:
			sph_simd512_init(&ctx_simd);
			sph_simd512(&ctx_simd, in, size);
			sph_simd512_close(&ctx_simd, hash);
			break;
		case ECHO:
			sph_echo512_init(&ctx_echo);
			sph_echo512(&ctx_echo, in, size);
			sph_echo512_close(&ctx_echo, hash);
			break;
		case HAMSI:
			sph_hamsi512_init(&ctx_hamsi);
			sph_hamsi512(&ctx_hamsi, in, size);
			sph_hamsi512_close(&ctx_hamsi, hash);
			break;
		case FUGUE:
			sph_fugue512_init(&ctx_fugue);
			sph_fugue512(&ctx_fugue, in, size);
			sph_fugue512_close(&ctx_fugue, hash);
			break;
		case SHABAL:
			sph_shabal512_init(&ctx_shabal);
			sph_shabal512(&ctx_shabal, in, size);
			sph_shabal512_close(&ctx_shabal, hash);
			break;
		case WHIRLPOOL:
			sph_whirlpool_init(&ctx_whirlpool);
			sph_whirlpool(&ctx_whirlpool, in, size);
			sph_whirlpool_close(&ctx_whirlpool, hash);
			break;
		case SHA512:
			sph_sha512_init(&ctx_sha512);
			sph_sha512(&ctx_sha512,(const void*) in, size);
			sph_sha512_close(&ctx_sha512,(void*) hash);
			break;
		}
	}
		for(int j=0;j<8;j++)
            {
            	printf("%08x",hash[j]);
            }
            printf("\n");
	memcpy(output, hash, 32);
}