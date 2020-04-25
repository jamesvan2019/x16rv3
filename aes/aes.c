#include <stdio.h>
#include <stdlib.h>
//#include <unistd.h>
//#include <io.h>
//#include <process.h>


#include <stddef.h>
#include "aes.h"




const uint8_t sbox[256] = { 0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
                                    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
                                    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
                                    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
                                    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
                                    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
                                    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
                                    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
                                    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
                                    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
                                    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
                                    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
                                    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
                                    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
                                    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
                                    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

const uint8_t Inv_Subbytes[256] = {  0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                                         0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                                         0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                                         0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                                         0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                                         0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                                         0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                                         0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                                         0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                                         0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                                         0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                                         0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                                         0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                                         0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                                         0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                                         0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};




#define getSBoxValue(num) (sbox[(num)])

state_t tmp;
uint32_t ShiftRows(uint32_t state)
{
  uint8_t *src, *dst;
  uint32_t res;

  src = (uint8_t*)&state;
  dst = (uint8_t*)&res;
  // Rotate first row 1 columns to left
  for (uint8_t i=0, j=1;i<3;i++,j++)
	  *(dst+i) = *(src+j);
  *(dst+3) = *src;

  return res;
}

uint32_t SubBytes(uint32_t state)
{
  uint32_t res;
  uint8_t *src, *dst;
  src = (uint8_t*)&state;
  dst = (uint8_t*)&res;
  for (uint8_t i = 0; i < 4; ++i)
  {
     *(dst+i) = getSBoxValue(*(src+i));
  }
  return res;
}



void ShiftRows_a(uint8_t state[4][4])
{
  uint8_t temp;


  // Rotate first row 1 columns to left
  temp           = state[0][1];
  state[0][1] = state[1][1];
  state[1][1] = state[2][1];
  state[2][1] = state[3][1];
  state[3][1] = temp;

  // Rotate second row 2 columns to left
  temp           = state[0][2];
  state[0][2] = state[2][2];
  state[2][2] = temp;

  temp           = state[1][2];
  state[1][2] = state[3][2];
  state[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = state[0][3];
  state[0][3] = state[3][3];
  state[3][3] = state[2][3];
  state[2][3] = state[1][3];
  state[1][3] = temp;
}

void SubBytes_a(uint8_t state[4][4])
{
  uint8_t i, j;
  for (i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      state[j][i] = getSBoxValue(state[j][i]);
    }
  }
}

static inline uint8_t xtime(uint8_t x)
{
  return ((x<<1) ^ (((x>>7) & 1) * 0x1b));
}

void MixCol(uint8_t state[4][4])
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {
    t   = state[i][0];
    Tmp = state[i][0] ^ state[i][1] ^ state[i][2] ^ state[i][3] ;
    Tm  = state[i][0] ^ state[i][1] ; Tm = xtime(Tm);  state[i][0] ^= Tm ^ Tmp ;
    Tm  = state[i][1] ^ state[i][2] ; Tm = xtime(Tm);  state[i][1] ^= Tm ^ Tmp ;
    Tm  = state[i][2] ^ state[i][3] ; Tm = xtime(Tm);  state[i][2] ^= Tm ^ Tmp ;
    Tm  = state[i][3] ^ t ;              Tm = xtime(Tm);  state[i][3] ^= Tm ^ Tmp ;
  }
}



//_mm_aeskeygenassist_si128
static inline void aeskey_gen_soft(uint32_t *in, uint32_t *ou, uint32_t idx)
{
	uint32_t l0 = SubBytes(in[1]);
	uint32_t l1 = ShiftRows(l0);
	l1 ^= idx;

	uint32_t h0 = SubBytes(in[3]);
	uint32_t h1 = ShiftRows(h0);
	h1 ^= idx;

	ou[0] = l0;
	ou[1] = l1;
	ou[2] = h0;
	ou[3] = h1;
}

static inline void shuffle_soft(uint32_t *in, uint32_t *ou, uint8_t idx)
{
	uint32_t h1 = in[(idx&0xc0)>>6];
	uint32_t h0 = in[(idx&0x30)>>4];
	uint32_t l1 = in[(idx&0x0c)>>2];
	uint32_t l0 = in[idx&0x03];
	ou[0] = l0;
	ou[1] = l1;
	ou[2] = h0;
	ou[3] = h1;
}


static inline void aes_256_assist1_soft(uint64_t* in1, uint64_t * in2)
{
	uint64_t inh, inl, tmp;
	shuffle_soft((uint32_t*)in2, (uint32_t*)in2, 0xff);
	inh = in1[1];
	inl = in1[0];
	for (uint8_t i=0; i<3; i++)
	{
		tmp = inl;
		tmp >>= 32;
		tmp &= 0x0ffffffff; // highest 4bit of low 64bit data

		inl <<= 32;
		inh <<= 32;
		inh |= tmp;
		in1[0] ^= inl;
		in1[1] ^= inh;
	}
	in1[0] ^= in2[0];
	in1[1] ^= in2[1];
}

static inline void aes_256_assist2_soft(uint64_t* in1, uint64_t * in2)
{
	uint64_t inh, inl, tmp, inner1[2];
	uint32_t * ptr32 = (uint32_t*)in1;

	uint32_t h0 = SubBytes(ptr32[3]);
	inner1[0] = h0;
	inner1[0] <<= 32;
	inner1[0] |= h0;
	inner1[1] = inner1[0];

    inh = in2[1];
	inl = in2[0];
	for (uint8_t i=0; i<3; i++)
	{
		tmp = inl;
		tmp >>= 32;
		tmp &= 0x0ffffffff; // highest 4bit of low 64bit data

		inl <<= 32;
		inh <<= 32;
		inh |= tmp;
		in2[0] ^= inl;
		in2[1] ^= inh;
	}

	in2[0] ^= inner1[0];
	in2[1] ^= inner1[1];
}

void aes_expand_key_soft(const uint64_t *key, uint64_t *expandedKey)
{
	ALIGN8 uint64_t *ek = expandedKey;
	uint64_t t1[2], t2[2], t3[2];  //for

	for (uint8_t i=0; i<2; i++)
	{
		t1[i] = key[i];
		t3[i] = key[i+2];
	}

	ek[0] = t1[0];
	ek[1] = t1[1];
	ek[2] = t3[0];
	ek[3] = t3[1];

	aeskey_gen_soft((uint32_t*)t3, (uint32_t*)t2, 0x01);
	aes_256_assist1_soft(t1, t2);
	ek[4] = t1[0];
	ek[5] = t1[1];
	aes_256_assist2_soft(t1, t3);
	ek[6] = t3[0];
	ek[7] = t3[1];

	aeskey_gen_soft((uint32_t*)t3, (uint32_t*)t2, 0x02);
	aes_256_assist1_soft(t1, t2);
	ek[8] = t1[0];
	ek[9] = t1[1];
	aes_256_assist2_soft(t1, t3);
	ek[10] = t3[0];
	ek[11] = t3[1];

	aeskey_gen_soft((uint32_t*)t3, (uint32_t*)t2, 0x04);
	aes_256_assist1_soft(t1, t2);
	ek[12] = t1[0];
	ek[13] = t1[1];
	aes_256_assist2_soft(t1, t3);
	ek[14] = t3[0];
	ek[15] = t3[1];

	aeskey_gen_soft((uint32_t*)t3, (uint32_t*)t2, 0x08);
	aes_256_assist1_soft(t1, t2);
	ek[16] = t1[0];
	ek[17] = t1[1];
	aes_256_assist2_soft(t1, t3);
	ek[18] = t3[0];
	ek[19] = t3[1];

	aeskey_gen_soft((uint32_t*)t3, (uint32_t*)t2, 0x10);
	aes_256_assist1_soft(t1, t2);
	ek[20] = t1[0];
	ek[21] = t1[1];
	aes_256_assist2_soft(t1, t3);
	ek[22] = t3[0];
	ek[23] = t3[1];
#if 0
	ur128 *exkey = (ur128 *)expandedKey;
	AESSETKEY0(exkey[0]);
	AESSETKEY1(exkey[1]);
	AESSETKEY2(exkey[2]);
	AESSETKEY3(exkey[3]);
	AESSETKEY4(exkey[4]);
	AESSETKEY5(exkey[5]);
	AESSETKEY6(exkey[6]);
	AESSETKEY7(exkey[7]);
	AESSETKEY8(exkey[8]);
	AESSETKEY9(exkey[9]);
	AESSETKEYA(exkey[10]);

#endif
}


static inline void xor128(uint64_t* in, uint64_t* key)
{
#ifdef CONFIG_MPUT
	ur128 din = *(ur128 *)in;
	ur128 kin = *(ur128 *)key;
	ur128 result = VRXOR(din, kin);
	*(ur128 *)in = result;
#else
	in[0] ^= key[0];
	in[1] ^= key[1];
#endif
}

void aes_enc_soft(uint64_t *a, uint64_t *b, uint64_t *roundKey)
{
//#ifdef CONFIG_MPUT
#if 0
	ur128 din = *(ur128 *)b;
	ur128 kin = *(ur128 *)roundKey;
	ur128 result = AESENC(din, kin);
	*(ur128 *)a = result;
#else
	uint8_t* ptr = (uint8_t*)tmp;  //tmp is global variable
	uint8_t* in = (uint8_t*)b;
	uint8_t* ou = (uint8_t*)a;
	//load into state
	for (uint8_t i=0; i<4; i++)
		for (uint8_t j=0; j<4; j++)
			ptr[4*i+j] = *in++;  //columns first

	ShiftRows_a(tmp);
	SubBytes_a(tmp);
	MixCol(tmp);

	//readout from state
	ptr = (uint8_t*)tmp;
	for (uint8_t i=0; i<4; i++)
		for (uint8_t j=0; j<4; j++)
			ou[4*i+j] = *ptr++;  //columns first
	xor128(a, roundKey);
#endif
}

void aes_pseudo_round_soft(const uint64_t *in, uint64_t *out,
							 uint64_t *expandedKey, int nblocks){

#ifdef CONFIG_MPUT
	ur128 din;
	ur128 *kin;

	for (uint32_t i=0; i<nblocks; i++)
	{
		din = *(ur128*)(in+2*i);
		kin = (ur128 *)expandedKey;
		for (uint32_t j=0; j<10; j++)
			din = AESENC(din, *kin++);
		*(ur128*)(out+2*i) = din;
	}

#else

	ALIGN8 uint64_t *ek = expandedKey;
	uint64_t d[2];

	for (uint32_t i=0; i<nblocks; i++)
	{
		d[0] = in[2*i];
		d[1] = in[2*i+1];

		aes_enc_soft(d, d, ek);
		aes_enc_soft(d, d, ek+2);
		aes_enc_soft(d, d, ek+4);
		aes_enc_soft(d, d, ek+6);
		aes_enc_soft(d, d, ek+8);
		aes_enc_soft(d, d, ek+10);
		aes_enc_soft(d, d, ek+12);
		aes_enc_soft(d, d, ek+14);
		aes_enc_soft(d, d, ek+16);
		aes_enc_soft(d, d, ek+18);
		out[2*i] = d[0];
		out[2*i+1] = d[1];
	}
#endif
}

void aes_pseudo_round_xor_soft(const uint64_t *in, uint64_t *out,
		uint64_t *expandedKey, uint64_t* xor_b, int nblocks){
#ifdef CONFIG_MPUT
	ur128 din;
	ur128 *kin;
	ur128 xv;

	for (uint32_t i=0; i<nblocks; i++)
	{
		din = *(ur128*)(in+2*i);
		kin = (ur128*)expandedKey;
		xv = *(ur128*)(xor_b+2*i);
		din = VRXOR(din, xv);
		for (uint32_t j=0; j<10; j++)
			din = AESENC(din, *kin++);
		*(ur128*)(out+2*i) = din;
	}

#else

	ALIGN8 uint64_t *ek = expandedKey;
	ALIGN8 uint64_t *x = xor_b;
	uint64_t d[2];

	for (uint32_t i=0; i<nblocks; i++)
	{
		d[0] = in[2*i];
		d[1] = in[2*i+1];
		xor128(d, x);
		x += 2; // points to next key : 128bitwidth
		aes_enc_soft(d, d, ek);
		aes_enc_soft(d, d, ek+2);
		aes_enc_soft(d, d, ek+4);
		aes_enc_soft(d, d, ek+6);
		aes_enc_soft(d, d, ek+8);
		aes_enc_soft(d, d, ek+10);
		aes_enc_soft(d, d, ek+12);
		aes_enc_soft(d, d, ek+14);
		aes_enc_soft(d, d, ek+16);
		aes_enc_soft(d, d, ek+18);
		out[2*i] = d[0];
		out[2*i+1] = d[1];
	}
#endif
}
