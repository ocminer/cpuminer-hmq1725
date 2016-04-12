#include "miner.h"

#include <string.h>
#include <stdint.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"

#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"
#include "sha3/sph_haval.h"



extern void hmq1725hash(void *state, const void *input)
{

  sph_blake512_context     ctx_blake;
    sph_bmw512_context       ctx_bmw;
    sph_groestl512_context   ctx_groestl;
    sph_jh512_context        ctx_jh;
    sph_keccak512_context    ctx_keccak;
    sph_skein512_context     ctx_skein;

   sph_luffa512_context     ctx_luffa;
   sph_cubehash512_context  ctx_cubehash;
   sph_shavite512_context   ctx_shavite;
   sph_simd512_context      ctx_simd;
   sph_echo512_context      ctx_echo;
   sph_hamsi512_context     ctx_hamsi;
   sph_fugue512_context     ctx_fugue;
   sph_shabal512_context    ctx_shabal;
   sph_whirlpool_context    ctx_whirlpool;
   sph_sha512_context       ctx_sha2;
   sph_haval256_5_context   ctx_haval;

    uint32_t mask = 24;
    uint32_t zero = 0;

    uint32_t hashA[16], hashB[16];


  sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, input, len);
    sph_bmw512_close (&ctx_bmw, hashA);  //0


    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashA, 64);    //0
    sph_whirlpool_close(&ctx_whirlpool, hashB);   //1


    if ((hashB[0] & mask) != zero)   //1
    {
        sph_groestl512_init(&ctx_groestl);
        sph_groestl512 (&ctx_groestl, hashB, 64); //1
        sph_groestl512_close(&ctx_groestl, hashA); //2
    }
    else
    {
        sph_skein512_init(&ctx_skein);
        sph_skein512 (&ctx_skein, hashB, 64); //1
        sph_skein512_close(&ctx_skein, hashA); //2
    }


    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, hashA, 64); //2
    sph_jh512_close(&ctx_jh, hashB); //3

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, hashB, 64); //3
    sph_keccak512_close(&ctx_keccak, hashA); //4

    if ((hashA[0] & mask) != zero) //4
    {
        sph_blake512_init(&ctx_blake);
        sph_blake512 (&ctx_blake, hashA, 64); //
        sph_blake512_close(&ctx_blake, hashB); //5
    }
    else
    {
        sph_bmw512_init(&ctx_bmw);
        sph_bmw512 (&ctx_bmw, hashA, 64); //4
        sph_bmw512_close(&ctx_bmw, hashB);   //5
    }

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa,hashB, 64); //5
    sph_luffa512_close(&ctx_luffa, hashA); //6

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, hashA, 64); //6
    sph_cubehash512_close(&ctx_cubehash, hashB); //7

    if ((hashB[0] & mask) != zero) //7
    {
        sph_keccak512_init(&ctx_keccak);
        sph_keccak512 (&ctx_keccak, hashB, 64); //
        sph_keccak512_close(&ctx_keccak, hashA); //8
    }
    else
    {
        sph_jh512_init(&ctx_jh);
        sph_jh512 (&ctx_jh, hashB, 64); //7
        sph_jh512_close(&ctx_jh, hashA); //8
    }


/**/

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512 (&ctx_shavite,hashA, 64); //5
    sph_shavite512_close(&ctx_shavite, hashB); //6

    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, hashB, 64); //6
    sph_simd512_close(&ctx_simd, hashA); //7

    if ((hashA[0] & mask) != zero) //4
    {
        sph_whirlpool_init(&ctx_whirlpool);
        sph_whirlpool (&ctx_whirlpool, hashA, 64); //
        sph_whirlpool_close(&ctx_whirlpool, hashB); //5
    }
    else
    {
        sph_haval256_5_init(&ctx_haval);
        sph_haval256_5 (&ctx_haval, hashA, 64); //4
        sph_haval256_5_close(&ctx_haval, hashB);   //5
    }

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo,hashB, 64); //5
    sph_echo512_close(&ctx_echo, hashA); //6

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, hashA, 64); //6
    sph_blake512_close(&ctx_blake, hashB); //7

    if ((hashB[0] & mask) != zero) //7
    {
        sph_shavite512_init(&ctx_shavite);
        sph_shavite512 (&ctx_shavite, hashB, 64); //
        sph_shavite512_close(&ctx_shavite, hashA); //8
    }
    else
    {
        sph_luffa512_init(&ctx_luffa);
        sph_luffa512 (&ctx_luffa, hashB, 64); //7
        sph_luffa512_close(&ctx_luffa, hashA); //8
    }


    sph_hamsi512_init(&ctx_hamsi);
    sph_hamsi512 (&ctx_hamsi,hashA, 64); //5
    sph_hamsi512_close(&ctx_hamsi, hashB); //6

    sph_fugue512_init(&ctx_fugue);
    sph_fugue512 (&ctx_fugue, hashB, 64); //6
    sph_fugue512_close(&ctx_fugue, hashA); //7


    if ((hashA[0] & mask) != zero) //4
    {
        sph_echo512_init(&ctx_echo);
        sph_echo512 (&ctx_echo, hashA, 64); //
        sph_echo512_close(&ctx_echo, hashB); //5
    }
    else
    {
        sph_simd512_init(&ctx_simd);
        sph_simd512 (&ctx_simd, hashA, 64); //4
        sph_simd512_close(&ctx_simd, hashB);   //5
    }

    sph_shabal512_init(&ctx_shabal);
    sph_shabal512 (&ctx_shabal,hashB, 64); //5
    sph_shabal512_close(&ctx_shabal, hashA); //6

    sph_whirlpool_init(&ctx_whirlpool);
    sph_whirlpool (&ctx_whirlpool, hashA, 64); //6
    sph_whirlpool_close(&ctx_whirlpool, hashB); //7

   if ((hashB[0] & mask) != zero) //7
    {
        sph_fugue512_init(&ctx_fugue);
        sph_fugue512 (&ctx_fugue, hashB, 64); //
        sph_fugue512_close(&ctx_fugue, hashA); //8
    }
    else
    {
        sph_sha512_init(&ctx_sha2);
        sph_sha512 (&ctx_sha2, hashB, 64); //7
        sph_sha512_close(&ctx_sha2, hashA); //8
    }

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl,hashA, 64); //5 
    sph_groestl512_close(&ctx_groestl, hashB); //6 

    sph_sha512_init(&ctx_sha2);
    sph_sha512 (&ctx_sha2, hashB, 64); //6
    sph_sha512_close(&ctx_sha2, hashA); //7


    if ((hashA[0] & mask) != zero) //4
    {
        sph_haval256_5_init(&ctx_haval);
        sph_haval256_5 (&ctx_haval, hashA, 64); //
        sph_haval256_5_close(&ctx_haval, hashB); //5
    }
    else
    {
        sph_whirlpool_init(&ctx_whirlpool);
        sph_whirlpool (&ctx_whirlpool, hashA, 64); //4
        sph_whirlpool_close(&ctx_whirlpool, hashB);   //5
    }


    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw,hashB, 64); //5
    sph_bmw512_close(&ctx_bmw, hashA); //6


	memcpy(state, hashA, 32);
	
}

int scanhash_hmq1725(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce, uint64_t *hashes_done)
{
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	//const uint32_t Htarg = ptarget[7];

	uint32_t _ALIGN(32) hash64[8];
	uint32_t endiandata[32];
	
	//char testdata[] = {"\x70\x00\x00\x00\x5d\x38\x5b\xa1\x14\xd0\x79\x97\x0b\x29\xa9\x41\x8f\xd0\x54\x9e\x7d\x68\xa9\x5c\x7f\x16\x86\x21\xa3\x14\x20\x10\x00\x00\x00\x00\x57\x85\x86\xd1\x49\xfd\x07\xb2\x2f\x3a\x8a\x34\x7c\x51\x6d\xe7\x05\x2f\x03\x4d\x2b\x76\xff\x68\xe0\xd6\xec\xff\x9b\x77\xa4\x54\x89\xe3\xfd\x51\x17\x32\x01\x1d\xf0\x73\x10\x00"};
	
	//we need bigendian data...
	//lessons learned: do NOT endianchange directly in pdata, this will all proof-of-works be considered as stale from minerd.... 
	int kk=0;
	for (; kk < 32; kk++)
	{
		be32enc(&endiandata[kk], ((uint32_t*)pdata)[kk]);
	};

//	if (opt_debug) 
//	{
//		applog(LOG_DEBUG, "Thr: %02d, firstN: %08x, maxN: %08x, ToDo: %d", thr_id, first_nonce, max_nonce, max_nonce-first_nonce);
//	}
	
	/* I'm to lazy to put the loop in an inline function... so dirty copy'n'paste.... */
	/* i know that i could set a variable, but i don't know how the compiler will optimize it, not that then the cpu needs to load the value *everytime* in a register */
	if (ptarget[7]==0) {
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFFFF)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFFF0)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFFF00)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	} 
	else if (ptarget[7]<=0xFFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFFF000)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	

	} 
	else if (ptarget[7]<=0xFFFF) 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (((hash64[7]&0xFFFF0000)==0) && 
					fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	

	} 
	else 
	{
		do {
			pdata[19] = ++n;
			be32enc(&endiandata[19], n); 
			hmq1725hash(hash64, endiandata);
			if (fulltest(hash64, ptarget)) {
				*hashes_done = n - first_nonce + 1;
				return true;
			}
		} while (n < max_nonce && !work_restart[thr_id].restart);	
	}
	
	
	*hashes_done = n - first_nonce + 1;
	pdata[19] = n;
	return 0;
}
