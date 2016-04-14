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


/* Move init out of loop, so init once externally, and then use one single memcpy with that bigger memory block */
typedef struct {
	sph_blake512_context 	blake1, blake2;
	sph_bmw512_context		bmw1, bmw2, bmw3;
	sph_groestl512_context	groestl1, groestl2;
	sph_skein512_context	skein1, skein2;
	sph_jh512_context		jh1, jh2;
	sph_keccak512_context	keccak1, keccak2;

 sph_luffa512_context     luffa1, luffa2;
 sph_cubehash512_context  cubehash1;
 sph_shavite512_context   shavite1, shavite2;
 sph_simd512_context      simd1, simd2;
 sph_echo512_context      echo1, echo2;
 sph_hamsi512_context     hamsi1;
 sph_fugue512_context     fugue1, fugue2;
 sph_shabal512_context    shabal1;
 sph_whirlpool_context    whirlpool1, whirlpool2, whirlpool3, whirlpool4;
 sph_sha512_context       sha1, sha2;
 sph_haval256_5_context   haval1, haval2;


} quarkhash_context_holder;

static quarkhash_context_holder base_contexts;

void init_quarkhash_contexts()
{
    sph_blake512_init(&base_contexts.blake1);
    sph_bmw512_init(&base_contexts.bmw1);
    sph_groestl512_init(&base_contexts.groestl1);
    sph_skein512_init(&base_contexts.skein1);
    sph_groestl512_init(&base_contexts.groestl2);
    sph_jh512_init(&base_contexts.jh1);	
    sph_blake512_init(&base_contexts.blake2);	
    sph_bmw512_init(&base_contexts.bmw2);	
    sph_keccak512_init(&base_contexts.keccak1);	
    sph_skein512_init(&base_contexts.skein2);
    sph_keccak512_init(&base_contexts.keccak2);
    sph_jh512_init(&base_contexts.jh2);	

sph_bmw512_init(&base_contexts.bmw2);
sph_bmw512_init(&base_contexts.bmw3);
sph_luffa512_init(&base_contexts.luffa1);
sph_luffa512_init(&base_contexts.luffa2);
sph_cubehash512_init(&base_contexts.cubehash1);
sph_shavite512_init(&base_contexts.shavite1);
sph_shavite512_init(&base_contexts.shavite2);
sph_simd512_init(&base_contexts.simd1);
sph_simd512_init(&base_contexts.simd2);
sph_echo512_init(&base_contexts.echo1);
sph_echo512_init(&base_contexts.echo2);
sph_hamsi512_init(&base_contexts.hamsi1);
sph_fugue512_init(&base_contexts.fugue1);
sph_fugue512_init(&base_contexts.fugue2);
sph_shabal512_init(&base_contexts.shabal1);
sph_whirlpool_init(&base_contexts.whirlpool1);
sph_whirlpool_init(&base_contexts.whirlpool2);
sph_whirlpool_init(&base_contexts.whirlpool3);
sph_whirlpool_init(&base_contexts.whirlpool4);
sph_sha512_init(&base_contexts.sha1);
sph_sha512_init(&base_contexts.sha2);
sph_haval256_5_init(&base_contexts.haval1);
sph_haval256_5_init(&base_contexts.haval2);

}

extern void quarkhash(void *state, const void *input)
{

	quarkhash_context_holder ctx;

    uint32_t mask = 24;
    uint32_t zero = 0;

	//these uint512 in the c++ source of the client are backed by an array of uint32
    uint32_t hashA[25], hashB[25];	
	

	//do one memcopy to get fresh contexts, its faster even with a larger block then issuing 9 memcopies
	memcpy(&ctx, &base_contexts, sizeof(base_contexts));

	
	
    sph_bmw512 (&ctx.bmw1, input, 80);    //0
    sph_bmw512_close(&ctx.bmw1, hashA);   //1

    sph_whirlpool (&ctx.whirlpool1, hashA, 64);    //0
    sph_whirlpool_close(&ctx.whirlpool1, hashB);   //1

	
    if ((hashB[0] & mask) != zero)   //1
    {
        sph_groestl512 (&ctx.groestl1, hashB, 64); //1
        sph_groestl512_close(&ctx.groestl1, hashA); //2
    }
    else
    {
        sph_skein512 (&ctx.skein1, hashB, 64); //1
        sph_skein512_close(&ctx.skein1, hashA); //2
    }
	
    sph_jh512 (&ctx.jh1, hashA, 64); //3
    sph_jh512_close(&ctx.jh1, hashB); //4

    sph_keccak512 (&ctx.keccak1, hashB, 64); //2
    sph_keccak512_close(&ctx.keccak1, hashA); //3


    if ((hashA[0] & mask) != zero) //4
    {
        sph_blake512 (&ctx.blake1, hashA, 64); //
        sph_blake512_close(&ctx.blake1, hashB); //5
    }
    else
    {
        sph_bmw512 (&ctx.bmw2, hashA, 64); //4
        sph_bmw512_close(&ctx.bmw2, hashB);   //5
    }
    
    sph_luffa512 (&ctx.luffa1, hashB, 64); //5
    sph_luffa512_close(&ctx.luffa1, hashA); //6

    sph_cubehash512 (&ctx.cubehash1, hashA, 64); //6
    sph_cubehash512_close(&ctx.cubehash1, hashB); //7

    if ((hashB[0] & mask) != zero) //7
    {
        sph_keccak512 (&ctx.keccak2, hashB, 64); //
        sph_keccak512_close(&ctx.keccak2, hashA); //8
    }
    else
    {
        sph_jh512 (&ctx.jh2, hashB, 64); //7
        sph_jh512_close(&ctx.jh2, hashA); //8
    }






    sph_shavite512 (&ctx.shavite1, hashA, 64); //3
    sph_shavite512_close(&ctx.shavite1, hashB); //4

    sph_simd512 (&ctx.simd1, hashB, 64); //2
    sph_simd512_close(&ctx.simd1, hashA); //3

    
    if ((hashA[0] & mask) != zero) //4
    {
        sph_whirlpool (&ctx.whirlpool2, hashA, 64); //
        sph_whirlpool_close(&ctx.whirlpool2, hashB); //5
    }
    else
    {
        sph_haval256_5 (&ctx.haval1, hashA, 64); //4
        sph_haval256_5_close(&ctx.haval1, hashB);   //5
	memset(&hashB[8], 0, 32);
    }






    sph_echo512 (&ctx.echo1, hashB, 64); //5
    sph_echo512_close(&ctx.echo1, hashA); //6

    sph_blake512 (&ctx.blake2, hashA, 64); //6
    sph_blake512_close(&ctx.blake2, hashB); //7

    if ((hashB[0] & mask) != zero) //7
    {
        sph_shavite512 (&ctx.shavite2, hashB, 64); //
        sph_shavite512_close(&ctx.shavite2, hashA); //8
    }
    else
    {
        sph_luffa512 (&ctx.luffa2, hashB, 64); //7
        sph_luffa512_close(&ctx.luffa2, hashA); //8
    }






    sph_hamsi512 (&ctx.hamsi1, hashA, 64); //3
    sph_hamsi512_close(&ctx.hamsi1, hashB); //4

    sph_fugue512 (&ctx.fugue1, hashB, 64); //2   ////
    sph_fugue512_close(&ctx.fugue1, hashA); //3 


    if ((hashA[0] & mask) != zero) //4
    {
        sph_echo512 (&ctx.echo2, hashA, 64); //
        sph_echo512_close(&ctx.echo2, hashB); //5
    }
    else
    {
        sph_simd512 (&ctx.simd2, hashA, 64); //4
        sph_simd512_close(&ctx.simd2, hashB);   //5
    }





    sph_shabal512 (&ctx.shabal1, hashB, 64); //5
    sph_shabal512_close(&ctx.shabal1, hashA); //6

    sph_whirlpool (&ctx.whirlpool3, hashA, 64); //6
    sph_whirlpool_close(&ctx.whirlpool3, hashB); //7

    if ((hashB[0] & mask) != zero) //7
    {
        sph_fugue512 (&ctx.fugue2, hashB, 64); //
        sph_fugue512_close(&ctx.fugue2, hashA); //8
    }
    else
    {
        sph_sha512 (&ctx.sha1, hashB, 64); //7
        sph_sha512_close(&ctx.sha1, hashA); //8
    }






    sph_groestl512 (&ctx.groestl2, hashA, 64); //3
    sph_groestl512_close(&ctx.groestl2, hashB); //4

    sph_sha512 (&ctx.sha2, hashB, 64); //2 
    sph_sha512_close(&ctx.sha2, hashA); //3 


    if ((hashA[0] & mask) != zero) //4
    {
        sph_haval256_5 (&ctx.haval2, hashA, 64); //
        sph_haval256_5_close(&ctx.haval2, hashB); //5
	memset(&hashB[8], 0, 32);
    }
    else
    {
        sph_whirlpool (&ctx.whirlpool4, hashA, 64); //4
        sph_whirlpool_close(&ctx.whirlpool4, hashB);   //5
    }


    sph_bmw512 (&ctx.bmw3, hashB, 64); //5
    sph_bmw512_close(&ctx.bmw3, hashA); //6




	memcpy(state, hashA, 32);

	
}

int scanhash_quark(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
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
			quarkhash(hash64, endiandata);
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
			quarkhash(hash64, endiandata);
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
			quarkhash(hash64, endiandata);
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
			quarkhash(hash64, endiandata);
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
			quarkhash(hash64, endiandata);
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
			quarkhash(hash64, endiandata);
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
