/*-
 * KSHAKE320 is a Proof of Work authored by Oscar A. Perez based on the new
 * eXtendable-Output Function (XOF) called  SHAKE  that was  standardized by
 * the NIST as part of the SHA-3 (See FIPS 202 for more details).
 *
 * SHAKE's variable output makes it ideal for a Proof-Of-Work solution, as it 
 * can easily be configured to require large amount of memory which increases 
 * the computing cost to those attempting to perform large-scale ASIC attacks.
 * 
 * This Kernel was implemented using the below OpenCL source file as base:
 * keccak130718.cl - found in cgminer versions with keccak support
 *  Scrypt-jane public domain, OpenCL implementation of scrypt(keccak, chacha,
 *  SCRYPTN,1,1) 2013 mtrlt
 *
 * Note: This kernel has been  optimized to calculate the  Keccak  hash on input
 * buffers equal to (KRATE*8) bytes in size. Passing an input buffer with a size
 * different than (KRATE*8) will result in an incorrect calculation of the hash.
 */

#ifndef __ENDIAN_LITTLE__
#error This device is not little endian. Cannot continue.
#endif

/*-
 * The below parameter indicates a Keccak Rate equal to 960 and a Capacity equal
 * to 640. In other words, what would be SHAKE320 (if it ever gets standardized).
 */
#define KRATE (15U)

/*-
 * The below parameter indicates the total size of the proof-of-work.
 * (8*KRATE*KPROOF_OF_WORK_SZ) is the number of bytes used by each worker.
 */
#define KPROOF_OF_WORK_SZ (546U)

#define EndianSWAP(x) (rotate(x & 0x00ff00ffU, 24U) | rotate(x & 0xff00ff00U, 8U))

#define FOUND (0xff)
#define SETFOUND(Xnonce) output[output[FOUND]++] = Xnonce

__constant uint2 keccak_constants[24] = 
{
	(uint2)(0x00000001,0x00000000),
	(uint2)(0x00008082,0x00000000),
	(uint2)(0x0000808a,0x80000000),
	(uint2)(0x80008000,0x80000000),
	(uint2)(0x0000808b,0x00000000),
	(uint2)(0x80000001,0x00000000),
	(uint2)(0x80008081,0x80000000),
	(uint2)(0x00008009,0x80000000),
	(uint2)(0x0000008a,0x00000000),
	(uint2)(0x00000088,0x00000000),
	(uint2)(0x80008009,0x00000000),
	(uint2)(0x8000000a,0x00000000),
	(uint2)(0x8000808b,0x00000000),
	(uint2)(0x0000008b,0x80000000),
	(uint2)(0x00008089,0x80000000),
	(uint2)(0x00008003,0x80000000),
	(uint2)(0x00008002,0x80000000),
	(uint2)(0x00000080,0x80000000),
	(uint2)(0x0000800a,0x00000000),
	(uint2)(0x8000000a,0x80000000),
	(uint2)(0x80008081,0x80000000),
	(uint2)(0x00008080,0x80000000),
	(uint2)(0x80000001,0x00000000),
	(uint2)(0x80008008,0x80000000)
};


#define declare(X) \
	uint2 X##ba, X##be, X##bi, X##bo, X##bu; \
	uint2 X##ga, X##ge, X##gi, X##go, X##gu; \
	uint2 X##ka, X##ke, X##ki, X##ko, X##ku; \
	uint2 X##ma, X##me, X##mi, X##mo, X##mu; \
	uint2 X##sa, X##se, X##si, X##so, X##su; \
	uint2 X##a,  X##e,  X##i,  X##o,  X##u; \
	uint2 X##0,  X##1; \
\


#define initState(X) \
	X##ba = 0; \
	X##be = 0; \
	X##bi = 0; \
	X##bo = 0; \
	X##bu = 0; \
	X##ga = 0; \
	X##ge = 0; \
	X##gi = 0; \
	X##go = 0; \
	X##gu = 0; \
	X##ka = 0; \
	X##ke = 0; \
	X##ki = 0; \
	X##ko = 0; \
	X##ku = 0; \
	X##ma = 0; \
	X##me = 0; \
	X##mi = 0; \
	X##mo = 0; \
	X##mu = 0; \
	X##sa = 0; \
	X##se = 0; \
	X##si = 0; \
	X##so = 0; \
	X##su = 0; \
\


#define copyToPad(off, X) \
	scratchpad[                      off] = X##ba; \
	scratchpad[      globalSZ +      off] = X##be; \
	scratchpad[mad24(globalSZ,  2U, off)] = X##bi; \
	scratchpad[mad24(globalSZ,  3U, off)] = X##bo; \
	scratchpad[mad24(globalSZ,  4U, off)] = X##bu; \
	scratchpad[mad24(globalSZ,  5U, off)] = X##ga; \
	scratchpad[mad24(globalSZ,  6U, off)] = X##ge; \
	scratchpad[mad24(globalSZ,  7U, off)] = X##gi; \
	scratchpad[mad24(globalSZ,  8U, off)] = X##go; \
	scratchpad[mad24(globalSZ,  9U, off)] = X##gu; \
	scratchpad[mad24(globalSZ, 10U, off)] = X##ka; \
	scratchpad[mad24(globalSZ, 11U, off)] = X##ke; \
	scratchpad[mad24(globalSZ, 12U, off)] = X##ki; \
	scratchpad[mad24(globalSZ, 13U, off)] = X##ko; \
	scratchpad[mad24(globalSZ, 14U, off)] = X##ku; \
\



#define absorbFromPad(X, off) \
	X##ba ^= scratchpad[                      off]; \
	X##be ^= scratchpad[      globalSZ +      off]; \
	X##bi ^= scratchpad[mad24(globalSZ,  2U, off)]; \
	X##bo ^= scratchpad[mad24(globalSZ,  3U, off)]; \
	X##bu ^= scratchpad[mad24(globalSZ,  4U, off)]; \
	X##ga ^= scratchpad[mad24(globalSZ,  5U, off)]; \
	X##ge ^= scratchpad[mad24(globalSZ,  6U, off)]; \
	X##gi ^= scratchpad[mad24(globalSZ,  7U, off)]; \
	X##go ^= scratchpad[mad24(globalSZ,  8U, off)]; \
	X##gu ^= scratchpad[mad24(globalSZ,  9U, off)]; \
	X##ka ^= scratchpad[mad24(globalSZ, 10U, off)]; \
	X##ke ^= scratchpad[mad24(globalSZ, 11U, off)]; \
	X##ki ^= scratchpad[mad24(globalSZ, 12U, off)]; \
	X##ko ^= scratchpad[mad24(globalSZ, 13U, off)]; \
	X##ku ^= scratchpad[mad24(globalSZ, 14U, off)]; \
\


#define absorbInput(X, input, nonce) \
	X##ba ^= input[ 0]; \
	X##be ^= input[ 1]; \
	X##bi ^= input[ 2]; \
	X##bo ^= input[ 3]; \
	X##bu ^= input[ 4]; \
	X##ga ^= input[ 5]; \
	X##ge ^= input[ 6]; \
	X##gi ^= input[ 7]; \
	X##go ^= input[ 8]; \
	X##gu ^= input[ 9]; \
	X##ka ^= input[10]; \
	X##ke ^= input[11]; \
	X##ki ^= input[12]; \
	X##ko ^= input[13]; \
	X##ku ^= (uint2)(input[14].x, input[14].y + nonce); \
\

#define absorbFromState(X, Y) \
	X##ba ^= Y##ba; \
	X##be ^= Y##be; \
	X##bi ^= Y##bi; \
	X##bo ^= Y##bo; \
	X##bu ^= Y##bu; \
	X##ga ^= Y##ga; \
	X##ge ^= Y##ge; \
	X##gi ^= Y##gi; \
	X##go ^= Y##go; \
	X##gu ^= Y##gu; \
	X##ka ^= Y##ka; \
	X##ke ^= Y##ke; \
	X##ki ^= Y##ki; \
	X##ko ^= Y##ko; \
	X##ku ^= Y##ku; \
\


#define ROUND(X, k) \
	X##a = X##bu ^ X##gu ^ X##ku ^ X##mu ^ X##su ^ ROTL64_X(X##be ^ X##ge ^ X##ke ^ X##me ^ X##se, 1); \
	X##e = X##ba ^ X##ga ^ X##ka ^ X##ma ^ X##sa ^ ROTL64_X(X##bi ^ X##gi ^ X##ki ^ X##mi ^ X##si, 1); \
	X##i = X##be ^ X##ge ^ X##ke ^ X##me ^ X##se ^ ROTL64_X(X##bo ^ X##go ^ X##ko ^ X##mo ^ X##so, 1); \
	X##o = X##bi ^ X##gi ^ X##ki ^ X##mi ^ X##si ^ ROTL64_X(X##bu ^ X##gu ^ X##ku ^ X##mu ^ X##su, 1); \
	X##u = X##bo ^ X##go ^ X##ko ^ X##mo ^ X##so ^ ROTL64_X(X##ba ^ X##ga ^ X##ka ^ X##ma ^ X##sa, 1); \
\
	X##0 = X##be ^ X##e; \
\
	X##ba ^= X##a; \
	X##be = ROTL64_Y(X##ge ^ X##e, 12); \
	X##ge = ROTL64_X(X##gu ^ X##u, 20); \
	X##gu = ROTL64_Y(X##si ^ X##i, 29); \
	X##si = ROTL64_Y(X##ku ^ X##u,  7); \
	X##ku = ROTL64_X(X##sa ^ X##a, 18); \
	X##sa = ROTL64_Y(X##bi ^ X##i, 30); \
	X##bi = ROTL64_Y(X##ki ^ X##i, 11); \
	X##ki = ROTL64_X(X##ko ^ X##o, 25); \
	X##ko = ROTL64_X(X##mu ^ X##u,  8); \
	X##mu = ROTL64_Y(X##so ^ X##o, 24); \
	X##so = ROTL64_Y(X##ma ^ X##a,  9); \
	X##ma = ROTL64_X(X##bu ^ X##u, 27); \
	X##bu = ROTL64_X(X##su ^ X##u, 14); \
	X##su = ROTL64_X(X##se ^ X##e,  2); \
	X##se = ROTL64_Y(X##go ^ X##o, 23); \
	X##go = ROTL64_Y(X##me ^ X##e, 13); \
	X##me = ROTL64_Y(X##ga ^ X##a,  4); \
	X##ga = ROTL64_X(X##bo ^ X##o, 28); \
	X##bo = ROTL64_X(X##mo ^ X##o, 21); \
	X##mo = ROTL64_X(X##mi ^ X##i, 15); \
	X##mi = ROTL64_X(X##ke ^ X##e, 10); \
	X##ke = ROTL64_X(X##gi ^ X##i,  6); \
	X##gi = ROTL64_X(X##ka ^ X##a,  3); \
	X##ka = ROTL64_X(        X##0,  1); \
	\
	X##0 = X##ba; \
	X##1 = X##be; \
	X##ba = bitselect(X##ba ^ X##bi, X##ba, X##be); \
	X##be = bitselect(X##be ^ X##bo, X##be, X##bi); \
	X##bi = bitselect(X##bi ^ X##bu, X##bi, X##bo); \
	X##bo = bitselect(X##bo ^  X##0, X##bo, X##bu); \
	X##bu = bitselect(X##bu ^  X##1, X##bu,  X##0); \
	\
	X##0 = X##ga; \
	X##1 = X##ge; \
	X##ga = bitselect(X##ga ^ X##gi, X##ga, X##ge); \
	X##ge = bitselect(X##ge ^ X##go, X##ge, X##gi); \
	X##gi = bitselect(X##gi ^ X##gu, X##gi, X##go); \
	X##go = bitselect(X##go ^  X##0, X##go, X##gu); \
	X##gu = bitselect(X##gu ^  X##1, X##gu,  X##0); \
	\
	X##0 = X##ka; \
	X##1 = X##ke; \
	X##ka = bitselect(X##ka ^ X##ki, X##ka, X##ke); \
	X##ke = bitselect(X##ke ^ X##ko, X##ke, X##ki); \
	X##ki = bitselect(X##ki ^ X##ku, X##ki, X##ko); \
	X##ko = bitselect(X##ko ^  X##0, X##ko, X##ku); \
	X##ku = bitselect(X##ku ^  X##1, X##ku,  X##0); \
	\
	X##0 = X##ma; \
	X##1 = X##me; \
	X##ma = bitselect(X##ma ^ X##mi, X##ma, X##me); \
	X##me = bitselect(X##me ^ X##mo, X##me, X##mi); \
	X##mi = bitselect(X##mi ^ X##mu, X##mi, X##mo); \
	X##mo = bitselect(X##mo ^  X##0, X##mo, X##mu); \
	X##mu = bitselect(X##mu ^  X##1, X##mu,  X##0); \
	\
	X##0 = X##sa; \
	X##1 = X##se; \
	X##sa = bitselect(X##sa ^ X##si, X##sa, X##se); \
	X##se = bitselect(X##se ^ X##so, X##se, X##si); \
	X##si = bitselect(X##si ^ X##su, X##si, X##so); \
	X##so = bitselect(X##so ^  X##0, X##so, X##su); \
	X##su = bitselect(X##su ^  X##1, X##su,  X##0); \
\
	X##ba ^= keccak_constants[k]; \
\


#define keccak_round(X) \
	ROUND(X, 0); \
	for (j = 1; j < 22; ++j) { \
		ROUND(X, j); \
		++j; \
		ROUND(X, j); \
		++j; \
		ROUND(X, j); \
	} \
	ROUND(X, 22); \
	ROUND(X, 23); \
\


uint2 ROTL64_X(const uint2 a, const uint b)
{
	return (uint2)( (a.x << b) ^ (a.y >> (32 - b)) , (a.y << b) ^ (a.x >> (32 - b)) );
}


uint2 ROTL64_Y(const uint2 a, const uint b)
{
	return (uint2)( (a.y << b) ^ (a.x >> (32 - b)) , (a.x << b) ^ (a.y >> (32 - b)) );
}


__kernel
__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
void search(__global uint2*restrict inputbuffer,
			__global uint*restrict output,
			__global uint2*restrict scratchpad,
			const uint2 target)
{
	uint globalID = get_global_id(0);
	uint globalSZ = get_global_size(0);
	uint goffset  = globalSZ * KRATE;
	uint glimit   = goffset * KPROOF_OF_WORK_SZ + globalID;
	uint version  = inputbuffer[0].x;	
	uint i, j;
	declare(A)

	initState(A)
	absorbInput(A, inputbuffer, globalID)
	keccak_round(A)
	Aba.x ^= 0x0000001fUL;
	Aku.y ^= 0x80000000UL;

	for (i = globalID; i < glimit; i += goffset)
	{
		keccak_round(A)
		copyToPad(i, A)
	}

	barrier(CLK_GLOBAL_MEM_FENCE); 

	initState(A)
	if (version <= 1)
	{
		for (i = globalID; i < glimit; i += goffset)
		{
			absorbFromPad(A, i)
			keccak_round(A)
		}
	}
	else
	{
		for (i = glimit - goffset; i > globalID; i -= goffset)
		{
			absorbFromPad(A, i)
			keccak_round(A)
		}
		absorbFromPad(A, globalID)
		keccak_round(A)
	}

	Aba.x ^= 0x0000001fUL;
	Aku.y ^= 0x80000000UL;
	keccak_round(A)

	if (target.y != 0)
	{
		if (Abu.y <= target.y)
		{
			SETFOUND(globalID);
		}
	}
	else
	{
		if (Abu.y == 0 && Abu.x <= target.x)
		{
			SETFOUND(globalID);
		}
	}
}
