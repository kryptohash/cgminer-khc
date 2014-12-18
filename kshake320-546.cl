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
 *  keccak130718.cl - found in cgminer versions with keccak support
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

#define EndianSWAP32(x) ( \
		rotate(x & 0x00ff00ffU, 24U) | \
		rotate(x & 0xff00ff00U,  8U) \
		) \

#define EndianSWAP64(x) ( \
		rotate(x & 0x000000ff000000ffUL, 56UL) | \
		rotate(x & 0x0000ff000000ff00UL, 40UL) | \
		rotate(x & 0x00ff000000ff0000UL, 24UL) | \
		rotate(x & 0xff000000ff000000UL,  8UL) \
		) \

#define ROL64(a, b) (rotate(a, b))

#define FOUND (0xff)
#define SETFOUND(Xnonce) output[output[FOUND]++] = Xnonce

__constant ulong keccak_constants[24] = 
{
	0x0000000000000001UL,
	0x0000000000008082UL,
	0x800000000000808aUL,
	0x8000000080008000UL,
	0x000000000000808bUL,
	0x0000000080000001UL,
	0x8000000080008081UL,
	0x8000000000008009UL,
	0x000000000000008aUL,
	0x0000000000000088UL,
	0x0000000080008009UL,
	0x000000008000000aUL,
	0x000000008000808bUL,
	0x800000000000008bUL,
	0x8000000000008089UL,
	0x8000000000008003UL,
	0x8000000000008002UL,
	0x8000000000000080UL,
	0x000000000000800aUL,
	0x800000008000000aUL,
	0x8000000080008081UL,
	0x8000000000008080UL,
	0x0000000080000001UL,
	0x8000000080008008UL 
};



#define declare(X) \
	ulong X##ba, X##be, X##bi, X##bo, X##bu; \
	ulong X##ga, X##ge, X##gi, X##go, X##gu; \
	ulong X##ka, X##ke, X##ki, X##ko, X##ku; \
	ulong X##ma, X##me, X##mi, X##mo, X##mu; \
	ulong X##sa, X##se, X##si, X##so, X##su; \
	ulong X##a,  X##e,  X##i,  X##o,  X##u; \
	ulong X##0,  X##1; \
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
	X##ku ^= input[14] + EndianSWAP64(nonce); \
\


/*-
 * If you ever change KRATE, you need to adjust the below delimiter accordingly.
 */
#define shake320_delimeter(X) \
	X##ba ^= 0x000000000000001fUL; \
	X##ku ^= 0x8000000000000000UL; \
\


#define ROUND(X, k) \
	X##a = X##bu ^ X##gu ^ X##ku ^ X##mu ^ X##su ^ ROL64(X##be ^ X##ge ^ X##ke ^ X##me ^ X##se, 1UL); \
	X##e = X##ba ^ X##ga ^ X##ka ^ X##ma ^ X##sa ^ ROL64(X##bi ^ X##gi ^ X##ki ^ X##mi ^ X##si, 1UL); \
	X##i = X##be ^ X##ge ^ X##ke ^ X##me ^ X##se ^ ROL64(X##bo ^ X##go ^ X##ko ^ X##mo ^ X##so, 1UL); \
	X##o = X##bi ^ X##gi ^ X##ki ^ X##mi ^ X##si ^ ROL64(X##bu ^ X##gu ^ X##ku ^ X##mu ^ X##su, 1UL); \
	X##u = X##bo ^ X##go ^ X##ko ^ X##mo ^ X##so ^ ROL64(X##ba ^ X##ga ^ X##ka ^ X##ma ^ X##sa, 1UL); \
\
	X##0 = X##be ^ X##e; \
\
	X##ba ^= X##a; \
	X##be = ROL64(X##ge ^ X##e, 44UL); \
	X##ge = ROL64(X##gu ^ X##u, 20UL); \
	X##gu = ROL64(X##si ^ X##i, 61UL); \
	X##si = ROL64(X##ku ^ X##u, 39UL); \
	X##ku = ROL64(X##sa ^ X##a, 18UL); \
	X##sa = ROL64(X##bi ^ X##i, 62UL); \
	X##bi = ROL64(X##ki ^ X##i, 43UL); \
	X##ki = ROL64(X##ko ^ X##o, 25UL); \
	X##ko = ROL64(X##mu ^ X##u,  8UL); \
	X##mu = ROL64(X##so ^ X##o, 56UL); \
	X##so = ROL64(X##ma ^ X##a, 41UL); \
	X##ma = ROL64(X##bu ^ X##u, 27UL); \
	X##bu = ROL64(X##su ^ X##u, 14UL); \
	X##su = ROL64(X##se ^ X##e,  2UL); \
	X##se = ROL64(X##go ^ X##o, 55UL); \
	X##go = ROL64(X##me ^ X##e, 45UL); \
	X##me = ROL64(X##ga ^ X##a, 36UL); \
	X##ga = ROL64(X##bo ^ X##o, 28UL); \
	X##bo = ROL64(X##mo ^ X##o, 21UL); \
	X##mo = ROL64(X##mi ^ X##i, 15UL); \
	X##mi = ROL64(X##ke ^ X##e, 10UL); \
	X##ke = ROL64(X##gi ^ X##i,  6UL); \
	X##gi = ROL64(X##ka ^ X##a,  3UL); \
	X##ka = ROL64(        X##0,  1UL); \
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



__kernel
__attribute__((reqd_work_group_size(WORKSIZE, 1, 1)))
void search(__global ulong*restrict inputbuffer,
			__global uint*restrict output,
			__global ulong*restrict scratchpad,
			const ulong target)
{
	uint globalID = get_global_id(0);
	uint globalSZ = get_global_size(0);
	uint goffset  = globalSZ * KRATE;
	uint glimit   = goffset * KPROOF_OF_WORK_SZ + globalID;
	ulong nonce   = (ulong)EndianSWAP32(globalID);
	uint i, j;
	declare(A)

	initState(A)
	absorbInput(A, inputbuffer, nonce)
	keccak_round(A)
	shake320_delimeter(A)
	keccak_round(A)
	for (i = globalID; i < glimit; i += goffset)
	{
		if (i > globalID)
		{
			keccak_round(A)
		}
		copyToPad(i, A)
	}

	barrier(CLK_GLOBAL_MEM_FENCE); 

	initState(A)
	for (i = globalID; i < glimit; i += goffset)
	{
		absorbFromPad(A, i)
		keccak_round(A)
	}
	shake320_delimeter(A)
	keccak_round(A)

	if (Abu <= target)
	{
		SETFOUND(globalID);
	}
}
