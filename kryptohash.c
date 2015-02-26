
#include "miner.h"
#include "logging.h"

void kryptohash_regenhash(struct work *work)
{
    unsigned char scratchpad1[KPROOF_OF_WORK_SZ];
    unsigned char scratchpad2[KPROOF_OF_WORK_SZ];
    int version = *((int *)work->data);
	
    KSHAKE320(work->data, KRATE * 8, scratchpad1, KPROOF_OF_WORK_SZ);

	if (version <= 1) {
		KSHAKE320(scratchpad1, KPROOF_OF_WORK_SZ * 8, work->kryptohash, 40);
	}
	else {
		// Swap blocks in chunks of KRATE size
		unsigned char *p1 = scratchpad1 + KPROOF_OF_WORK_SZ;
		unsigned char *p2 = scratchpad2;
		int i;
		for (i = 0; i < KPOW_MUL; i++)
		{
			p1 -= KRATE;
			memcpy(p2, p1, KRATE);
			p2 += KRATE;
		}
		KSHAKE320(scratchpad2, KPROOF_OF_WORK_SZ * 8, work->kryptohash, 40);
	}
}

bool kryptohash_prepare_work(struct thr_info __maybe_unused *thr, struct work *work)
{
    memcpy(work->blk.kryptohash_data, work->data, sizeof(work->blk.kryptohash_data));
    return true;
}
