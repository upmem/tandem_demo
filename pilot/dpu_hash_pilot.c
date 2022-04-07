#include "libsig.h"
#include <stdio.h>
#include <string.h>

#include <mram.h>
#include "dpu_common.h"

__mram_noinit mram_t mram;
extern __mram_ptr void *__sys_sec_mram_start;

int main (void){
    __mram_ptr sec_mram_t *sec_mram = (__mram_ptr sec_mram_t *)__sys_sec_mram_start;
    __dma_aligned uint8_t out_hash[SHA256_SIZE];
    sha256((const u8 *)(uint32_t) mram.app_text, mram.app_text_size, (u8 *)out_hash);

    /* Copy the hash to secure MRAM for further handling - accessible by DPUs only */
    mram_write(out_hash, sec_mram->hash, SHA256_SIZE);
    /* Copy the hash to non-secure MRAM for sanity checks - for demonstration purposes only */
    mram_write(out_hash, mram.hash, SHA256_SIZE);
    return 0;
}
