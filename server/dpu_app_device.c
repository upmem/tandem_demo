#include <stdint.h>
#include <mram.h>
#include "dpu_common.h"
extern __mram_ptr void *__sys_sec_mram_start;
extern __mram_ptr __dma_aligned uint8_t __sys_used_mram_end[0];
__mram_noinit mram_t mram;

#define MRAM_BLOCK_SIZE (8)


int main (void){
    char string [MRAM_BLOCK_SIZE*3] = "Dev hello world!!\0";
    mram_write(string, __sys_sec_mram_start, sizeof(string));
    uint64_t dpu_temp;
    // TODO try new API for mram read
    mram_read((const __mram_ptr void *)&mram.dpu_temperature_value, (void *)&dpu_temp, sizeof(dpu_temp));

    return 0;
}
