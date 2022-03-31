#ifndef DPU_COMMON_H
#define DPU_COMMON_H

#define APP_MAX_SIZE (0x100000)
#define P256_PUB_KEY_SIZE ((256/8)*2)
#define P256_SIG_SIZE ((256/8)*2)
#define SHA256_SIZE (256/8)
#define SIG_DATA_SIZE (P256_PUB_KEY_SIZE + SHA256_SIZE + P256_SIG_SIZE)

#ifndef __dma_aligned
#define __dma_aligned __attribute__((aligned(8)))
#endif

typedef struct {
    unsigned int dpu_policy __dma_aligned;
    volatile unsigned long int verification_status __dma_aligned;
    uint8_t pub_key[P256_PUB_KEY_SIZE] __dma_aligned;
    uint8_t hash[SHA256_SIZE] __dma_aligned ;
    uint8_t signature[P256_SIG_SIZE] __dma_aligned;
    int app_text_size;
    uint8_t		 app_text[APP_MAX_SIZE]  __dma_aligned;
    int app_data_size;
    uint8_t		 app_data[APP_MAX_SIZE]  __dma_aligned;
    volatile uint64_t dpu_temperature_value;
    volatile uint64_t encrypted_temp_value;
    uint8_t		 code[] __dma_aligned;
} mram_t;

#define DPU_POLICY_VERIFY_AND_JUMP  (0)
#define DPU_POLICY_VERIFY_ONLY      (1)

#define VERIFICATION_STATUS_FAILURE (-1)
#define VERIFICATION_STATUS_SUCCESS (0)

void wait (uint32_t seconds);
#endif /* DPU_COMMON_H */
