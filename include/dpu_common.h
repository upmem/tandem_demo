#ifndef DPU_COMMON_H
#define DPU_COMMON_H

#ifndef __dma_aligned
#define __dma_aligned __attribute__((aligned(8)))
#endif

#define APP_MAX_SIZE (1024*1024)
#define P256_PUB_KEY_SIZE ((256/8)*2)
#define P256_SIG_SIZE ((256/8)*2)
#define SHA256_SIZE (256/8)
#define AES_BLOCK_SIZE (16)

#define DPU_POLICY_VERIFY_AND_JUMP  (0)
#define DPU_POLICY_VERIFY_ONLY      (1)

#define VERIFICATION_STATUS_FAILURE (-1)
#define VERIFICATION_STATUS_SUCCESS (0)

#define ATF_LOG_BUFFER_SIZE         (80)
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
    volatile uint8_t device_temp_sample[AES_BLOCK_SIZE];
    volatile uint8_t encrypted_device_temp_sample[AES_BLOCK_SIZE];
    uint8_t		 code[] __dma_aligned;
} mram_t;

typedef struct {
    /* log buffer handled by ATF */
    char atf_log_buffer [ATF_LOG_BUFFER_SIZE];
    uint8_t hash[SHA256_SIZE] __dma_aligned ;
    uint8_t app_text[APP_MAX_SIZE]  __dma_aligned;
} sec_mram_t;

void wait (uint32_t seconds);
#endif /* DPU_COMMON_H */
