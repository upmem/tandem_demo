DPU_CC = dpu-upmem-dpurte-clang
DPU_OBJCPY = llvm-objcopy
DPU_OBJDUMP = llvm-objdump

ROOT_DIR = ..
LIBECC_ROOT_DIR=$(ROOT_DIR)/libs/libecc
LIBCRYPTO_ROOT_DIR=$(ROOT_DIR)/libs/libcrypto


include $(LIBECC_ROOT_DIR)/common.mk

LIBCRYPTO ?= $(ROOT_DIR)/libs/libcrypto.a
LIBSIGN = $(ROOT_DIR)/libs/libsign.a

CFLAGS += -I$(LIBECC_ROOT_DIR)/src/ -I$(LIBECC_ROOT_DIR)/src/external_deps -I$(LIBCRYPTO_ROOT_DIR)/include -I$(ROOT_DIR)/include

WARNING_CFLAGS ?= -Wall -Wextra
BIN_LDFLAGS += -Wl,-T$(ROOT_DIR)/dpu_common/dpu.lds

NR_TASKLETS ?= 1
DPU_TASKLETFLAGS = -DNR_TASKLETS=${NR_TASKLETS} -DSTACK_SIZE_DEFAULT=768

all: dpu_pilot

dpu_pilot:
	$(DPU_CC) $(BIN_CFLAGS)  dpu_ecdsa_pilot.c $(LIBECC_ROOT_DIR)/src/external_deps/rand.c dpu_jump.c  $(LIBSIGN) $(BIN_LDFLAGS) $(DPU_TASKLETFLAGS) -o dpu_ecdsa_pilot
	$(DPU_OBJDUMP) -xS  dpu_ecdsa_pilot > dpu_ecdsa_pilot.objdump
	$(DPU_CC) $(BIN_CFLAGS) dpu_hash_pilot.c $(LIBSIGN) $(BIN_LDFLAGS) -o dpu_hash_pilot
	$(DPU_CC) $(BIN_CFLAGS) dpu_aes_pilot.c  dpu_jump.c $(BIN_LDFLAGS) $(LIBCRYPTO) -o dpu_aes_pilot


clean:
	@rm -f dpu_ecdsa_pilot  dpu_ecdsa_pilot.objdump  dpu_hash_pilot dpu_aes_pilot

.PHONY: all clean
