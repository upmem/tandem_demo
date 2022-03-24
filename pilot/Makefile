DPU_CC = dpu-upmem-dpurte-clang
DPU_OBJCPY = llvm-objcopy
DPU_OBJDUMP = llvm-objdump

ROOT_DIR = ..
LIBECC_ROOT_DIR=$(ROOT_DIR)/libs/libecc
LIBCRYPTO_ROOT_DIR=$(ROOT_DIR)/libs/libcrypto

include $(LIBECC_ROOT_DIR)/common.mk

LIBCRYPTO ?= $(ROOT_DIR)/libs/libcrypto.a
LIBSIGN = $(ROOT_DIR)/libs/libsign.a

CFLAGS += -I$(LIBECC_ROOT_DIR)/src/ -I$(LIBECC_ROOT_DIR)/src/external_deps -I$(LIBCRYPTO_ROOT_DIR)/include

WARNING_CFLAGS ?= -Wall -Wextra
BIN_LDFLAGS += -Wl,-T$(ROOT_DIR)/dpu_common/dpu.lds

all: dpu_pilot

dpu_pilot:
	$(DPU_CC) $(BIN_CFLAGS) dpu_ecdsa_pilot.c $(LIBECC_ROOT_DIR)/src/external_deps/rand.c dpu_jump.c  $(LIBSIGN) $(BIN_LDFLAGS) -o dpu_ecdsa_pilot
	$(DPU_OBJDUMP) -xS  dpu_ecdsa_pilot > dpu_ecdsa_pilot.objdump
	$(DPU_CC) $(BIN_CFLAGS) dpu_hash_pilot.c $(LIBSIGN) $(BIN_LDFLAGS) -o dpu_hash_pilot

clean:
	@rm -f dpu_ecdsa_pilot  dpu_ecdsa_pilot.objdump  

.PHONY: all clean
