HOST_CC = gcc
DPU_CC = dpu-upmem-dpurte-clang
DPU_OBJCPY = llvm-objcopy
DPU_OBJDUMP = llvm-objdump

ROOT_DIR = ..
PILOT_ROOT_DIR=$(ROOT_DIR)/pilot

WARNING_CFLAGS ?= -Wall -Wextra
HOST_LDFLAGS = `dpu-pkg-config --libs dpu`
HOST_CFLAGS = $(WARNING_CFLAGS) -std=c11 `dpu-pkg-config --cflags dpu` -O2
HOST_CFLAGS += -I$(ROOT_DIR)/include
KEY = $(shell hexdump -v -e '/1 "%02X"' < key)

ifdef SIG_KO
HOST_CFLAGS += -DSIG_KO
endif
BIN_LDFLAGS += -Wl,-T$(ROOT_DIR)/dpu_common/dpu.lds -Os

all: host host

host:
	$(HOST_CC) $(HOST_CFLAGS) host_app_device.c ../host_common/host_common.c ../pilot/pilot.c $(HOST_LDFLAGS) -o host_app_device

clean:
	@rm -f host_app_device dpu_app_device.tar  dpu_app_device  dpu_app_device.text dpu_app_device.text.enc dpu_app_device.data

.PHONY: all clean  host