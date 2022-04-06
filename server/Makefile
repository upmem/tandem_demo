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
ifdef VERIFY_ONLY
HOST_CFLAGS += -DVERIFY_ONLY
endif
BIN_LDFLAGS += -Wl,-T$(ROOT_DIR)/dpu_common/dpu.lds -Os

LIBCRYPTO ?= $(ROOT_DIR)/libs/libcrypto.a
LIBCRYPTO_ROOT_DIR=$(ROOT_DIR)/libs/libcrypto

all: clean host dpu_app_server dpu_app_device

dpu_app_server:
	$(DPU_CC) $(BIN_CFLAGS) -I$(ROOT_DIR)/include dpu_app_server.c -I$(LIBCRYPTO_ROOT_DIR)/include $(BIN_LDFLAGS) $(LIBCRYPTO) -o dpu_app_server
	$(DPU_OBJCPY) -O binary --only-section=.text dpu_app_server dpu_app_server.text
	$(DPU_OBJCPY) -O binary --only-section=.data dpu_app_server dpu_app_server.data
    #Generata private key in PEM format - not needed private key is in the remo
	#openssl ecparam -name prime256v1 -genkey -out ec-prime256v1-priv-key.pem
    #Generate public key (text) from private key (remove the initial 0x4) - not needed public key is in the repo
	#openssl ec -in ec-prime256v1-priv-key.pem -text -noout  > public_key.txt
	#Copy bytes manually in a binary called public_key.bin - not needed public key is in the repo
	#ghex public_key.bin
	#Generate SHA-256
	openssl dgst -binary -sha256 dpu_app_server.text > dpu_app_server.sha256
    #Generate the signature (remove 3046 then 022100 before each coordinate - if not preset discard the signature)
	openssl dgst -sha256 -sign ec-prime256v1-priv-key.pem dpu_app_server.text > dpu_app_server.sig
	#encrypt the text section
	openssl aes-256-ecb -nopad -in  dpu_app_server.text -out  dpu_app_server.text.enc -K $(KEY)

dpu_app_device:
	$(DPU_CC) $(BIN_CFLAGS) dpu_app_device.c -I$(ROOT_DIR)/include -I$(LIBCRYPTO_ROOT_DIR)/include ../dpu_common/dpu_common.c $(BIN_LDFLAGS) $(LIBCRYPTO) -o dpu_app_device
	$(DPU_OBJDUMP) -xS  dpu_app_device > dpu_app_device.objdump
	$(DPU_OBJCPY) -O binary --only-section=.text dpu_app_device dpu_app_device.text
	$(DPU_OBJCPY) -O binary --only-section=.data dpu_app_device dpu_app_device.data
    #Generata private key in PEM format - not needed private key is in the remo
	#openssl ecparam -name prime256v1 -genkey -out ec-prime256v1-priv-key.pem
    #Generate public key (text) from private key (remove the initial 0x4) - not needed public key is in the repo
	#openssl ec -in ec-prime256v1-priv-key.pem -text -noout  > public_key.txt
	#Copy bytes manually in a binary called public_key.bin - not needed public key is in the repo
	#ghex public_key.bin
	#Generate SHA-256
	openssl dgst -binary -sha256 dpu_app_device.text > dpu_app_device.sha256
    #Generate the signature (remove 3046 then 022100 before each coordinate - if not preset discard the signature)
	openssl dgst -sha256 -sign ec-prime256v1-priv-key.pem dpu_app_device.text > dpu_app_device.sig
	#encrypt the text section
	openssl aes-256-ecb -nopad -in  dpu_app_device.text -out  dpu_app_device.text.enc -K $(KEY)
	tar -cvf dpu_app_device.tar dpu_app_device*
	rm dpu_app_device.text* dpu_app_device.data dpu_app_device.sig dpu_app_device.sha256 dpu_app_device

host:
	$(HOST_CC) $(HOST_CFLAGS) host_app_server.c ../host_common/host_common.c $(HOST_LDFLAGS) -o host_app_server

clean:
	@rm -f host_app_server  dpu_app_server  dpu_app_server.text dpu_app_server.text.enc dpu_app_server.data temp_sample OK dpu_app_device.tar

.PHONY: all clean dpu_app_server dpu_app_device
