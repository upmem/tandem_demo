HOST_CC = gcc
DPU_CC = dpu-upmem-dpurte-clang
DPU_OBJCPY = llvm-objcopy
DPU_OBJDUMP = llvm-objdump

ROOT_DIR = ..
PILOT_ROOT_DIR=$(ROOT_DIR)/pilot

WARNING_CFLAGS ?= -Wall -Wextra
HOST_LDFLAGS = `dpu-pkg-config --libs dpu`
HOST_CFLAGS = $(WARNING_CFLAGS) -std=c11 `dpu-pkg-config --cflags dpu` -O2
HOST_CFLAGS += -I$(PILOT_ROOT_DIR)
KEY = $(shell hexdump -v -e '/1 "%02X"' < key)

ifdef SIG_KO
HOST_CFLAGS += -DSIG_KO
endif
ifdef VERIFY_ONLY
HOST_CFLAGS += -DVERIFY_ONLY
endif
BIN_LDFLAGS += -Wl,-T$(ROOT_DIR)/dpu_common/dpu.lds

all: host dpu_app_server

dpu_app_server:
	$(DPU_CC) $(BIN_CFLAGS) dpu_app_server.c $(BIN_LDFLAGS) -o dpu_app_server
	$(DPU_OBJCPY) -O binary --only-section=.text dpu_app_server dpu_app_server.text
	$(DPU_OBJCPY) -O binary --only-section=.data dpu_app_server dpu_app_server.data
    #Generata private key in PEM format - not needed private key is in the remo
	#openssl ecparam -name prime256v1 -genkey -out ec-prime256v1-priv-key.pem
    #Generate public key (text) from private key (remove the initial 0x4) - not needed public key is in the repo
	#openssl ec -in ec-prime256v1-priv-key.pem -text -noout  > public_key.txt
	#Copy bytes manually in a binary called public_key.bin - not needed public key is in the repo
	#ghex public_key.bin
	#Generate SHA-256
	./file_pad dpu_app_server.text dpu_app_server.text.pad
	openssl dgst -binary -sha256 dpu_app_server.text.pad > dpu_app_server.sha256
    #Generate the signature (remove 3046 then 022100 before each coordinate - if not preset discard the signature)
	openssl dgst -sha256 -sign ec-prime256v1-priv-key.pem dpu_app_server.text.pad > dpu_app_server.sig
	#encrypt the text section
	openssl aes-256-ecb -nopad -in  dpu_app_server.text.pad -out  dpu_app_server.text.enc -K $(KEY)
host:
	$(HOST_CC) $(HOST_CFLAGS) host_app_server.c $(HOST_LDFLAGS) -o host_app_server

clean:
	@rm -f host_app_server  dpu_app_server  dpu_app_server.text dpu_app_server.data ec-secp256k1-priv-key.pem public_key.txt hash.txt signature.hex signature.txt

.PHONY: all clean dpu_app_server
