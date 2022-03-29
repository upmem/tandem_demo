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

all: host dpu_app_server dpu_app_IoT

dpu_app_server:
	$(DPU_CC) $(BIN_CFLAGS) -I$(ROOT_DIR)/include dpu_app_server.c $(BIN_LDFLAGS) -o dpu_app_server
	$(DPU_OBJCPY) -O binary --only-section=.text dpu_app_server dpu_app_server.text
	$(DPU_OBJCPY) -O binary --only-section=.data dpu_app_server dpu_app_server.data
    #Generata private key in PEM format - not needed private key is in the remo
	#openssl ecparam -name prime256v1 -genkey -out ec-prime256v1-priv-key.pem
    #Generate public key (text) from private key (remove the initial 0x4) - not needed public key is in the repo
	#openssl ec -in ec-prime256v1-priv-key.pem -text -noout  > public_key.txt
	#Copy bytes manually in a binary called public_key.bin - not needed public key is in the repo
	#ghex public_key.bin
	#Pad the application to the next 16 byte boundary
	./file_pad dpu_app_server.text dpu_app_server.text.pad
	#Generate SHA-256
	openssl dgst -binary -sha256 dpu_app_server.text.pad > dpu_app_server.sha256
    #Generate the signature (remove 3046 then 022100 before each coordinate - if not preset discard the signature)
	openssl dgst -sha256 -sign ec-prime256v1-priv-key.pem dpu_app_server.text.pad > dpu_app_server.sig
	#encrypt the text section
	openssl aes-256-ecb -nopad -in  dpu_app_server.text.pad -out  dpu_app_server.text.enc -K $(KEY)

dpu_app_IoT:
	$(DPU_CC) $(BIN_CFLAGS) dpu_app_IoT.c $(BIN_LDFLAGS) -o dpu_app_IoT
	$(DPU_OBJCPY) -O binary --only-section=.text dpu_app_IoT dpu_app_IoT.text
	$(DPU_OBJCPY) -O binary --only-section=.data dpu_app_IoT dpu_app_IoT.data
    #Generata private key in PEM format - not needed private key is in the remo
	#openssl ecparam -name prime256v1 -genkey -out ec-prime256v1-priv-key.pem
    #Generate public key (text) from private key (remove the initial 0x4) - not needed public key is in the repo
	#openssl ec -in ec-prime256v1-priv-key.pem -text -noout  > public_key.txt
	#Copy bytes manually in a binary called public_key.bin - not needed public key is in the repo
	#ghex public_key.bin
	#Pad the application to the next 16 byte boundary
	./file_pad dpu_app_IoT.text dpu_app_IoT.text.pad
	#Generate SHA-256
	openssl dgst -binary -sha256 dpu_app_IoT.text.pad > dpu_app_IoT.sha256
    #Generate the signature (remove 3046 then 022100 before each coordinate - if not preset discard the signature)
	openssl dgst -sha256 -sign ec-prime256v1-priv-key.pem dpu_app_IoT.text.pad > dpu_app_IoT.sig
	#encrypt the text section
	openssl aes-256-ecb -nopad -in  dpu_app_IoT.text.pad -out  dpu_app_IoT.text.enc -K $(KEY)
	tar -cvf dpu_app_IoT.tar dpu_app_IoT*
	rm dpu_app_IoT.text* dpu_app_IoT.data dpu_app_IoT.sig dpu_app_IoT.sha256 dpu_app_IoT

host:
	$(HOST_CC) $(HOST_CFLAGS) host_app_server.c ../host_common/host_common.c $(HOST_LDFLAGS) -o host_app_server

clean:
	@rm -f host_app_server  dpu_app_server  dpu_app_server.text dpu_app_server.text.pad dpu_app_server.text.enc dpu_app_server.data ec-secp256k1-priv-key.pem public_key.txt signature.hex signature.txt

.PHONY: all clean dpu_app_server dpu_app_IoT
