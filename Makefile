BUILD_DIR = $(PWD)/libs

.PHONY: all pilot libs server device

all:
	make 32 CC=dpu-upmem-dpurte-clang -C libs/libecc
	make -C libs/libcrypto lib
	make 32 CC=dpu-upmem-dpurte-clang -C pilot
	make -C server
	make -C device

libs:
	make 32 CC=dpu-upmem-dpurte-clang -C libs/libecc
	make -C libs/libcrypto lib

pilot:
	make 32 CC=dpu-upmem-dpurte-clang -C pilot

server:
	make -C server

device:
	make -C device

clean:
	make -C libs/libecc clean
	make -C libs/libcrypto clean
	make -C pilot clean
	make -C server clean
	make -C device clean