BUILD_DIR = $(PWD)/libs

.PHONY: all pilot libs server

all:
	make 32 CC=dpu-upmem-dpurte-clang -C libs/libecc
	make -C libs/libcrypto lib
	make 32 CC=dpu-upmem-dpurte-clang -C pilot
	make -C server

libs:
	make 32 CC=dpu-upmem-dpurte-clang -C libs/libecc
	make -C libs/libcrypto lib

pilot:
	make 32 CC=dpu-upmem-dpurte-clang -C pilot

server:
	make -C server
