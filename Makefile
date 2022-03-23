all:
	make 32 CC=dpu-upmem-dpurte-clang -C libs/libecc
	make -C libs/libcrypto lib