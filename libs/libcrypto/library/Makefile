
DPU_CC = dpu-upmem-dpurte-clang
DPU_AR = llvm-ar

CRYPTO_INCLUDES ?= -I../include

WARNING_CFLAGS ?= -Wall -Wextra

DPU_CFLAGS = $(WARNING_CFLAGS) $(CRYPTO_INCLUDES) -Os

LIB_FILE = ../../libcrypto.a

# Set AR_DASH= (empty string) to use an ar implementation that does not accept
# the - prefix for command line options (e.g. llvm-ar)
AR_DASH =

ARFLAGS = $(AR_DASH)src

CRYPTO_SOURCES = $(wildcard *.c)
CRYPTO_OBJS = $(CRYPTO_SOURCES:.c=.o)

.SILENT:

.PHONY: all clean

all: libcrypto

# crypto
libcrypto: $(CRYPTO_OBJS)
	echo "  AR    $@"
	$(DPU_AR) $(ARFLAGS) $(LIB_FILE) $(CRYPTO_OBJS)

%.o : %.c
	echo "  CLANG    $<"
	$(DPU_CC) $(DPU_CFLAGS) -o $@ -c $<

clean:
	rm -f libdpucrypto.a $(CRYPTO_OBJS) $(LIB_FILE)