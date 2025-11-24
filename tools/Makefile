# Path to mbedtls
MBEDTLS_DIR ?=
ifeq ($(strip $(MBEDTLS_DIR)),)
	INCLUDES =
	LIBPATH =
else
	INCLUDES = -I$(MBEDTLS_DIR)/include
	LIBPATH = -L$(MBEDTLS_DIR)/build/library
endif

LIBS = -lmbedx509 -lmbedtls -lmbedcrypto

# Compiler
CC = gcc
CFLAGS = -Wall -Wextra $(INCLUDES)
LDFLAGS = $(LIBPATH) $(LIBS)

# Source and executable
SRC = verify.c
OUT = verify

all: $(OUT)

$(OUT): $(SRC)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

clean:
	rm -f $(OUT)

