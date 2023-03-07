CC = gcc
_CFLAGS += -Wall -Werror -MMD -ggdb3 -fPIC
CFLAGS =
LDFLAGS =

LIB_DIR=./lib

HOST_INDCLUDES = -I../../include \
                 -I../../external/host/skiboot/libstb \
                 -I../../external/host/skiboot \
                 -I../../external/host/skiboot/include \
                 -I./

SKIBOOT_DIR = ../../external/host/skiboot/libstb/secvar
MBEDTLS_DIR = ../../external/host/extraMbedtls

CRYPTO_SRC =

DEBUG ?= 0
ifeq ($(strip $(DEBUG)), 1)
  _CFLAGS += -g
else
  _LDFLAGS += -s
endif

#use CRYPTO_READ_ONLY for smaller executable but limited functionality
#removes all write functions (secvarctl generate, pem_to_der etc.)
CRYPTO_READ_ONLY = 0
ifeq ($(strip $(CRYPTO_READ_ONLY)), 0)
  _CFLAGS += -DSECVAR_CRYPTO_WRITE_FUNC
endif

#By default, Build with crypto library openssl
OPENSSL = 1
GNUTLS = 0
MBEDTLS = 0
CRYPTO_LIB = openssl

ifeq ($(strip $(GNUTLS)), 1)
  MBEDTLS = 0
  OPENSSL = 0
  CRYPTO_LIB = gnutls
endif

ifeq ($(strip $(MBEDTLS)), 1)
  GNUTLS = 0
  OPENSSL = 0
  CRYPTO_LIB = mbedtls
endif

ifeq ($(strip $(OPENSSL)), 1)
  _LDFLAGS += -lcrypto
  _CFLAGS += -DSECVAR_CRYPTO_OPENSSL
  CRYPTO_SRC = $(SKIBOOT_DIR)/crypto/crypto-openssl.c
else ifeq ($(strip $(GNUTLS)), 1)
  _LDFLAGS += -lgnutls
  _CFLAGS += -DSECVAR_CRYPTO_GNUTLS
  CRYPTO_SRC = $(SKIBOOT_DIR)/crypto/crypto-gnutls.c
else ifeq ($(strip $(MBEDTLS)), 1)
  _LDFLAGS += -lmbedtls -lmbedx509 -lmbedcrypto
  _CFLAGS += -DSECVAR_CRYPTO_MBEDTLS
  HOST_INDCLUDES += -I$(MBEDTLS_DIR)/include
  CRYPTO_SRC = $(MBEDTLS_DIR)/pkcs7_write.c \
	             $(MBEDTLS_DIR)/pkcs7.c
endif

#By default, static library created
DYNAMIC_LIB = 0
ifeq ($(strip $(DYNAMIC_LIB)), 1)
  LD = gcc
else
  LD = ar -rcs
endif

HOST_SRCS = ./host_svc_read.c \
            ./host_svc_write.c \
            ./host_svc_validate.c \
            ./host_svc_verify.c \
            ./host_svc_generate.c

#SKIBOOT SRCS
HOST_SRCS += $(SKIBOOT_DIR)/secvar_util.c \
             $(SKIBOOT_DIR)/backend/edk2-compat.c \
             $(SKIBOOT_DIR)/backend/edk2-compat-process.c

HOST_SRCS += $(CRYPTO_SRC)

HOST_OBJS = $(HOST_SRCS:.c=.o)

_CFLAGS += $(CFLAGS) $(HOST_INDCLUDES)
_LDFLAGS += $(LDFLAGS)

all: host-backend

host-backend: dirmake libhost-backend-$(CRYPTO_LIB)

$(HOST_OBJS):%.o: %.c
	$(CC) $(_CFLAGS) $< -o $@ -c

libhost-backend-$(CRYPTO_LIB): $(HOST_OBJS)
ifeq ($(strip $(DYNAMIC_LIB)), 1)
	$(LD) $(_LDFLAGS) -shared $^ -o $(LIB_DIR)/$@.so
else
	$(LD) $(LIB_DIR)/$@.a $^
endif
	@echo "Host Backend Build successful!"

dirmake:
	@mkdir -p $(LIB_DIR)

clean:
	find $(SKIBOOT_DIR)/ -name "*.[od]" -delete
	find $(MBEDTLS_DIR)/ -name "*.[od]" -delete
	find ./ -name "*.[od]" -delete
	rm -rf $(LIB_DIR)

.PHONY: all clean
