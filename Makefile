# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2023 IBM Corp.
CC = gcc
_CFLAGS = -MMD -O2 -std=gnu99 -Wall -Werror
CFLAGS =
# TODO: just put all the linker flags for now, rework the LDFLAGS settings later
LDFLAGS = -lcrypto -lmbedtls -lmbedx509 -lmbedcrypto
SECVAR_TOOL = $(PWD)/bin/secvarctl-cov
MANDIR=usr/share/man
BIN_DIR = bin
OBJ_DIR = obj

# TODO: seriously trim down the number of -I includes. use more relative pathing.
INCLUDES = -I.                                       \
           -I./include                               \
           -I./external/libstb-secvar/               \
           -I./external/libstb-secvar/include        \
           -I./external/libstb-secvar/include/secvar

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

# TODO: Split libstb-secvar Makefile into includeable and runnable probably
LIBSTB_SECVAR = external/libstb-secvar/lib/libstb-secvar-openssl.a

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
else ifeq ($(strip $(GNUTLS)), 1)
  _LDFLAGS += -lgnutls
  _CFLAGS += -DSECVAR_CRYPTO_GNUTLS
else ifeq ($(strip $(MBEDTLS)), 1)
  _LDFLAGS += -lmbedtls -lmbedx509 -lmbedcrypto
  _CFLAGS += -DSECVAR_CRYPTO_MBEDTLS
endif

#use STATIC=1 for static build
STATIC = 0
ifeq ($(strip $(STATIC)), 1)
  STATICFLAG= -static
  _LDFLAGS += -lpthread
else
	STATICFLAG=
endif

HOST_BACKEND = 1
GUEST_BACKEND = 1

ifeq ($(strip $(HOST_BACKEND)), 1)
  INCLUDES += -I./external/skiboot               \
              -I./external/skiboot/libstb        \
              -I./external/skiboot/include       \
              -I./external/extraMbedtls/include/ \
              -I./backends/host
  _CFLAGS += -DSECVAR_HOST_BACKEND
endif

ifeq ($(strip $(GUEST_BACKEND)), 1)
  INCLUDES += -I./backends/guest/include
  CFLAGS += -DSECVAR_GUEST_BACKEND
endif

_LDFLAGS += -L./lib

SVC_SRCS = generic.c \
           secvarctl.c

# TODO: Consider splitting this also into its own Makefile.inc?
EXTERNAL_SRCS = external/extraMbedtls/pkcs7.c                                \
                external/extraMbedtls/pkcs7_write.c                          \
                external/skiboot/libstb/secvar/secvar_util.c                 \
                external/skiboot/libstb/secvar/crypto/crypto-mbedtls.c       \
                external/skiboot/libstb/secvar/crypto/crypto-openssl.c       \
                external/skiboot/libstb/secvar/crypto/crypto-gnutls.c        \
                external/skiboot/libstb/secvar/backend/edk2-compat.c         \
                external/skiboot/libstb/secvar/backend/edk2-compat-process.c

include backends/host/Makefile.inc
include backends/guest/Makefile.inc

SRCS  = $(SVC_SRCS)
SRCS += $(addprefix backends/host/,$(HOST_SRCS))
SRCS += $(addprefix backends/guest/,$(GUEST_SRCS))

# Copy for format-related targets, so they ignore the external files
MAIN_SRCS := $(SRCS)

SRCS += $(EXTERNAL_SRCS)

OBJS = $(addprefix $(OBJ_DIR)/,$(SRCS:.c=.o))
OBJCOV = $(patsubst %.o, %.cov.o,$(OBJS))
DEPS = $(OBJS:.o=.d)

_CFLAGS += $(CFLAGS) $(INCLUDES)
_LDFLAGS += $(LDFLAGS)

export CFLAGS
export LDFLAGS

all: secvarctl

-include $(DEPS)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(_CFLAGS) $< -o $@ -c

$(OBJ_DIR)/%.cov.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(_CFLAGS) -c --coverage $< -o $@

$(BIN_DIR)/secvarctl: $(OBJS) $(LIBSTB_SECVAR)
	@mkdir -p $(BIN_DIR)
	$(CC) $(_CFLAGS) $(STATICFLAG) $^ -o $@ $(_LDFLAGS)

$(BIN_DIR)/secvarctl-cov: $(OBJCOV) $(LIBSTB_SECVAR)
	@mkdir -p $(BIN_DIR)
	$(CC) $(_CFLAGS) $^ $(STATICFLAG) -fprofile-arcs -ftest-coverage -o $@ $(_LDFLAGS)

$(LIBSTB_SECVAR):
	$(MAKE) CFLAGS=-DSECVAR_CRYPTO_WRITE_FUNC -C external/libstb-secvar lib/libstb-secvar-openssl.a


secvarctl: $(BIN_DIR)/secvarctl
secvarctl-cov: $(BIN_DIR)/secvarctl-cov
.PHONY: secvarctl secvarctl-cov

check: secvarctl-cov
	@$(MAKE) -C test MEMCHECK=$(MEMCHECK) OPENSSL=$(OPENSSL) GNUTLS=$(GNUTLS) \
	                 HOST_BACKEND=$(HOST_BACKEND) \
	                 SECVAR_TOOL=$(SECVAR_TOOL) \
	                 check

memcheck: secvarctl-cov
	@$(MAKE) -C test MEMCHECK=$(MEMCHECK) OPENSSL=$(OPENSSL) GNUTLS=$(GNUTLS) \
	                 HOST_BACKEND=$(HOST_BACKEND) \
	                 SECVAR_TOOL=$(SECVAR_TOOL) \
	                 memcheck

cppcheck:
	cppcheck --enable=all --suppress=missingIncludeSystem --force -q \
	         $(INCLUDES) $(MAIN_SRCS)

generate:
	@$(MAKE) -C test generate MEMCHECK=$(MEMCHECK) OPENSSL=$(OPENSSL) GNUTLS=$(GNUTLS) \
	                 HOST_BACKEND=$(HOST_BACKEND) \
	                 SECVAR_TOOL=$(SECVAR_TOOL)

install: all
	@mkdir -p $(DESTDIR)/usr/bin
	@install -m 0755 secvarctl $(DESTDIR)/usr/bin/secvarctl
	@mkdir -p $(DESTDIR)/$(MANDIR)/man1
	@install -m 0644 secvarctl.1 $(DESTDIR)/$(MANDIR)/man1
	@mkdir -p $(DESTDIR)/usr/lib/secvarctl
	@install -m 0755 ./lib/* $(DESTDIR)/usr/lib/secvarctl
	@echo "secvarctl installed successfully!"

uninstall:
	@rm -rf $(DESTDIR)/usr/bin/secvarctl
	@rm -rf $(DESTDIR)/$(MANDIR)/man1/secvarctl.1
	@rm -rf $(DESTDIR)/usr/lib/secvarctl
	@echo "secvarctl uninstalled successfully!"

CLANG_FORMAT ?= clang-format
HEADERS = $(shell find . ! \( -path ./external -prune \) -name "*.h" -type f)
format:
	@$(CLANG_FORMAT) --style=file:external/linux/.clang-format -i $(MAIN_SRCS) $(HEADERS)

clean:
	@$(MAKE) -C test clean
	$(MAKE) -C external/libstb-secvar/ clean
	rm -rf $(BIN_DIR)
	rm -rf $(OBJ_DIR)

.PHONY: all generate install uninstall format clean
