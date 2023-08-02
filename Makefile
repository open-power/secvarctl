# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2023 IBM Corp.
CC ?= gcc
_CFLAGS = -MMD -std=gnu99 -Wall -Werror
# TODO: just put all the linker flags for now, rework the LDFLAGS settings later
LDFLAGS = -lcrypto -lmbedtls -lmbedx509 -lmbedcrypto
MANDIR=usr/share/man
BIN_DIR = $(PWD)/bin
OBJ_DIR = $(PWD)/obj

# TODO: seriously trim down the number of -I includes. use more relative pathing.
INCLUDES = -I.                                       \
           -I./include                               \
           -I./external/libstb-secvar/               \
           -I./external/libstb-secvar/include        \
           -I./external/libstb-secvar/include/secvar

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
OBJDBG = $(patsubst %.o, %.dbg.o,$(OBJS))
DEPS = $(OBJS:.o=.d)

_CFLAGS += $(CFLAGS)
_LDFLAGS += $(LDFLAGS)

ifneq ($(DISABLE_ASAN),1)
SANITIZE_FLAGS = -fsanitize=address              \
                 -fsanitize=undefined            \
                 -fno-sanitize-recover=all       \
                 -fsanitize=float-divide-by-zero \
                 -fsanitize=float-cast-overflow  \
                 -fno-sanitize=null              \
                 -fno-sanitize=alignment
endif

DEBUG_CFLAGS = -g -O0 --coverage
RELEASE_CFLAGS = -s -O2

export CFLAGS
export LDFLAGS

all: secvarctl

-include $(DEPS)

$(OBJ_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(RELEASE_CFLAGS) $(_CFLAGS) $(INCLUDES) $< -o $@ -c

$(OBJ_DIR)/%.dbg.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(DEBUG_CFLAGS) $(_CFLAGS) $(SANITIZE_FLAGS) $(INCLUDES) -c  $< -o $@

$(BIN_DIR)/secvarctl: $(OBJS) $(LIBSTB_SECVAR)
	@mkdir -p $(BIN_DIR)
	$(CC) $(_CFLAGS) $(STATICFLAG) $^ -o $@ $(_LDFLAGS)

$(BIN_DIR)/secvarctl-dbg: $(OBJDBG) $(LIBSTB_SECVAR)
	@mkdir -p $(BIN_DIR)
	$(CC) $(_CFLAGS) -g $^ $(STATICFLAG) $(SANITIZE_FLAGS) -fprofile-arcs -ftest-coverage -o $@ $(_LDFLAGS)

$(LIBSTB_SECVAR):
	$(MAKE) CFLAGS=-DSECVAR_CRYPTO_WRITE_FUNC -C external/libstb-secvar lib/libstb-secvar-openssl.a


secvarctl: $(BIN_DIR)/secvarctl
secvarctl-dbg: $(BIN_DIR)/secvarctl-dbg
debug: $(BIN_DIR)/secvarctl-dbg
.PHONY: secvarctl secvarctl-dbg debug

check: secvarctl-dbg
	@$(MAKE) -C test MEMCHECK=$(MEMCHECK) OPENSSL=$(OPENSSL) GNUTLS=$(GNUTLS) \
	                 HOST_BACKEND=$(HOST_BACKEND) \
	                 SECVAR_TOOL=$(addprefix $(BIN_DIR)/,$<) \
	                 check

CPPCHECK_FLAGS =  --enable=all --force -q --error-exitcode=1
CPPCHECK_FLAGS += --suppress=missingIncludeSystem
CPPCHECK_FLAGS += --suppress=unusedFunction       # false positive on validateTS
CPPCHECK_FLAGS += --suppress=internalAstError     # false positive on ccan/list_for_each
cppcheck:
	cppcheck $(CPPCHECK_FLAGS) $(INCLUDES) $(MAIN_SRCS)

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

formatcheck:
	@$(CLANG_FORMAT) --style=file:external/linux/.clang-format -Werror --dry-run $(MAIN_SRCS) $(HEADERS)

clean:
	@$(MAKE) -C test clean
	$(MAKE) -C external/libstb-secvar/ clean
	rm -rf $(BIN_DIR)
	rm -rf $(OBJ_DIR)

.PHONY: all generate install uninstall format formatcheck clean
