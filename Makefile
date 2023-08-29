# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2023 IBM Corp.
CC ?= gcc
_CFLAGS = -MMD -std=gnu99 -Wall -Werror
MANDIR=usr/share/man
BIN_DIR = $(PWD)/bin
OBJ_DIR = $(PWD)/obj

# Backend selection, default to both host and guest
HOST_BACKEND  ?= 1
GUEST_BACKEND ?= 1

# Crypto library selection, default to OpenSSL.
CRYPTO_OPTIONS = openssl mbedtls gnutls
CRYPTO ?= openssl

ifeq ($(filter $(CRYPTO),$(CRYPTO_OPTIONS)),)
  $(error CRYPTO must be set to one of: $(CRYPTO_OPTIONS))
endif


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

# Initialize here, so the mbedtls option can add the bonus pkcs7 if needed
EXTERNAL_SRCS =

ifeq ($(CRYPTO), openssl)
  _LDFLAGS += -lcrypto
  _CFLAGS += -DSECVAR_CRYPTO_OPENSSL
endif

ifeq ($(CRYPTO), gnutls)
  _LDFLAGS += -lgnutls
  _CFLAGS += -DSECVAR_CRYPTO_GNUTLS
  EXTERNAL_SRCS += external/skiboot/libstb/secvar/crypto/crypto-gnutls.c
endif

ifeq ($(CRYPTO), mbedtls)
  _LDFLAGS += -lmbedtls -lmbedx509 -lmbedcrypto
  _CFLAGS += -DSECVAR_CRYPTO_MBEDTLS
  INCLUDES += -I./external/extraMbedtls/include/
  EXTERNAL_SRCS += external/extraMbedtls/pkcs7.c \
                   external/extraMbedtls/pkcs7_write.c \
                   external/skiboot/libstb/secvar/crypto/crypto-mbedtls.c
endif


LIBSTB_SECVAR_ROOT ?= external/libstb-secvar/
# LIBSTB_SECVAR_ARCHIVE = libstb-secvar-$(CRYPTO).a # TODO: uncomment when libstb-secvar supports other libraries
LIBSTB_SECVAR_ARCHIVE = libstb-secvar-openssl.a
LIBSTB_SECVAR = $(LIBSTB_SECVAR_ROOT)/lib/$(LIBSTB_SECVAR_ARCHIVE)
# NOTE: currently required for libstb-secvar, should be dependent on crypto library choice
LDFLAGS = -lcrypto


#use STATIC=1 for static build
STATIC = 0
ifeq ($(strip $(STATIC)), 1)
  STATICFLAG= -static
  _LDFLAGS += -lpthread
else
	STATICFLAG=
endif


_LDFLAGS += -L./lib

MAIN_SRCS = generic.c \
            secvarctl.c

ifeq ($(strip $(HOST_BACKEND)), 1)
include backends/host/Makefile.inc
endif

ifeq ($(strip $(GUEST_BACKEND)), 1)
include backends/guest/Makefile.inc
endif


SRCS := $(MAIN_SRCS)
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
	$(MAKE) CFLAGS=-DSECVAR_CRYPTO_WRITE_FUNC -C $(LIBSTB_SECVAR_ROOT) lib/$(LIBSTB_SECVAR_ARCHIVE)


secvarctl: $(BIN_DIR)/secvarctl
secvarctl-dbg: $(BIN_DIR)/secvarctl-dbg
debug: $(BIN_DIR)/secvarctl-dbg
.PHONY: secvarctl secvarctl-dbg debug
SECVAR_TOOL ?= $(BIN_DIR)/secvarctl-dbg

check: $(SECVAR_TOOL)
	@$(MAKE) -C test SECVAR_TOOL=$< check

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
