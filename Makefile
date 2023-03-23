# SPDX-License-Identifier: Apache-2.0
# Copyright 2022-2023 IBM Corp.
CC = gcc
_CFLAGS = -MMD -O2 -std=gnu99 -Wall -Werror
CFLAGS =
LDFLAGS =

SECVAR_TOOL = $(PWD)/secvarctl-cov
MANDIR=usr/share/man
LIB_DIR = ../../lib
BIN_DIR = .
HOST_BACKEND_DIR = ./backends/host
GUEST_BACKEND_DIR = ./backends/guest

INCLUDES = -I./include

#By default host backend static library created
DYNAMIC_LIB = 0
#it is used to enable memory leak test in test sript
MEMCHECK = 0

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
  INCLUDES += -I./external/host/skiboot \
              -I./external/host/skiboot/libstb \
              -I./external/host/skiboot/include \
              -I$(HOST_BACKEND_DIR)
  _LDFLAGS += -lhost-backend-$(CRYPTO_LIB)
  _CFLAGS += -DSECVAR_HOST_BACKEND
endif

ifeq ($(strip $(GUEST_BACKEND)), 1)
  INCLUDES += -I$(GUEST_BACKEND_DIR)/include
  LDFLAGS += -lguest-backend-openssl -lstb-secvar-openssl
  CFLAGS += -DSECVAR_GUEST_BACKEND
endif

_LDFLAGS += -L./lib

SECVARCTL_SRCS = ./src/generic.c \
                 ./src/secvarctl.c

SECVARCTL_OBJS = $(SECVARCTL_SRCS:.c=.o)
OBJCOV = $(patsubst %.o, %.cov.o,$(SECVARCTL_OBJS))

_CFLAGS += $(CFLAGS) $(INCLUDES)
_LDFLAGS += $(LDFLAGS)

export CFLAGS
export LDFLAGS

all: secvarctl-backends secvarctl secvarctl-cov

coverage: secvarctl-backends secvarctl-cov

secvarctl: $(SECVARCTL_OBJS)
	$(CC) $(_CFLAGS) $(STATICFLAG) $^ -o $(BIN_DIR)/$@ $(_LDFLAGS)
	@echo "secvarctl Build successful!"

secvarctl-cov: $(OBJCOV)
	$(CC) $(_CFLAGS) $^ $(STATICFLAG) -fprofile-arcs -ftest-coverage -o $(BIN_DIR)/$@ $(_LDFLAGS)
	@echo "secvarctl-cov Build successful!"

secvarctl-backends:
	@mkdir -p $(LIB_DIR)
ifeq ($(strip $(HOST_BACKEND)), 1)
	@$(MAKE) -C $(HOST_BACKEND_DIR) LIB_DIR=$(LIB_DIR) OPENSSL=$(OPENSSL) GNUTLS=$(GNUTLS) \
	            MBEDTLS=$(MBEDTLS) CRYPTO_READ_ONLY=$(CRYPTO_READ_ONLY) DEBUG=$(DEBUG) \
	            DYNAMIC_LIB=$(DYNAMIC_LIB)
endif
ifeq ($(strip $(GUEST_BACKEND)), 1)
	@$(MAKE) -C $(GUEST_BACKEND_DIR) DEBUG=$(DEBUG) LIB_DIR=$(LIB_DIR) \
	            CRYPTO_READ_ONLY=$(CRYPTO_READ_ONLY) DYNAMIC_LIB=$(DYNAMIC_LIB)
endif

%.o: %.c
	$(CC) $(_CFLAGS) $< -o $@ -c

%.cov.o: %.c
	$(CC) $(_CFLAGS) -c  --coverage $< -o $@

check:
	@$(MAKE) -C test MEMCHECK=$(MEMCHECK) OPENSSL=$(OPENSSL) GNUTLS=$(GNUTLS) \
	                 DYNAMIC_LIB=$(DYNAMIC_LIB) HOST_BACKEND=$(HOST_BACKEND) \
	                 SECVAR_TOOL=$(SECVAR_TOOL)
generate:
	@$(MAKE) -C test generate MEMCHECK=$(MEMCHECK) OPENSSL=$(OPENSSL) GNUTLS=$(GNUTLS) \
	                 DYNAMIC_LIB=$(DYNAMIC_LIB) HOST_BACKEND=$(HOST_BACKEND) \
	                 SECVAR_TOOL=$(SECVAR_TOOL)

install: all
	@mkdir -p $(DESTDIR)/usr/bin
	@install -m 0755 secvarctl $(DESTDIR)/usr/bin/secvarctl
	@mkdir -p $(DESTDIR)/$(MANDIR)/man1
	@install -m 0644 secvarctl.1 $(DESTDIR)/$(MANDIR)/man1
	@mkdir -p $(DESTDIR)/usr/lib/secvarctl
	@install -m 0755 ./lib/* $(DESTDIR)/usr/lib/secvarctl
ifeq ($(strip $(DYNAMIC_LIB)), 1)
	@echo "$(DESTDIR)/usr/lib/secvarctl" > /etc/ld.so.conf.d/secvarctl.conf
	@ldconfig
endif
	@echo "secvarctl installed successfully!"

uninstall:
	@rm -rf $(DESTDIR)/usr/bin/secvarctl
	@rm -rf $(DESTDIR)/$(MANDIR)/man1/secvarctl.1
	@rm -rf $(DESTDIR)/usr/lib/secvarctl
ifeq ($(strip $(DYNAMIC_LIB)), 1)
	@rm -rf /etc/ld.so.conf.d/secvarctl.conf
	@ldconfig
endif
	@echo "secvarctl uninstalled successfully!"

clean:
ifeq ($(strip $(HOST_BACKEND)), 1)
	@$(MAKE) -C $(HOST_BACKEND_DIR) clean
endif
ifeq ($(strip $(GUEST_BACKEND)), 1)
	@$(MAKE) -C $(GUEST_BACKEND_DIR) clean
endif
	@$(MAKE) -C test clean
	find . -name "*.[od]" -delete
	find . -name "*.cov.*" -delete
	rm -rf ./lib
	rm -f $(BIN_DIR)/secvarctl $(BIN_DIR)/secvarctl-cov

.PHONY: all secvarctl-backends coverage clean
