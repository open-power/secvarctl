# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
#_*_MakeFile_*_
CC = gcc 
_CFLAGS = -MMD -O2 -std=gnu99 -I./ -Iinclude/ -Iexternal/skiboot/ \
	  -Iexternal/skiboot/include -Wall -Werror

DEBUG ?= 0
ifeq ($(DEBUG),1)
_CFLAGS += -g
else
_LDFLAGS += -s
endif

EDK2OBJDIR = backends/edk2-compat
_EDK2_OBJ =  edk2-svc-read.o edk2-svc-write.o edk2-svc-validate.o edk2-svc-verify.o edk2-svc-generate.o
EDK2_OBJ = $(patsubst %,$(EDK2OBJDIR)/%, $(_EDK2_OBJ))

SKIBOOTOBJDIR = external/skiboot/libstb/secvar
_SKIBOOT_OBJ = secvar_util.o backend/edk2-compat.o backend/edk2-compat-process.o
SKIBOOT_OBJ = $(patsubst %,$(SKIBOOTOBJDIR)/%, $(_SKIBOOT_OBJ))

OBJ =secvarctl.o  generic.o 
OBJ +=$(SKIBOOT_OBJ) $(EDK2_OBJ) 

OBJCOV = $(patsubst %.o, %.cov.o,$(OBJ))

MANDIR=usr/share/man
#use STATIC=1 for static build
STATIC = 0
ifeq ($(STATIC),1)
	STATICFLAG=-static
	_LDFLAGS +=-lpthread
else 
	STATICFLAG=
endif

#use SECVAR_CRYPTO_WRITE_FUNC for smaller executable but limited functionality
NO_CRYPTO = 0 
ifeq ($(strip $(NO_CRYPTO)), 0)
	_CFLAGS+=-DSECVAR_CRYPTO_WRITE_FUNC
endif

#Build with crypto library = openssl rather than mbedtls
OPENSSL = 0
ifeq ($(OPENSSL),1)
	_LDFLAGS += -lcrypto
	_CFLAGS += -DSECVAR_CRYPTO_OPENSSL
	CRYPTO_OBJ = $(SKIBOOTOBJDIR)/crypto/crypto-openssl.o
else
	_LDFLAGS += -lmbedtls -lmbedx509 -lmbedcrypto
	_CFLAGS += -DSECVAR_CRYPTO_MBEDTLS

	EXTRAMBEDTLSDIR = external/extraMbedtls
	_EXTRAMBEDTLS = pkcs7_write.o pkcs7.o 
	EXTRAMBEDTLS = $(patsubst %,$(EXTRAMBEDTLSDIR)/%, $(_EXTRAMBEDTLS))
	OBJ += $(EXTRAMBEDTLS)

	CRYPTO_OBJ = $(SKIBOOTOBJDIR)/crypto/crypto-mbedtls.o

endif

OBJ += $(CRYPTO_OBJ)

secvarctl: $(OBJ) 
	$(CC) $(CFLAGS) $(_CFLAGS) $(STATICFLAG) $^  -o $@ $(LDFLAGS) $(_LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(_CFLAGS) -c  $< -o $@

clean:
	find . -name "*.[od]" -delete
	find . -name "*.cov.*" -delete
	rm -f secvarctl secvarctl-cov ./html*

%.cov.o: %.c
	$(CC) $(CFLAGS) $(_CFLAGS) -c  --coverage $< -o $@

secvarctl-cov: $(OBJCOV) 
	$(CC) $(CFLAGS) $(_CFLAGS) $^  $(STATICFLAG) -fprofile-arcs -ftest-coverage -o $@ $(LDFLAGS) $(_LDFLAGS)

install: secvarctl
	mkdir -p $(DESTDIR)/usr/bin
	install -m 0755 secvarctl $(DESTDIR)/usr/bin/secvarctl
	mkdir -p $(DESTDIR)/$(MANDIR)/man1
	install -m 0644 secvarctl.1 $(DESTDIR)/$(MANDIR)/man1

#dont add all c files, extra mbedtls and skiboot should retain its own format
CLANG_FORMAT ?= clang-format
format:
	cp external/linux/.clang-format .
	$(CLANG_FORMAT) --style=file -i *.c include/*.h backends/*/*.c backends/*/*/*.h
	rm .clang-format

-include $(OBJ:.o=.d)
