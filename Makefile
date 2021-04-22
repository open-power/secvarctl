# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
#_*_MakeFile_*_
CC = gcc 
_CFLAGS = -MMD -O2 -std=gnu99 -I./ -Iinclude/ -Wall -Werror

DEBUG ?= 0
ifeq ($(DEBUG),1)
_CFLAGS += -g
else
_LDFLAGS += -s
endif

EDK2OBJDIR = backends/edk2-compat
_EDK2_OBJ =  edk2-svc-read.o edk2-svc-write.o edk2-svc-validate.o edk2-svc-verify.o edk2-svc-generate.o
EDK2_OBJ = $(patsubst %,$(EDK2OBJDIR)/%, $(_EDK2_OBJ))

SKIBOOTOBJDIR = external/skiboot/
_SKIBOOT_OBJ = secvar_util.o edk2-compat.o edk2-compat-process.o
SKIBOOT_OBJ = $(patsubst %,$(SKIBOOTOBJDIR)/%, $(_SKIBOOT_OBJ))

OBJ =secvarctl.o  generic.o 
OBJ +=$(SKIBOOT_OBJ) $(EDK2_OBJ) 

OBJCOV = $(patsubst %.o, %.cov.o,$(OBJ))

MANDIR=usr/local/share/man
#use STATIC=1 for static build
STATIC = 0
ifeq ($(STATIC),1)
	STATICFLAG=-static
	_LDFLAGS +=-lpthread
else 
	STATICFLAG=
endif

#use NO_CRYPTO for smaller executable but limited functionality
NO_CRYPTO = 0 
ifeq ($(NO_CRYPTO),1)
	_CFLAGS+=-DNO_CRYPTO
endif

#Build with crypto library = openssl rather than mbedtls
OPENSSL = 0
ifeq ($(OPENSSL),1)
	_LDFLAGS += -lcrypto
	_CFLAGS += -DOPENSSL
	CRYPTO_OBJ = crypto/crypto-openssl.o
else
	_LDFLAGS += -lmbedtls -lmbedx509 -lmbedcrypto
	_CFLAGS += -DMBEDTLS

	EXTRAMBEDTLSDIR = external/extraMbedtls
	_EXTRAMBEDTLS = generate-pkcs7.o pkcs7.o 
	EXTRAMBEDTLS = $(patsubst %,$(EXTRAMBEDTLSDIR)/%, $(_EXTRAMBEDTLS))
	OBJ += $(EXTRAMBEDTLS)

	CRYPTO_OBJ = crypto/crypto-mbedtls.o

endif

OBJ += $(CRYPTO_OBJ)

secvarctl: $(OBJ) 
	$(CC) $(CFLAGS) $(_CFLAGS) $(STATICFLAG) $^  -o $@ $(LDFLAGS) $(_LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(_CFLAGS) -c  $< -o $@

clean:
	rm -f $(OBJ) secvarctl 
	rm -f $(OBJ:.o=.d)
	rm -f ./*/*.cov.* secvarctl-cov ./*.cov.* ./backends/*/*.cov.* ./external/*/*.cov.* ./html*

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
	$(CLANG_FORMAT) --style=file -i *.c include/*.h crypto/*.c crypto/*.h backends/*/*.c backends/*/*/*.h
	rm .clang-format

-include $(OBJ:.o=.d)
