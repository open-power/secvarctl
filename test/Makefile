# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
py = python3
#add location of efitools here. if in PATH, leave blank
efitools = ../../efitools/
host_data = host/testdata/PK_by_PK.auth
SECVAR_TOOL ?= $(PWD)/../bin/secvarctl-dbg

#By default host backend static library created
DYNAMIC_LIB = 0
#run tests against secvarctl compiled with openssl
OPENSSL = 1
GNUTLS = 0
HOST_BACKEND = 1
GUEST_BACKEND = 1

define test_host
	$(py) host_tests.py -s $(SECVAR_TOOL) && \
	$(py) host_generate_tests.py -o $(OPENSSL) -g $(GNUTLS) -s $(SECVAR_TOOL)
endef

define test_guest
	$(py) guest_tests.py -s $(SECVAR_TOOL)
endef

# TODO: skip tests if a backend isn't enabled
all: check
check: check-host check-guest

check-%:
	$(call $(patsubst check-%,test_%,$@))

generate: $(host_data)
ifeq ($(strip $(HOST_BACKEND)), 1)
	@cd host/ && \
	$(py) generateTestData.py $(efitools)
endif
ifeq ($(strip $(GUEST_BACKEND)), 1)
	@cd guest/ && \
	$(py) guest_generate_testdata.py $(SECVAR_TOOL)
endif

coverage:
ifeq ("$(wildcard $(SECVAR_TOOL))","")
	@make -C ../ coverage DYNAMIC_LIB=$(DYNAMIC_LIB)
endif

clean:
	rm -rf guest/*.txt guest/generated-data guest/testenv guest/log
	rm -rf host/*.txt host/generatedTestData host/testenv

.PHONY: all coverage clean check check-%
