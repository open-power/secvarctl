# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
py = python3
#add location of efitools here. if in PATH, leave bleank
# efitools = ../../efitools/
efitools =../../efitools/
host_data = host/testdata/PK_by_PK.auth
SECVAR_TOOL = ../secvarctl-cov

#By default host backend static library created
DYNAMIC_LIB = 0
MEMCHECK = 0
#run tests against secvarctl compiled with openssl
OPENSSL = 1
GNUTLS = 0
HOST_BACKEND = 1
GUEST_BACKEND = 1

ifeq ($(SECVAR_TOOL), ../secvarctl-cov)
   SECVAR_TOOLS = ../$(SECVAR_TOOL)
else
   SECVAR_TOOLS = $(SECVAR_TOOL)
endif

define test_host
	@cd host/ && \
	$(py) runTests.py -m $(1) -s $(SECVAR_TOOLS) && \
	$(py) runSvcGenerateTests.py -m $(1) -o $(OPENSSL) -g $(GNUTLS) -s $(SECVAR_TOOLS)
endef

define test_guest
	@cd guest/ && \
	$(py) guest_tests.py -m $(1) -s $(SECVAR_TOOLS)
endef

# TODO: skip tests if a backend isn't enabled
all: check
check: check-host check-guest
memcheck: memcheck-host memcheck-guest

check-%:
	$(call $(patsubst check-%,test_%,$@),0)

memcheck-%:
	$(call $(patsubst check-%,test_%,$@),1)

generate: $(host_data)
ifeq ($(strip $(HOST_BACKEND)), 1)
	@cd host/ && \
	$(py) generateTestData.py $(efitools)
endif
ifeq ($(strip $(GUEST_BACKEND)), 1)
	@cd guest/ && \
	$(py) guest_generate_testdata.py $(SECVAR_TOOLS)
endif

coverage:
ifeq ("$(wildcard $(SECVAR_TOOL))","")
	@make -C ../ coverage DYNAMIC_LIB=$(DYNAMIC_LIB)
endif

clean:
	rm -rf guest/*.txt guest/generated-data guest/testenv guest/log
	rm -rf host/*.txt host/generatedTestData host/testenv

.PHONY: all coverage clean check memcheck check-% memcheck-%
