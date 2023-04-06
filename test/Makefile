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

all: coverage
ifeq ($(strip $(HOST_BACKEND)), 1)
	@cd host/ && \
	$(py) runTests.py -m $(MEMCHECK) -s $(SECVAR_TOOLS) && \
	$(py) runSvcGenerateTests.py -m $(MEMCHECK) -o $(OPENSSL) -g $(GNUTLS) -s $(SECVAR_TOOLS)
endif
ifeq ($(strip $(GUEST_BACKEND)), 1)
	@cd guest/ && \
	$(py) guest_tests.py -m $(MEMCHECK) -s $(SECVAR_TOOLS)
endif

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

.PHONY: all coverage clean
