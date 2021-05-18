# SPDX-License-Identifier: Apache-2.0
# Copyright 2021 IBM Corp.
py = python3
#add location of efitools here. if in PATH, leave bleank
# efitools = ../../efitools/
efitools =../../efitools/
data = testdata/PK_by_PK.auth

#use STATIC=1 for static build
MEMCHECK = 0
ifeq ($(MEMCHECK),1)
	MEMARGS = "MEMCHECK"
else 
	MEMARGS=
endif

#run tests against secvarctl compiled with openssl
OPENSSL = 0
ifeq ($(OPENSSL),1)
	OPENSSL_TESTS = "OPENSSL_TESTS_ONLY"
else 
	OPENSSL_TESTS =
endif

all: $(data) ../secvarctl-cov
	$(py) runTests.py $(MEMARGS)
	$(py) runSvcGenerateTests.py $(MEMARGS) $(OPENSSL_TESTS)

	

generate: $(data)
	$(py) generateTestData.py $(efitools)

../secvarctl-cov:
	make -C ../ secvarctl-cov

clean:
	rm -f -r ./*.txt generatedTestData testenv/*