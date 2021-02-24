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

all: $(data) ../secvarctl-cov
	$(py) runTests.py $(MEMARGS)
	$(py) runSvcGenerateTests.py $(MEMARGS)
	

generate: $(data)
	$(py) generateTestData.py $(efitools)

../secvarctl-cov:
	make -C ../ secvarctl-cov

clean:
	rm -f -r ./*.txt generatedTestData testenv/*