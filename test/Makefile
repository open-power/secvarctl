py = python3
#add location of efitools here. if in PATH, leave bleank
# efitools = ../../efitools/
efitools =../../efitools/
data = testdata/PK_by_PK.auth
all: $(data) ../secvarctl-cov
	$(py) runTests.py
	$(py) runSvcGenerateTests.py
$(data): generateTestData.py
	$(py) generateTestData.py $(efitools)
../secvarctl-cov:
	make -C ../ secvarctl-cov
clean:
	rm -f -r ./*.txt generatedTestData testenv/*