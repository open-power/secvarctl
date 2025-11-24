# verify-tool
## PKCS#7 Signature Verification Utility
This utility verifies PKCS#7 (CMS) signatures against content files using the Mbed TLS library. It supports both detached and appended signatures, verification with local certificates, Secure variables from PKS, and supports multi-signer PKCS#7 files.

### Features
  * Verifies appended PKCS#7 signatures extracted from binaries.
  * Supports multiple appended signatures.
  * Supports detached PKCS#7 signatures (DER format).
  * Supports signatures with one or multiple signers in the same .p7s file.
  * Verifies signatures using:
    - Local PEM or DER certificates (single or concatenated multi-cert PEM)
    - Secure variables (grubdb/db) from PKS
  * Parses EFI Signature List (ESL) data from Secure Boot variables and builds mbedTLS X.509 chain.
  * For multi-signature verification, multiple PEM certificates can be concatenated into a single file. The utility will use all certificates in the file to verify the signatures.

### Prerequisites
  * Mbed TLS library (latest version recommended)
  * GCC or compatible C compiler
  * OpenSSL is required for generating PKCS#7 signatures using the provided examples.
  * `secvarctl` tool (to write `db`/`grubdb` into PKS).
  * `sign-file` tool (for appending PKCS#7 signatures to binaries).

### Build Instructions
  1. Clone or download this repository.
  2. Ensure Mbed TLS is built and installed.
  3. If Mbed TLS is installed in a custom location, export the MBEDTLS_DIR variable with the path. For example
   ```bash
   export MBEDTLS_DIR=/your/mbedtls/path
   ```
  4. Run `make`.This will build the verify executable.

### Usage
Detached PKCS#7 signature verification using local certificate:
```bash
./verify -d <pkcs7 signature> <binary> -c <certificate>
```
Appended PKCS#7 signature verification using local certificate:
```bash
./verify -a <binary_with_appended_sig> -c <certificate>
```
Appended PKCS#7 signature verification using secure variable:
```bash
./verify -a <binary_with_appended_sig> -s <secvar>
```
* `<pkcs7 signature>`: PKCS#7 signature file (DER format, e.g., .p7s)
* `<binary>`: Original binary file that was signed (e.g., an ELF file)
* `<certificate>`: Signer certificate (can be a single PEM or DER file, or multiple PEM certificates concatenated into one file for multi-signer signatures)
* `<binary_with_appended_sig>`: Binary file with PKCS#7 signature appended
* `<secvar>`: Secure variable (eg. grubdb/db). The tool reads the ESL data for this variable, converts it to an mbedTLS X.509 certificate.

### Detached Signature Examples
**Signing with a single private key and its corresponding certificate:**
```bash
openssl cms -sign -binary -nocerts -in core.elf -signer certificate.pem -inkey imprint.key -out core.p7s -outform DER -noattr -md sha256
```
**Single signature verification:**
```bash 
./verify -d core.p7s core.elf -c certificate.pem
```
**Signing with multiple private keys and their corresponding certificates:**
```bash
openssl cms -sign -binary -nocerts -in core.elf -signer certificate.pem -inkey imprint.key -signer certificate2.pem -inkey imprint2.key -out core.p7s -outform DER -noattr -md sha256
```
**Multiple signatures verification (one at a time):**
```bash
./verify -d core.p7s core.elf -c certificate.pem
./verify -d core.p7s core.elf -c certificate2.pem
```
**Multiple signatures verification (concatenated PEM):**
```bash
cat certificate.pem certificate2.pem > multicert.pem
./verify -d core.p7s core.elf -c multicert.pem
```
**Using Secure variable:**
```bash
./verify -d core.p7s core.elf -s grubdb
```
### Appended Signature Examples
**Signing and Appending with sign-file:**
First, generate a detached signature (see above). Then, append it:
```bash
sign-file -s core.p7s sha256 /dev/null core.elf core.elf.signed
```
**Verification**
```bash
./verify -a core.elf.signed -c certificate.pem
```
**Using Secure variable:**
```bash
./verify -a core.elf.signed -s grubdb
```
### Notes
  * The tool expects a Secure variable that contains an EFI Signature List (ESL) blob (from /sys/firmware/secvar/vars/`<var>`/data) 
  * This utility does not perform full certificate chain validation.



