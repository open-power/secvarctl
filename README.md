# secvarctl
Suite of tools to manipulate and generate Secure Boot variables on POWER.

The purpose of this tool is to simplify and automate the process of reading and writing secure boot keys.
`secvarctl` allows the user to communicate, via terminal commands, with the keys efficiently. It is
supporting automate process of the both host and guest secure boot keys.

                                            |-------------------|
                                            |     secvarctl     |
                                            |-------------------|
                                                     |
                                                     |
                                  |-----------------------------------|
                                  |                                   |
                          |----------------|                 |-----------------|
                          |  Host Backend  |                 |  Guest Backend  |
                          |----------------|                 |-----------------|
                                  |                                   |
                                  |                                   |
                       |--------------------|               |---------------------|
                       |       edk2         |               |    libstb-secvar    |
                       |  external backend  |               |   external backend  |
                       |--------------------|               |---------------------|


**1. Host Secure Boot**

Secure variables are responsible for loading the target OS/hypervisor during Secure Boot.
There are currently four secure variables in the Secure Boot process:

* **Platform Key (PK):** The PK serves as the root key, usually supplied by platform owner, if there is no PK then Secure Boot is not enabled. The PK has authority over all other keys.
* **Key Exchange Key (KEK):** The KEK is usually provided by the OS vendor and has authority over the db and dbx.
* **Database Key (db):** The db has authority over the kernels and other user specific firmware.
* **Blocklist Key (dbx):** The dbx has authority over kernels and other user specific firmware that are not to be loaded.

**2. Guest Secure Boot**

Secure variables are responsible for loading the target OS in LPAR during Secure Boot. There are
currently nine secure variables in the Secure Boot process:

* **Platform Key (PK):** It is serves as the root key, usually supplied by platform owner, if there is no PK then Secure Boot is not enabled. The PK has authority over all other keys.
* **Key Exchange Key (KEK):** It is usually provided by the OS vendor and has authority over the db, dbx, grubdb, grubdbx, sbat, moduledb and trustedcadb.
* **Database Key (db):** It is kernel key database and has a list of public keys that are used by grub to validate the kernel signatures
* **Blocklist Key (dbx):** It is kernel key exclusion database and has a list of public keys, key hashes and binary hashes that should be excluded by grub when attempting to validate the kernel signatures
* **Grub database Key (grubdb):** It is GRUB key database and has a list of public keys and binary hashes that are used by firmware to validate the grub signatures
* **Grub blocklist Key (grubdbx):** It is GRUB key exclusion database and has a list of public keys, key hashes and binary hashes that should be excluded by firmware when attempting to validate the grub signatureslist of public keys,
* **Module database Key (moduledb):** It is kernel module key database and hash a list of public keys that are used by Kernel to validate the kernel module signatures
* **Trusted CA database (trustedcadb):** It is truested CA key database
* **Secure boot advanced targeting (sbat):** It is secure boot advanced targeting (SBAT) generation number based revocation data that are used by firmware to validate grub


Being that the key management process is rather lengthy and difficult, `secvarctl` was created to simplify these steps.

## REQUIREMENTS:
  - Must be on a POWER machine that supports Secure Boot (for reading and updating secure variables), x86 works for file generation and validation
  - Mbedtls version 2.14 and above or OpenSSL
  - GNU Make
  - C compiler

## BUILDING:
 |               | Make      |
 ---             | ----------- |
 | Default Build (openssl is cryptolib) | `make [build options]`      |
 | Build W Mbedtls as cryptolib | `MBEDTLS=1` |
 | Build W OpenSSL as cryptolib | `OPENSSL=1` |
 | Build W GnuTLS as cryptolib | `GNUTLS=1` |
 | Static Build | `STATIC=1` |
 | Reduced Size Build | default |
 | Build Without Crypto Write Functions | `CRYPTO_READ_ONLY=1` |
 | Build W Specific Mbedtls Library | `CFLAGS="-I<path>/include" LDFLAGS="-L<path>/library"` |
 | Build for Coverage Tests | `make [options] coverage` |
 | Build W Debug Symbols | `make DEBUG=1` |
 | Run unit test | `make check`        |
 | Install    | `make install`        |
 | Uninstall    | `make uninstall`        |

## USAGE:

**$ secvarctl [MODE] [COMMAND]**

	MODEs:

	-m, --mode  supports both the Guest and Host secure boot variables in two different modes and
	            either `-m host` or `-m guest` are acceptable values.

	COMMANDs:

		--help/--usage

		read      prints info on secure variables,
		          use 'secvarctl [MODE] read --usage/help' for more information
		write     updates secure variable with new auth,
		          use 'secvarctl [MODE] write --usage/help' for more information
		validate  validates format of given esl/cert/auth,
		          use 'secvarctl [MODE] validate --usage/help' for more information
		verify    compares proposed variable to the current variables,
		          use 'secvarctl [MODE] verify --usage/help' for more information
		generate  creates relevant files for secure variable management,
		          use 'secvarctl [MODE] generate --usage/help' for more information

For Host secure variable : [host usage](host-usage.md)

For Guest secure variable : [guest usage](guest-usage.md)

## FILE/KEY GENERATION:
   + X509:
     - `$openssl req –new –x509 –newKey rsa:2048 –keyout <outPrivate.key> -out <outPublic.crt> -nodes –sha256`
   + Efi Signature list (ESL):
     - From an x509 : `$secvarctl -m <mode> generate c:e -i <inputCert> -o <out.esl>`
     - From a hash: `$secvarctl -m <mode> generate h:e -h <hashAlgUsed> -i <inputHash> -o <out.esl>`
     - From a generic file (hash done internally) : `$secvarctl -m <mode> generate f:e -h <hashAlgToUse> -i <inputFile> -o <out.esl>`
   + Signed Auth File (EXPERIMENTAL):
     - From an ESL: `$secvarctl -m <mode> generate e:a -k <signerPrivate.key> -c <signerPublic.crt> -n <varName> -i <inputESL> -o <out.auth> `
     - From an x509 (ESL created internally): `$secvarctl -m <mode> generate c:a -k <signerPrivate.key> -c <signerPublic.crt> -n <varName> -i <inputCert> -o <out.auth> `
     - From a hash (ESL created internally): `$secvarctl -m <mode> generate h:a -k <signerPrivate.key> -c <signerPublic.crt> -n <varName> -h <hashAlgUsed> -i <inputHash> -o <out.auth> `
     - From a file (hash->ESL created internally): `$secvarctl -m <mode> generate f:a -k <signerPrivate.key> -c <signerPublic.crt> -n <varName> -h <hashAlgUsed> -i <inputFile> -o <out.auth> `
     - To create a variable reset file: `$secvarctl -m <mode> generate reset -k <signerPrivate.key> -c <signerPublic.crt> -n <varName> -o <out.auth>

## Further Reading

For more background knowledge on key heirarchy and the Secure Boot process : [IBM Secure Boot on POWER Doc](https://developer.ibm.com/articles/protect-system-firmware-openpower/)

For information on the Secure Variable sysfs : [Secvar Docs](https://elixir.bootlin.com/linux/latest/source/Documentation/ABI/testing/sysfs-secvar)

For any questions regarding secvarctl, feel free to reach out: [Nick Child](nick.child@ibm.com)

## License   
The files located in the `external/host` directory are borrowed files from other packages. They retain their licenses from their respective license headers. For example, the file `external/linux/.clang-format` is protected under GPL-2.0 as specified by its file header and `external/linux/LICENSE` . All other files not in the `external/host` directory are protected under Apache 2.0, as specified in the `LICENSE` file.
